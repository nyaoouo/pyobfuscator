"""Bounded O2 archive publication proof for two selected mixed POST predicates.

This checks the compiled producer, the exact COFF-to-PE publication route, and
the consuming state edge. Its fifteen owned/measured helper calls rely on the
preceding mixed POST helper-route gate for bounded normal returns; this module
does not prove transitive callee behavior. It also does not infer writes made
inside the archive decoder or equivalence of every optimized predicate to the
original program.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from archive_format import Kind, parse_plan
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image, rva_section

from cff_archive_origin import verify_archive_origin_record
from cff_builder_original_predicates import (_block_start, _dispatcher_destination,
    _document, _encoded_immediate, _entry_spill, _imm, _ir_function, _mix, _only_stack_write,
    _predicate_groups, _slot, _states, _transition, _writes_register, RSP)
from cff_builder_subjects import verify_builder_subjects
from cff_builder_entry_states import _expected_state
from cff_joint_machine_evidence import DIRECT, MEASURED, OWNED, _dispatcher_state, _graph, _instructions
from payload_binding import OWNER, WRAPPER
from post_mixed_binding import _plan


SELECTED = ((28, "slt", "cmovll"), (30, "eq", "cmovel"))
DECODER = "_ZN12pyobfuscator6native7archive14require_recordEPKhyjPhyRNS1_5CacheES3_"
PACKAGE = "_ZN12_GLOBAL__N_113package_bytesE"
RIP = re.compile(r"^-?(?:0x[0-9a-f]+|[0-9]+)\(%rip\)$")


def _fail(reason: str) -> None:
    raise ValueError(f"builder archive publication: {reason}")


def _one(items, reason):
    if len(items) != 1:
        _fail(reason)
    return items[0]


def _direct(item):
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    if match is None or item.opcode not in ("call", "callq") or item.raw[:1] != b"\xe8":
        _fail("publication call is not a direct REL32 call")
    return int(match[1], 16), match[2]


def _rip_target(item, image):
    if (item.opcode not in ("leaq", "movl") or len(item.operands) != 2 or
            RIP.fullmatch(item.operands[0]) is None or len(item.raw) < 6):
        _fail("publication pointer or storage read has unsupported RIP form")
    displacement = int.from_bytes(item.raw[-4:], "little", signed=True)
    target = item.address + len(item.raw) + displacement
    rva_section(image, target - image.preferred_base, 4)
    return target


def _relocation(object_bytes, obj, resolver, section, root_rva, item, field, image,
                target, *, symbol_name=None, symbol_index=None, zero_addend=False):
    section_offset = item.address - image.preferred_base - root_rva
    location = section_offset + field
    matches = [row for row in section.relocations if row.offset == location]
    row = _one(matches, "publication field lacks one COFF relocation")
    if row.kind != 4 or not 0 <= location <= section.size - 4:
        _fail("publication relocation is not a bounded REL32")
    addend = int.from_bytes(object_bytes[section.offset + location:section.offset + location + 4],
                            "little", signed=True)
    symbol = resolver.inputs[row.target]
    if symbol_index is not None and row.target != symbol_index:
        _fail("publication relocation targets a different COFF symbol index")
    if symbol_name is not None and symbol.name != symbol_name:
        _fail(f"publication relocation references {symbol.name}, not {symbol_name}")
    if zero_addend and addend != 0:
        _fail("publication relocation changes the exact symbol address")
    resolved = resolver.target(row.target) + addend
    actual = item.address + len(item.raw) + int.from_bytes(item.raw[-4:], "little", signed=True)
    if resolved != target - image.preferred_base or actual != target:
        _fail("publication relocation target differs from final PE address")
    return row, addend


def _root(obj, resolver, name):
    symbol = _one([row for row in obj.symbols if row.name == name and row.type == 0x20 and
                   row.section > 0 and row.value == 0], "publication function lacks one COFF root")
    return obj.sections[symbol.section - 1], resolver.named(name)


def _package_rva(package: bytes, image_bytes: bytes, image):
    if not package or len(package) > 1 << 20:
        _fail("archive package is empty or unbounded")
    found = []
    for section in image.layout.sections:
        raw = image_bytes[section.raw_offset:section.raw_offset + section.raw_size]
        at = raw.find(package)
        while at != -1:
            found.append(section.rva + at)
            at = raw.find(package, at + 1)
    return _one(found, "exact archive package is absent or duplicated in PE")


def _source(roles, report_bytes, edge_plan_bytes, wrappers):
    if any(type(roles[name]) is not bytes or len(roles[name]) > 16 << 20 for name in
           ("optimized_ir", "pending_ir", "prepared_ir")):
        _fail("archive IR role exceeds the selected byte budget")
    try:
        optimized = roles["optimized_ir"].decode("utf-8").replace("\r\n", "\n")
        pending = roles["pending_ir"].decode("utf-8").replace("\r\n", "\n")
        prepared = roles["prepared_ir"].decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("builder archive publication: IR roles must be UTF-8") from error
    body = _ir_function(optimized, OWNER)
    pending_body = _ir_function(pending, OWNER)
    prepared_body = _ir_function(prepared, OWNER)
    comparisons = re.findall(
        r"(?P<name>%[\w.]+) = icmp (?P<kind>slt|eq) i32 %2, 0[^\n]*\n"
        r"\s*br i1 (?P=name), label %\d+, label %\d+, !pyobf\.cff\.site !(?P<site>\d+)", body)
    if len(comparisons) != 2 or [item[1] for item in comparisons] != ["slt", "eq"] or \
            len(re.findall(r"\bicmp\b", body)) != 2:
        _fail("optimized source comparisons differ from selected O2 zero predicates")
    definitions = dict(re.findall(r'(?m)^!(\d+) = !\{!"(original\.[^"]+)"\}$', optimized))
    try:
        sites = [definitions[item[2]] for item in comparisons]
    except KeyError as error:
        raise ValueError("builder archive publication: optimized branch provenance is absent") from error
    lines = pending_body.splitlines()
    positions = []
    for index, kind, _ in SELECTED:
        calls = [number for number, line in enumerate(lines) if
                 f"call void @__pyobf_archive_pending_record-{index}(" in line and
                 f"ptr @__pyobf_archive_storage_record-{index}, i64 4)" in line]
        loads = [(number, line.strip().split(" = ", 1)[0]) for number, line in enumerate(lines) if
                 f" = load i32, ptr @__pyobf_archive_storage_record-{index}, align 4" in line]
        if len(calls) != 1 or len(loads) != 1 or not loads[0][1].startswith("%"):
            _fail(f"record {index} lacks one pending call or typed storage read")
        comparisons = [number for number, line in enumerate(lines) if
                       f" = icmp {kind} i32 %2, {loads[0][1]}" in line]
        if len(comparisons) != 1 or not calls[0] < loads[0][0] < comparisons[0]:
            _fail(f"record {index} pending call does not precede its same-slot compare")
        positions.append(calls[0])
    if positions != sorted(positions):
        _fail("pending producer order differs from optimized source")
    if len(re.findall(r"\bicmp\b", pending_body)) != 2:
        _fail("pending compute has extra comparisons")
    for index, kind, _ in SELECTED:
        name = wrappers[index]
        call = f"call void @{name}(ptr "
        slot = f"ptr @__pyobf_archive_storage_record-{index}, i64 4)"
        loads = [line.strip().split(" = ", 1)[0] for line in prepared_body.splitlines()
                 if f" = load i32, ptr @__pyobf_archive_storage_record-{index}, align 4" in line]
        if len(loads) != 1 or prepared_body.count(call) != 1 or \
                not any(call in line and slot in line for line in prepared_body.splitlines()) or \
                prepared_body.count(f" = icmp {kind} i32 %2, {loads[0]}") != 1:
            _fail(f"record {index} materialized wrapper and same-slot compare differ")
    for index in range(28, 34):
        name = wrappers[index]
        wrapper_body = _ir_function(prepared, name)
        cache_name = f"_ZN12_GLOBAL__N_18cache_{index}E"
        expected_call = (f"call void @{DECODER}(ptr noundef @{PACKAGE}, "
                         f"i64 noundef {len(roles['package'])}, i32 noundef {index}, "
                         f"ptr noundef %1, i64 noundef %2, "
                         f"ptr noundef nonnull align 8 dereferenceable(48) "
                         f"@{cache_name}, ptr noundef %0)")
        if (wrapper_body.count("call ") != 1 or expected_call not in wrapper_body or
                wrapper_body.count("ret void") != 1):
            _fail(f"record {index} prepared wrapper decoder/cache ABI differs")
    plan = _plan(edge_plan_bytes)
    report = _document(report_bytes, 8 << 20, "compiler report")
    if report.get("original_edge_plan_sha256") != hashlib.sha256(edge_plan_bytes).hexdigest():
        _fail("compiler report differs from frozen edge plan")
    planned, pairs = _predicate_groups(plan, report, OWNER, sites)
    return planned, pairs, report


def _wrapper_route(instructions, graph, dispatcher, state, state_slot, body):
    by_address = {item.address: item for item in instructions}
    for _ in range(3):
        route = _dispatcher_destination(instructions, dispatcher, state, state_slot)
        if route == body:
            return
        block = []
        cursor = route
        while len(block) <= 18 and cursor != dispatcher:
            item = by_address.get(cursor)
            if item is None:
                _fail("wrapper route enters an instruction gap")
            block.append(item)
            if item.opcode in ("jmp", "jmpq"):
                break
            if item.opcode in ("call", "callq", "ret", "retq", "jae"):
                _fail("wrapper reaches a side effect before package publication")
            cursor += len(item.raw)
        shape = [
            ("movl", (f"{state_slot:#x}(%rsp)", "%eax")),
            ("movl", ("%eax", "%ecx")), ("xorl", None),
            ("movl", ("%ecx", "%edx")), ("shrl", ("$0x10", "%edx")),
            ("xorl", ("%edx", "%ecx")),
            ("imull", ("$0x7feb352d", "%ecx", "%ecx")),
            ("movl", ("%ecx", "%edx")), ("shrl", ("$0xf", "%edx")),
            ("xorl", ("%edx", "%ecx")),
            ("imull", ("$0x846ca68b", "%ecx", "%ecx")),
            ("movl", ("%ecx", "%edx")), ("shrl", ("$0x10", "%edx")),
            ("xorl", ("%edx", "%ecx")), ("xorl", None),
            ("addl", ("%ecx", "%eax")),
            ("movl", ("%eax", f"{state_slot:#x}(%rsp)")),
        ]
        if (len(block) not in (17, 18) or
                any(item.opcode != opcode or (operands is not None and item.operands != operands)
                    for item, (opcode, operands) in zip(block[:17], shape)) or
                len(block[2].operands) != 2 or block[2].operands[1] != "%ecx" or
                len(block[14].operands) != 2 or block[14].operands[1] != "%ecx" or
                (len(block) == 17 and block[16].address + len(block[16].raw) != dispatcher) or
                (len(block) == 18 and (block[17].opcode not in ("jmp", "jmpq") or
                                       graph[block[17].address] != (dispatcher,)))):
            _fail("wrapper has an unmodeled pre-publication state route")
        state = (state + (_mix(state ^ _encoded_immediate(block[2], b"\x81\xf1")) ^
                          _encoded_immediate(block[14], b"\x81\xf1"))) & 0xffffffff
    _fail("wrapper did not route from its initialized state to publication")


def _wrapper(object_bytes, image_bytes, image, obj, resolver, code, name, index,
             package_rva, package_length, expected_state, decoder_rva,
             decoder_symbol_index):
    subject = function_subject(object_bytes, image_bytes, image, 0xb400 + index, name)
    instructions = _instructions(code, image_bytes, name)
    if len(subject.ranges) != 1 or subject.ranges[0].rva != instructions[0].address - image.preferred_base:
        _fail("wrapper COFF/PE extent differs from disassembly")
    section, root = _root(obj, resolver, name)
    by_address, graph, calls = _graph(instructions)
    if (len(calls) != 1 or len(instructions) < 18 or
            instructions[0].opcode != "subq" or instructions[0].operands != ("$0x68", "%rsp") or
            [item.operands for item in instructions[1:4]] != [
                ("%r8", "0x48(%rsp)"), ("%rdx", "0x50(%rsp)"),
                ("%rcx", "0x58(%rsp)")]):
        _fail("wrapper entry ABI or require-record call inventory is unsupported")
    if (instructions[4].opcode != "movl" or
            instructions[4].operands[1] != "0x64(%rsp)" or
            instructions[4].raw[:4] != b"\xc7\x44\x24\x64"):
        _fail("wrapper lacks one direct stack-state initializer")
    initial_state = _imm(instructions[4].operands[0])
    if initial_state != int.from_bytes(instructions[4].raw[-4:], "little"):
        _fail("wrapper displayed entry state differs from PE bytes")
    if initial_state != expected_state:
        _fail("wrapper entry state differs from compiler CFG recipe")
    frame = 0x68
    state_slot = _dispatcher_state(instructions, graph, frame) + frame
    if state_slot != 0x64:
        _fail("wrapper dispatcher state slot is unsupported")
    branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
    dispatcher = graph[branch.address][0]
    call = calls[0]
    call_index = instructions.index(call)
    body = instructions[call_index - 10:call_index]
    if (len(body) != 10 or
            [(item.opcode, item.operands) for item in body[:3]] != [
                ("movq", ("0x58(%rsp)", "%rax")),
                ("movq", ("0x48(%rsp)", "%r11")),
                ("movq", ("0x50(%rsp)", "%r9"))] or
            body[3].opcode != "leaq" or body[3].operands[1] != "%rcx" or
            body[4].opcode != "movl" or body[4].operands != (f"${package_length:#x}", "%edx") or
            body[5].opcode != "movl" or body[5].operands != (f"${index:#x}", "%r8d") or
            body[6].opcode != "leaq" or body[6].operands[1] != "%r10" or
            [(item.opcode, item.operands) for item in body[7:]] != [
                ("movq", ("%r11", "0x20(%rsp)")),
                ("movq", ("%r10", "0x28(%rsp)")),
                ("movq", ("%rax", "0x30(%rsp)"))]):
        _fail("wrapper package, record ID or Win64 call arguments are unsupported")
    if (body[4].raw != b"\xba" + package_length.to_bytes(4, "little") or
            body[5].raw != b"\x41\xb8" + index.to_bytes(4, "little")):
        _fail("wrapper package length or record ID differs from PE immediate bytes")
    _wrapper_route(instructions, graph, dispatcher, initial_state, state_slot, body[0].address)
    package_target = _rip_target(body[3], image)
    if package_target - image.preferred_base != package_rva:
        _fail("wrapper passes a different package to decoder")
    package_symbol = _one([symbol for symbol in obj.symbols if symbol.name == PACKAGE and
                           symbol.section > 0 and symbol.type == 0 and symbol.storage == 3],
                          "wrapper package lacks one COFF data object")
    if resolver.named(PACKAGE) != package_rva or \
            package_symbol.value + package_length > obj.sections[package_symbol.section - 1].size:
        _fail("wrapper package symbol does not cover the exact PE package")
    _relocation(object_bytes, obj, resolver, section, root, body[3], len(body[3].raw) - 4,
                image, package_target, symbol_name=PACKAGE,
                symbol_index=package_symbol.index, zero_addend=True)
    cache_target = _rip_target(body[6], image)
    cache_name = f"_ZN12_GLOBAL__N_18cache_{index}E"
    cache_symbol = _one([symbol for symbol in obj.symbols if symbol.name == cache_name and
                         symbol.section > 0 and symbol.type == 0 and symbol.storage == 3],
                        "wrapper cache lacks one COFF data symbol")
    _relocation(object_bytes, obj, resolver, section, root, body[6], len(body[6].raw) - 4,
                image, cache_target, symbol_name=cache_name,
                symbol_index=cache_symbol.index, zero_addend=True)
    cache_section = obj.sections[cache_symbol.section - 1]
    cache_rva = cache_target - image.preferred_base
    final_section = rva_section(image, cache_rva, 48, logical=True)
    if (cache_symbol.value + 48 > cache_section.size or
            cache_section.flags & 0xc0000000 != 0xc0000000 or
            cache_section.flags & 0x20000000 or
            final_section.flags & 0xc0000000 != 0xc0000000 or
            final_section.flags & 0x20000000 or
            resolver.named(cache_name) != cache_rva or
            any(other.section == cache_symbol.section and other.index != cache_symbol.index and
                other.type == 0 and other.storage == 3 and
                abs(other.value - cache_symbol.value) < 48
                for other in obj.symbols)):
        _fail("wrapper cache lacks a separate writable 48-byte PE extent")
    target, symbol = _direct(call)
    if symbol != DECODER.lower():
        _fail("wrapper call does not target archive decoder")
    if target != image.preferred_base + decoder_rva:
        _fail("wrapper call target differs from exact decoder contribution")
    _relocation(object_bytes, obj, resolver, section, root, call, 1, image, target,
                symbol_name=DECODER, symbol_index=decoder_symbol_index,
                zero_addend=True)
    if [(item.opcode, item.operands) for item in instructions[call_index + 1:call_index + 4]] != [
            ("nop", ()), ("addq", ("$0x68", "%rsp")), ("retq", ())]:
        _fail("wrapper call has an unsupported return route")
    return {"wrapper_rva": root, "call_rva": call.address - image.preferred_base,
            "package_rva": package_rva, "cache_rva": cache_rva,
            "decoder_rva": target - image.preferred_base}


def _argument_provenance(instructions, argument_slot, frame):
    entry = _one([item for item in instructions[:12] if item.opcode == "movl" and
                  item.operands == ("%r8d", f"{argument_slot:#x}(%rsp)")],
                 "original argument lacks one entry spill")
    _only_stack_write(instructions, argument_slot, 4, {entry.address})
    shifts = [(position, item) for position, item in enumerate(instructions) if
              item.opcode in ("subq", "addq") and item.operands[-1:] == ("%rsp",)]
    if (len(shifts) != 2 or shifts[0] != (0, instructions[0]) or
            shifts[0][1].opcode != "subq" or
            shifts[0][1].operands != (f"${frame:#x}", "%rsp") or
            shifts[1][1].operands != (f"${frame:#x}", "%rsp") or
            shifts[1][1].opcode != "addq" or
            instructions[shifts[1][0] + 1].opcode not in ("ret", "retq")):
        _fail("original argument frame has an unmodeled stack-pointer shift")
    for item in instructions:
        for operand in item.operands:
            if "%rsp" in operand and operand != "%rsp" and RSP.fullmatch(operand) is None:
                _fail("original argument frame has an unmodeled stack alias")
        if item.opcode == "leaq" and len(item.operands) == 2 and RSP.fullmatch(item.operands[0]):
            if _slot(item.operands[0]) <= argument_slot + 3:
                _fail("original argument stack address escapes")
        elif "%rsp" in item.operands and item.opcode not in ("subq", "addq"):
            _fail("original argument stack pointer escapes")
        if item.operands and "(" in item.operands[-1] and \
                RSP.fullmatch(item.operands[-1]) is None:
            _fail("original argument frame has an indirect or global writer")


def _archive_sites(object_bytes, image_bytes, image, obj, resolver, section, root,
                   instructions, bindings, argument_slot, frame):
    """Bound every stack-address producer in this fixed O2 owner to one archive ABI call."""
    expected_names = {index: bindings["records"][index]["wrapper"] for index in range(28, 34)}
    starts = [(position, item) for position, item in enumerate(instructions) if
              item.opcode == "leaq" and len(item.operands) == 2 and
              RSP.fullmatch(item.operands[0])]
    if len(starts) != len(expected_names):
        _fail("selected owner has extra or missing stack-address producers")
    sites = {}
    storage_symbol_index = None
    for position, key in starts:
        if position + 3 >= len(instructions):
            _fail("archive call setup is truncated")
        output, capacity, call = instructions[position + 1:position + 4]
        target, displayed = _direct(call)
        matched = [index for index, name in expected_names.items() if
                   displayed == name.lower() and target == image.preferred_base + resolver.named(name)]
        index = _one(matched, "archive call does not target one authenticated wrapper")
        if index in sites:
            _fail("archive wrapper has duplicate call sites")
        key_slot = _slot(key.operands[0])
        if (key.operands[1] != "%rcx" or
                key.raw != b"\x48\x8d\x8c\x24" + key_slot.to_bytes(4, "little") or
                not argument_slot + 4 <= key_slot <= frame - 32 or
                output.opcode != "leaq" or output.operands[1] != "%rdx" or
                RIP.fullmatch(output.operands[0]) is None or
                output.raw[:3] != b"\x48\x8d\x15" or len(output.raw) != 7 or
                capacity.opcode != "movl" or capacity.operands != ("$0x4", "%r8d") or
                capacity.raw != b"\x41\xb8\x04\x00\x00\x00"):
            _fail(f"record {index} has unsupported key/output/capacity setup")
        wrapper_symbol = _one([symbol for symbol in obj.symbols if symbol.name == displayed and
                               symbol.section > 0 and symbol.value == 0 and
                               symbol.type == 0x20 and symbol.storage == 3],
                              "archive call lacks one COFF wrapper root")
        function_subject(object_bytes, image_bytes, image, 0xb500 + index, displayed)
        _relocation(object_bytes, obj, resolver, section, root, call, 1, image, target,
                    symbol_name=displayed, symbol_index=wrapper_symbol.index,
                    zero_addend=True)
        slot = _rip_target(output, image)
        relocation, addend = _relocation(object_bytes, obj, resolver, section, root,
            output, len(output.raw) - 4, image, slot)
        storage_symbol = resolver.inputs[relocation.target]
        if (storage_symbol.name != ".bss" or storage_symbol.section <= 0 or
                storage_symbol.value != 0 or storage_symbol.type != 0 or
                storage_symbol.storage != 3):
            _fail("archive output slot lacks one section-root relocation")
        if storage_symbol_index is None:
            storage_symbol_index = storage_symbol.index
        elif storage_symbol.index != storage_symbol_index:
            _fail("archive output slots use different COFF storage roots")
        storage_section = obj.sections[storage_symbol.section - 1]
        slot_rva = slot - image.preferred_base
        final_section = rva_section(image, slot_rva, 4, logical=True)
        if (addend < 0 or addend > storage_section.size - 4 or
                storage_section.flags & 0xc0000000 != 0xc0000000 or
                storage_section.flags & 0x20000000 or
                final_section.flags & 0xc0000000 != 0xc0000000 or
                final_section.flags & 0x20000000):
            _fail(f"record {index} archive output slot lacks writable COFF/PE storage")
        sites[index] = {"call": call, "key_slot": key_slot,
                        "slot_rva": slot_rva,
                        "slot_addend": addend}
    if set(sites) != set(expected_names):
        _fail("archive call inventory differs from selected profile")
    first = sites[28]
    for index in expected_names:
        row = sites[index]
        if (row["key_slot"] != first["key_slot"] - 32 * (index - 28) or
                row["slot_rva"] != first["slot_rva"] + 4 * (index - 28) or
                row["slot_addend"] != first["slot_addend"] + 4 * (index - 28)):
            _fail("archive key frames or output slots differ from selected O2 layout")
    return sites


def _publication_read_window(instructions, call_index, read_index, key_slot,
                             argument_slot, index):
    span = instructions[call_index + 1:read_index]
    expected = []
    if index == 28:
        expected.append(("movl", (f"{argument_slot:#x}(%rsp)", "%r8d")))
    expected.extend(("movl", ("$0x0", f"{key_slot + offset:#x}(%rsp)"))
                    for offset in range(0, 32, 4))
    if len(span) != len(expected) or any((item.opcode, item.operands) != wanted
                                           for item, wanted in zip(span, expected)):
        _fail(f"record {index} publication-to-read window has an unmodeled writer or alias")
    for offset, item in zip(range(0, 32, 4), span[-8:]):
        if item.raw != (b"\xc7\x84\x24" + (key_slot + offset).to_bytes(4, "little") +
                        bytes(4)):
            _fail(f"record {index} key clear differs from exact PE stack-only bytes")


def _publication_graph(instructions, graph):
    """Bind displayed local branches to PE bytes and retain every incoming edge."""
    predecessors = {item.address: set() for item in instructions}
    for item in instructions:
        for successor in graph[item.address]:
            predecessors[successor].add(item.address)
        if item.opcode not in ("jmp", "jmpq", "jae"):
            continue
        raw = item.raw
        if raw[:1] in (b"\xeb", b"\x73") and len(raw) == 2:
            displacement = int.from_bytes(raw[1:], "little", signed=True)
        elif raw[:1] == b"\xe9" and len(raw) == 5:
            displacement = int.from_bytes(raw[1:], "little", signed=True)
        elif raw[:2] == b"\x0f\x83" and len(raw) == 6:
            displacement = int.from_bytes(raw[2:], "little", signed=True)
        else:
            _fail("owner has an unsupported PE branch encoding")
        if ((item.opcode == "jae") != (raw[:1] == b"\x73" or raw[:2] == b"\x0f\x83") or
                graph[item.address][0] != item.address + len(raw) + displacement):
            _fail("owner CFG branch target differs from PE bytes")
    return predecessors


def _owner_call_inventory(object_bytes, image, obj, resolver, section, root,
                          instructions, calls, bindings):
    """Reject unmodeled call edges and bind every direct call to one COFF root."""
    if len(calls) != sum(item.opcode in ("call", "callq") for item in instructions):
        _fail("owner has an indirect or unmodeled call target")
    expected = {OWNED: 9, MEASURED: 6}
    expected.update({bindings["records"][index]["wrapper"]: 1
                     for index in range(28, 34)})
    symbols = {}
    for name in expected:
        storage = 2 if name in (OWNED, MEASURED) else 3
        symbols[name] = _one([symbol for symbol in obj.symbols if symbol.name == name and
                              symbol.section > 0 and symbol.value == 0 and
                              symbol.type == 0x20 and symbol.storage == storage],
                             f"owner call target {name} lacks one exact COFF root")
    counts = {name: 0 for name in expected}
    entry = instructions[0].address
    end = instructions[-1].address + len(instructions[-1].raw)
    for call in calls:
        target, displayed = _direct(call)
        if call.raw[:1] != b"\xe8" or len(call.raw) != 5 or \
                target != call.address + 5 + int.from_bytes(call.raw[1:], "little", signed=True):
            _fail("owner direct call target differs from PE E8 bytes")
        if entry <= target < end:
            _fail("owner direct call enters its own protected interval")
        if displayed not in expected or \
                target != image.preferred_base + resolver.named(displayed):
            _fail("owner direct call targets an unmodeled external function")
        _relocation(object_bytes, obj, resolver, section, root, call, 1, image,
                    target, symbol_name=displayed,
                    symbol_index=symbols[displayed].index, zero_addend=True)
        counts[displayed] += 1
    if counts != expected:
        _fail("owner direct call inventory differs from selected O2 profile")


def _reachable(graph, entry, omitted=None):
    visited, pending = set(), [entry]
    while pending:
        address = pending.pop()
        if address == omitted or address in visited:
            continue
        visited.add(address)
        pending.extend(graph[address])
    return visited


def _publication_control_flow(instructions, graph, predecessors, start, call,
                              read, compare, write, index):
    """A selected call must be the only entry into its publication-to-state span."""
    positions = {item.address: position for position, item in enumerate(instructions)}
    if not (start in positions and start <= call.address < read.address <
            compare.address < write):
        _fail(f"record {index} publication route is not ordered")
    span = instructions[positions[start]:positions[write] + 1]
    entry = instructions[0].address
    reached = _reachable(graph, entry)
    if any(address not in reached for address in
           (start, call.address, read.address, compare.address, write)):
        _fail(f"record {index} publication route is unreachable from entry")
    for previous, current in zip(span, span[1:]):
        if (graph[previous.address] != (current.address,) or
                predecessors[current.address] != {previous.address}):
            _fail(f"record {index} publication route has a bypassing CFG predecessor")
    for dominator, target in ((start, call.address), (call.address, read.address),
                              (read.address, compare.address), (compare.address, write)):
        if target in _reachable(graph, entry, dominator):
            _fail(f"record {index} publication call/read does not dominate its consumer")


def _verify_builder_archive_publication(object_bytes, image_bytes, report_bytes,
    edge_plan_bytes, archive_record_bytes, archive_role_bytes, owner_codes,
    wrapper_codes) -> dict:
    """Prove the selected static publication routes in one fixed Windows O2 build."""
    if (type(object_bytes) is not bytes or not object_bytes or type(image_bytes) is not bytes or
            not image_bytes or type(owner_codes) is not dict or
            set(owner_codes) != {OWNER, WRAPPER} or
            any(type(value) is not str or not value for value in owner_codes.values())):
        _fail("actual COFF, PE and exact mixed-owner disassemblies are required")
    verify_archive_origin_record(archive_record_bytes, archive_role_bytes)
    record = _document(archive_record_bytes, 8192, "archive origin record")
    plan = parse_plan(_document(archive_role_bytes["archive_plan"], 1 << 20, "archive plan"))
    bindings = _document(archive_role_bytes["bindings"], 65536, "archive bindings")
    wrappers = {index: bindings["records"][index]["wrapper"] for index in range(28, 34)}
    intervening_wrapper = bindings["records"][33]["wrapper"]
    if (type(wrapper_codes) is not dict or set(wrapper_codes) != set(wrappers.values()) or
            any(type(value) is not str or not value for value in wrapper_codes.values())):
        _fail("exact authenticated wrapper disassemblies are required")
    for index in range(28, 34):
        item = plan[index]
        if (item.identity != f"record-{index}" or item.kind != Kind.integer or
                item.bit_width != 32 or item.alignment != 4 or item.byte_order != 1 or
                len(item.data) != 4 or
                (index in (28, 30) and item.data != b"\0" * 4)):
            _fail(f"record {index} is not the selected typed i32 source")
    planned, pairs, report = _source(archive_role_bytes, report_bytes,
                                     edge_plan_bytes,
                                     {index: bindings["records"][index]["wrapper"]
                                      for index in range(28, 34)})
    seed = int(record["plan_opt_options"][3].split("=", 1)[1])
    recipe = {"components": [{"component": "cfg", "seed": seed}]}
    image = parse_image(image_bytes)
    verify_builder_subjects(object_bytes, image_bytes)
    obj = parse_object(object_bytes)
    resolver = Resolver(obj, image, image_symbols(image_bytes, image))
    section, root = _root(obj, resolver, OWNER)
    package = archive_role_bytes["package"]
    package_rva = _package_rva(package, image_bytes, image)
    decoder_subject = function_subject(object_bytes, image_bytes, image, 0xb4f0, DECODER)
    if len(decoder_subject.ranges) != 1:
        _fail("decoder function has an unsupported COFF/PE extent")
    decoder_rva = decoder_subject.ranges[0].rva
    decoder_symbol = _one([symbol for symbol in obj.symbols if symbol.name == DECODER and
                           symbol.type == 0x20 and symbol.storage == 2 and
                           symbol.section > 0 and symbol.value == 0],
                          "decoder lacks one exact COFF function root")
    if resolver.named(DECODER) != decoder_rva:
        _fail("decoder root differs from exact PE function contribution")
    wrapper_proofs = {}
    for index in range(28, 34):
        name = wrappers[index]
        rows = [row for row in report["functions"] if row.get("function") == name]
        row = _one(rows, "compiler report lacks one generated wrapper")
        expected_state = _expected_state(name, row.get("effective_recipe"))
        wrapper_proofs[index] = _wrapper(object_bytes, image_bytes, image, obj, resolver,
            wrapper_codes[name], name, index, package_rva, len(package), expected_state,
            decoder_rva, decoder_symbol.index)
    instructions = _instructions(owner_codes[OWNER], image_bytes, OWNER)
    _, graph, calls = _graph(instructions)
    predecessors = _publication_graph(instructions, graph)
    _owner_call_inventory(object_bytes, image, obj, resolver, section, root,
                          instructions, calls, bindings)
    frame = _imm(instructions[1 if instructions[0].opcode == "pushq" else 0].operands[0])
    if instructions[0].opcode == "pushq": frame += 8
    state_slot = _dispatcher_state(instructions, graph, frame) + frame
    branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
    dispatcher = graph[branch.address][0]
    candidates = _states(OWNER, planned["recipe"])
    entry_state = candidates[0]
    argument_slot = _entry_spill(instructions, "%r8d", "l")
    _argument_provenance(instructions, argument_slot, frame)
    sites = _archive_sites(object_bytes, image_bytes, image, obj, resolver,
                           section, root, instructions, bindings, argument_slot, frame)
    all_wrapper_names = {row["wrapper"].lower() for row in bindings["records"]}
    archive_calls = [item for item in instructions if item.opcode in ("call", "callq") and
                     len(item.operands) == 1 and
                     (match := DIRECT.fullmatch(item.operands[0])) is not None and
                     match[2] in all_wrapper_names]
    if {item.address for item in archive_calls} != \
            {row["call"].address for row in sites.values()}:
        _fail("owner has an archive call outside the six modeled setup sites")
    proofs = []
    compares = [(position, item) for position, item in enumerate(instructions)
                if item.opcode == "cmpl" and position + 1 < len(instructions) and
                instructions[position + 1].opcode in ("cmovll", "cmovel")]
    by_polarity = {instructions[position + 1].opcode: (position, compare)
                   for position, compare in compares}
    if len(compares) != len(SELECTED) or len(by_polarity) != len(SELECTED) or \
            set(by_polarity) != {row[2] for row in SELECTED}:
        _fail("compute predicate inventory differs from selected O2 routes")
    for (index, kind, polarity), pair in zip(SELECTED, pairs):
        position, compare = by_polarity[polarity]
        name = wrappers[index]
        wrapper_symbol = _one([symbol for symbol in obj.symbols if symbol.name == name and
                               symbol.section > 0 and symbol.value == 0 and
                               symbol.type == 0x20 and symbol.storage == 3],
                              "selected wrapper lacks one exact COFF function root")
        call = sites[index]["call"]
        if _direct(call)[0] != image.preferred_base + wrapper_proofs[index]["wrapper_rva"]:
            _fail(f"record {index} modeled site targets a different wrapper")
        call_index = instructions.index(call)
        if (call_index < 3 or instructions[call_index - 3].opcode != "leaq" or
                instructions[call_index - 3].operands[1] != "%rcx" or
                instructions[call_index - 2].opcode != "leaq" or
                instructions[call_index - 2].operands[1] != "%rdx" or
                instructions[call_index - 1].opcode != "movl" or
                instructions[call_index - 1].operands != ("$0x4", "%r8d")):
            _fail(f"record {index} call arguments are unsupported")
        _relocation(object_bytes, obj, resolver, section, root, call, 1, image,
                    _direct(call)[0], symbol_name=name, symbol_index=wrapper_symbol.index,
                    zero_addend=True)
        slot = _rip_target(instructions[call_index - 2], image)
        if slot - image.preferred_base != sites[index]["slot_rva"]:
            _fail(f"record {index} call output differs from modeled archive site")
        _relocation(object_bytes, obj, resolver, section, root, instructions[call_index - 2],
                    len(instructions[call_index - 2].raw) - 4, image, slot)
        key = instructions[call_index - 3].operands[0]
        if RSP.fullmatch(key) is None or not 0 <= _slot(key) <= frame - 32 or \
                _slot(key) <= argument_slot + 3:
            _fail("key frame is not a private stack allocation")
        reads = [(p, item) for p, item in enumerate(instructions[call_index + 1:position], call_index + 1)
                 if item.opcode == "movl" and len(item.operands) == 2 and
                 RIP.fullmatch(item.operands[0]) and _rip_target(item, image) == slot]
        read_index, read = _one(reads, f"record {index} lacks one same-slot PE read")
        _publication_read_window(instructions, call_index, read_index,
                                 _slot(key), argument_slot, index)
        _relocation(object_bytes, obj, resolver, section, root, read, len(read.raw) - 4,
                    image, slot)
        if index == 28:
            if read.operands[1] != "%r9d" or any(item.opcode in ("jmp", "jmpq", "jae", "ret", "retq")
                    for item in instructions[call_index + 1:read_index]):
                _fail("record 28 publication does not precede its straight-line read")
        else:
            spill = instructions[read_index + 1]
            if (read.operands[1] != "%eax" or spill.opcode != "movl" or
                    spill.operands[0] != "%eax" or not spill.operands[1].endswith("(%rsp)")):
                _fail("record 30 publication lacks immediate spill")
            spill_slot = _slot(spill.operands[1])
            _only_stack_write(instructions, spill_slot, 4, {spill.address})
            reloads = [item for item in instructions[read_index + 2:position]
                       if item.opcode == "movl" and item.operands ==
                       (spill.operands[1], "%r9d")]
            reload = _one(reloads, "record 30 spill lacks one comparison reload")
            intervening = [item for item in calls if spill.address < item.address < reload.address and
                           _direct(item) == (image.preferred_base + resolver.named(intervening_wrapper),
                                             intervening_wrapper)]
            if len(intervening) != 1:
                _fail("record 30 reload lacks intervening record-33 call")
            intervening_symbol = _one([symbol for symbol in obj.symbols if
                                       symbol.name == intervening_wrapper and
                                       symbol.section > 0 and symbol.value == 0 and
                                       symbol.type == 0x20 and symbol.storage == 3],
                                      "intervening wrapper lacks one exact COFF root")
            _relocation(object_bytes, obj, resolver, section, root, intervening[0], 1,
                        image, _direct(intervening[0])[0],
                        symbol_name=intervening_wrapper,
                        symbol_index=intervening_symbol.index, zero_addend=True)
        if compare.raw != b"\x45\x39\xc8" or compare.operands != ("%r9d", "%r8d") or \
                instructions[position + 1].opcode != polarity or \
                instructions[position + 1].raw != (b"\x0f\x4c\xca" if index == 28 else b"\x0f\x44\xca"):
            _fail(f"record {index} compare polarity or argument order differs")
        argument_reads = [item for item in instructions[call_index + 1:position] if item.opcode == "movl" and
                          item.operands == (f"{argument_slot:#x}(%rsp)", "%r8d")]
        if len(argument_reads) != 1:
            _fail(f"record {index} compare lacks one original-argument reload")
        value_source = read if index == 28 else reload
        for source, register in ((value_source, "r9"), (argument_reads[0], "r8")):
            source_position = instructions.index(source)
            if any(item.opcode in ("call", "callq") or _writes_register(item, register)
                   for item in instructions[source_position + 1:position]):
                _fail(f"record {index} compare input changes after its verified reload")
        false_arm, true_arm, salt, write = _transition(instructions, position, dispatcher, state_slot)
        start = _block_start(instructions, position)
        body_calls = [item for item in instructions[call_index + 1:position]
                      if item.opcode in ("call", "callq")]
        expected_calls = [] if index == 28 else [sites[33]["call"]]
        if body_calls != expected_calls:
            _fail(f"record {index} publication body has an extra or missing call")
        if call.address < start or any(item.opcode in ("jmp", "jmpq", "jae", "ret", "retq")
                                       for item in instructions[call_index:position]):
            _fail(f"record {index} publication does not dominate its comparison body")
        _publication_control_flow(instructions, graph, predecessors, start, call,
                                  read, compare, write, index)
        source_states = []
        for before in candidates:
            if _dispatcher_destination(instructions, dispatcher, before, state_slot) != start:
                continue
            mask = _mix(before ^ salt)
            if ((before + (true_arm ^ mask)) & 0xffffffff,
                    (before + (false_arm ^ mask)) & 0xffffffff) == (pair[0], pair[1]):
                source_states.append(before)
        if len(source_states) != 1 or (index == 28 and source_states[0] != entry_state):
            _fail(f"record {index} compare does not route to frozen successor states")
        proofs.append({"record_index": index, "condition": f"{kind}-archive-i32-zero",
                       "slot_rva": slot - image.preferred_base,
                       "read_rva": read.address - image.preferred_base,
                       "compare_rva": compare.address - image.preferred_base,
                       "state_write_rva": write - image.preferred_base,
                       "source_state": source_states[0], "true_state": pair[0],
                       "false_state": pair[1], **wrapper_proofs[index]})
    spans = [(package_rva, package_rva + len(package), "package")]
    for index in range(28, 34):
        slot_rva = sites[index]["slot_rva"]
        spans.append((slot_rva, slot_rva + 4, f"record {index} storage"))
        cache_name = f"_ZN12_GLOBAL__N_18cache_{index}E"
        cache_symbol = _one([symbol for symbol in obj.symbols if
                             symbol.name == cache_name and symbol.section > 0 and
                             symbol.type == 0 and symbol.storage == 3],
                            f"record {index} cache lacks one COFF data symbol")
        cache_section = obj.sections[cache_symbol.section - 1]
        cache_rva = resolver.named(cache_name)
        final_section = rva_section(image, cache_rva, 48, logical=True)
        if (cache_symbol.value + 48 > cache_section.size or
                cache_section.flags & 0xc0000000 != 0xc0000000 or
                cache_section.flags & 0x20000000 or
                final_section.flags & 0xc0000000 != 0xc0000000 or
                final_section.flags & 0x20000000):
            _fail(f"record {index} cache lacks writable COFF/PE storage")
        spans.append((cache_rva, cache_rva + 48, f"record {index} cache"))
    spans.sort()
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])) or \
            proofs[0]["decoder_rva"] != proofs[1]["decoder_rva"]:
        _fail("selected package, storage or cache extents overlap")
    return {"verified": True, "publication_route_verified": True,
            "decoder_effect_verified": False,
            "original_predicate_equivalence_verified": False,
            "transitive_callee_semantics_verified": False,
            "scope": "selected-o2-archive-pe-publication-route-win64-after-mixed-helper-routes-v1",
            "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
            "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
            "archive_record_sha256": hashlib.sha256(archive_record_bytes).hexdigest(),
            "conditions": proofs}


def verify_builder_archive_publication(object_bytes, image_bytes, report_bytes,
    edge_plan_bytes, archive_record_bytes, archive_role_bytes, owner_codes,
    wrapper_codes) -> dict:
    """Reject malformed static shapes through the public proof boundary."""
    try:
        return _verify_builder_archive_publication(
            object_bytes, image_bytes, report_bytes, edge_plan_bytes,
            archive_record_bytes, archive_role_bytes, owner_codes, wrapper_codes)
    except (AttributeError, IndexError, KeyError, OverflowError, StopIteration, TypeError) as error:
        raise ValueError("builder archive publication: unsupported artifact shape") from error
