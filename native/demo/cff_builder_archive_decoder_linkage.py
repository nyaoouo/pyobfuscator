"""Selected COFF/PE call-boundary proof for the archive decoder chain.

This binds the five marked functions and their local Win64 argument routes.
It does not infer the parse, AEAD, destination-write, cache or OS effects of
those calls, nor every inter-state path in the 19-body acquisition function.
"""

from __future__ import annotations

from collections import deque
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_local_callees import _check_plain_unwind
from cff_builder_original_predicates import (_dispatcher_destination, _mix,
                                             _states, _transition)
from cff_joint_machine_evidence import (ALIASES, CALLER_SAVED, DIRECT,
                                        _check_rsi_unwind, _instructions)
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image


ARCHIVE_DECODER_CALLEES = (
    "_ZN12pyobfuscator6native7archive14require_recordEPKhyjPhyRNS1_5CacheES3_",
    "_ZN12pyobfuscator6native7archive14acquire_recordEPKhyjPhyRNS1_5CacheES3_",
    "_ZN12pyobfuscator6native7archive12parse_recordEPKhyjRNS1_10RecordViewE",
    "_ZN12pyobfuscator6native7archive12_GLOBAL__N_113verify_accessERKNS1_10RecordViewEPKh",
    "_ZN12pyobfuscator6native7archive12_GLOBAL__N_16decodeERKNS1_10RecordViewEPKhPh",
)
REQUIRE, ACQUIRE, PARSE, ACCESS, DECODE = ARCHIVE_DECODER_CALLEES
FAILURE = "_ZN12pyobfuscator6native8platform18protection_failureEj"
MASK32 = 0xffffffff
STACK = re.compile(r"^(0x[0-9a-f]+)\(%rsp\)$")
MEMORY = re.compile(r"^(-?0x[0-9a-f]+)?\((%[a-z][a-z0-9]*)\)$")
REGISTER = re.compile(r"^%([a-z][a-z0-9]*)$")
STACK_POINTERS = {"%rsp", "%esp", "%sp", "%spl"}
HIGH_BYTES = {"ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx"}
TERMINAL = {"jmp", "jmpq", "jae", "ret", "retq"}
EXPECTED_REAL = {REQUIRE: 3, ACQUIRE: 19, PARSE: 18, ACCESS: 1, DECODE: 3}
ROUTE_OPCODES = {
    "addl", "addq", "andb", "call", "callq", "cmovbl", "cmovel", "cmovnel",
    "cmpl", "cmpq", "divq", "imull", "jae", "jmp", "jmpq", "leaq", "movb",
    "movl", "movq", "orq", "popq", "pushq", "ret", "retq", "sete", "setne",
    "shrl", "subl", "subq", "testb", "xorl", "xorq",
}
FRAME_OPCODES = ROUTE_OPCODES | {
    "andl", "cmpb", "decl", "imulq", "movw", "orb", "seta", "setae",
    "setb", "testl",
}


def _fail(reason: str) -> None:
    raise ValueError(f"archive decoder linkage: {reason}")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("duplicate raw report key")
        result[key] = value
    return result


def _recipes(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: _fail("nonfinite raw report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("archive decoder linkage: invalid raw compiler report") from error
    rows = document.get("functions") if type(document) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw report lacks bounded function rows")
    recipes = {}
    for name in ARCHIVE_DECODER_CALLEES:
        selected = [row for row in rows if type(row) is dict and row.get("function") == name]
        kind = "shape-only" if name == ACCESS else "decision-flow"
        if (len(selected) != 1 or selected[0].get("selected") is not True or
                selected[0].get("status") != "transformed" or
                selected[0].get("strategy") != "relative-tree" or
                selected[0].get("coverage_kind") != kind):
            _fail(f"raw report lacks one transformed archive function: {name}")
        row = selected[0]
        recipe = row.get("effective_recipe")
        totals = row.get("site_totals")
        roles = totals.get("body_roles") if type(totals) is dict else None
        if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
                recipe.get("strategy") != "relative-tree" or
                type(roles) is not dict or roles.get("real") != EXPECTED_REAL[name] or
                (name == ACCESS and roles.get("shape") != 2)):
            _fail(f"unsupported selected archive recipe: {name}")
        recipes[name] = recipe
    return recipes


def _subjects(object_bytes: bytes, image_bytes: bytes, image):
    spans = {}
    for index, name in enumerate(ARCHIVE_DECODER_CALLEES):
        try:
            subject = function_subject(object_bytes, image_bytes, image, 0xbe00 + index, name)
        except ValueError as error:
            _fail(f"{name} COFF/PE contribution: {error}")
        if (subject.kind != "function-contribution" or subject.label != name or
                len(subject.ranges) != 1):
            _fail(f"{name} has an unsupported contribution extent")
        spans[name] = subject.ranges[0]
    ordered = sorted((span.rva, span.rva + span.size) for span in spans.values())
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        _fail("selected archive contributions overlap")
    return spans


def _items(code: str, image_bytes: bytes, image, name: str, span):
    try:
        items = _instructions(code, image_bytes, name.lower())
    except ValueError as error:
        _fail(f"{name} disassembly: {error}")
    if (not items or items[0].address != image.preferred_base + span.rva or
            items[-1].address + len(items[-1].raw) !=
            image.preferred_base + span.rva + span.size):
        _fail(f"{name} disassembly misses exact contribution")
    return items


def _frame(image_bytes, image, span, items, name):
    if name == ACQUIRE:
        if (len(items) < 3 or items[0].raw != b"\x56" or
                items[1].raw != b"\x48\x81\xec\xc0\x00\x00\x00"):
            _fail("acquire frame is not the selected Win64 push/allocate form")
        try:
            _check_rsi_unwind(items, image_bytes, 0xc0)
        except ValueError as error:
            _fail(f"acquire frame/unwind: {error}")
        _return_frame(items, name, 0xc0, saved_rsi=True)
        return
    allocation = {REQUIRE: 0xb8, PARSE: 0x88, ACCESS: 0xf8, DECODE: 0xe8}[name]
    if items[0].raw != b"\x48\x81\xec" + struct.pack("<I", allocation):
        _fail(f"{name} has an unsupported Win64 frame")
    try:
        _check_plain_unwind(image_bytes, image, span, items[0], allocation)
    except ValueError as error:
        _fail(f"{name} frame/unwind: {error}")
    _return_frame(items, name, allocation, saved_rsi=False)


def _return_frame(items, name, allocation, *, saved_rsi):
    returns = [index for index, item in enumerate(items)
               if item.opcode in ("ret", "retq")]
    if len(returns) != 1 or items[returns[0]].raw != b"\xc3":
        _fail(f"{name} has an unsupported return inventory")
    end = returns[0]
    restore = end - (2 if saved_rsi else 1)
    expected = b"\x48\x81\xc4" + struct.pack("<I", allocation)
    if (restore < 0 or items[restore].opcode != "addq" or
            items[restore].operands != (f"${allocation:#x}", "%rsp") or
            items[restore].raw != expected):
        _fail(f"{name} return does not restore its Win64 frame")
    if saved_rsi and (items[end - 1].opcode != "popq" or
                      items[end - 1].operands != ("%rsi",) or
                      items[end - 1].raw != b"\x5e"):
        _fail("acquire return does not restore saved RSI")
    prologue = 1 if saved_rsi else 0
    for index, item in enumerate(items):
        if (item.opcode in ("pushq", "popq") and index not in
                ({0, end - 1} if saved_rsi else set())):
            _fail(f"{name} changes its stack outside the selected frame")
        if (item.operands and item.operands[-1] in STACK_POINTERS and
                index not in (prologue, restore)):
            _fail(f"{name} changes RSP outside its prologue/epilogue")


def _root(obj, name):
    matches = [row for row in obj.symbols if row.name == name and row.type == 0x20 and
               row.section > 0 and row.value == 0]
    if len(matches) != 1:
        _fail(f"missing unique COFF function root: {name}")
    return matches[0]


def _call_target(object_bytes, obj, resolver, image, spans, caller, item, callee):
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    target = image.preferred_base + spans[callee].rva
    if (item.opcode not in ("call", "callq") or item.raw[:1] != b"\xe8" or
            len(item.raw) != 5 or match is None or match[2] != callee.lower() or
            int(match[1], 16) != target or
            item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target):
        _fail(f"{caller} call does not reach exact linked {callee}")
    caller_root, callee_root = _root(obj, caller), _root(obj, callee)
    section = obj.sections[caller_root.section - 1]
    offset = item.address - image.preferred_base - spans[caller].rva
    if (not 0 <= offset <= section.size - 5 or
            object_bytes[section.offset + offset] != 0xe8):
        _fail("archive call crosses its COFF contribution")
    found = [row for row in section.relocations if row.offset == offset + 1]
    if (len(found) != 1 or found[0].kind != 4 or found[0].target != callee_root.index or
            struct.unpack_from("<i", object_bytes, section.offset + offset + 1)[0] != 0 or
            resolver.named(callee) != spans[callee].rva):
        _fail(f"{callee} call lacks its exact root-symbol REL32 relocation")


def _one(items, reason):
    if len(items) != 1:
        _fail(reason)
    return items[0]


def _selected_call(items, name):
    return _one([item for item in items if item.opcode in ("call", "callq") and
                 len(item.operands) == 1 and
                 (match := DIRECT.fullmatch(item.operands[0])) is not None and
                 match[2] == name.lower()], f"missing unique linked call to {name}")


def _exact(items, expected, label):
    if len(items) != len(expected):
        _fail(f"{label} has an unsupported instruction count")
    for item, (opcode, operands) in zip(items, expected):
        if item.opcode != opcode or item.operands != operands:
            _fail(f"{label} has an unsupported instruction or argument route")


def _branch_target(item, addresses):
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    raw = item.raw
    if match is None:
        _fail("archive CFG has an indirect or unsupported branch")
    target = int(match[1], 16)
    if item.opcode in ("jmp", "jmpq") and len(raw) == 2 and raw[0] == 0xeb:
        encoded = item.address + 2 + struct.unpack_from("<b", raw, 1)[0]
    elif item.opcode in ("jmp", "jmpq") and len(raw) == 5 and raw[0] == 0xe9:
        encoded = item.address + 5 + struct.unpack_from("<i", raw, 1)[0]
    elif item.opcode == "jae" and len(raw) == 2 and raw[0] == 0x73:
        encoded = item.address + 2 + struct.unpack_from("<b", raw, 1)[0]
    elif item.opcode == "jae" and len(raw) == 6 and raw[:2] == b"\x0f\x83":
        encoded = item.address + 6 + struct.unpack_from("<i", raw, 2)[0]
    else:
        _fail("archive CFG has an unsupported branch encoding")
    if encoded != target:
        _fail("archive CFG branch text differs from its PE displacement")
    if target not in addresses:
        _fail("archive CFG branch leaves the exact function or enters an instruction")
    return target


def _cfg(items, protected, allowed_calls, *, route):
    addresses = {item.address for item in items}
    if len(addresses) != len(items):
        _fail("archive CFG duplicates an instruction address")
    successors = {}
    for item in items:
        if item.opcode not in (ROUTE_OPCODES if route else FRAME_OPCODES):
            _fail("archive CFG has an unsupported route instruction")
        if ((len(item.operands) > 2 and item.opcode not in ("imull", "imulq")) or
                any("(" in operand and _memory(operand) is None
                    for operand in item.operands)):
            _fail("archive CFG has an unmodeled indexed route operand")
        following = item.address + len(item.raw)
        if item.opcode in ("ret", "retq"):
            if item.operands:
                _fail("archive CFG has an unsupported return")
            successors[item.address] = ()
        elif item.opcode in ("jmp", "jmpq", "jae"):
            target = _branch_target(item, addresses)
            if item.opcode == "jae" and following not in addresses:
                _fail("archive CFG conditional fallthrough leaves its function")
            successors[item.address] = (target,) if item.opcode.startswith("jmp") else (target, following)
        else:
            if following not in addresses:
                _fail("archive CFG has an unmodeled terminal instruction")
            successors[item.address] = (following,)
            if item.opcode in ("call", "callq"):
                match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
                if match is None or item.raw[:1] != b"\xe8" or len(item.raw) != 5:
                    _fail("archive CFG has an indirect or malformed call")
                target = int(match[1], 16)
                if item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target:
                    _fail("archive call text differs from its PE displacement")
                if (any(begin <= target < end for begin, end in protected) and
                        item.address not in allowed_calls):
                    _fail("archive unselected call enters a protected function interval")
    return successors


def _frame_edges(items, successors, name):
    by_address = {item.address: item for item in items}
    predecessors = {address: set() for address in by_address}
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].add(source)
    prologue_end = 1 if name == ACQUIRE else 0
    if predecessors[items[0].address]:
        _fail(f"{name} CFG re-enters its frame prologue")
    for index in range(1, prologue_end + 1):
        if predecessors[items[index].address] != {items[index - 1].address}:
            _fail(f"{name} CFG enters its frame prologue interior")
    returns = [index for index, item in enumerate(items)
               if item.opcode in ("ret", "retq")]
    if len(returns) != 1:
        _fail(f"{name} CFG has an unsupported return inventory")
    start = returns[0]
    while start > 0 and items[start - 1].opcode not in TERMINAL:
        start -= 1
    for index in range(start + 1, returns[0] + 1):
        previous, current = items[index - 1], items[index]
        if (successors[previous.address] != (current.address,) or
                predecessors[current.address] != {previous.address}):
            _fail(f"{name} CFG bypasses its complete return frame restoration")


def _window(items, call, successors):
    index = items.index(call)
    before = index - 1
    while before >= 0 and items[before].opcode not in TERMINAL:
        before -= 1
    start = before + 1
    after = index + 1
    while after < len(items) and items[after].opcode not in TERMINAL:
        after += 1
    if start >= index or after >= len(items) or items[after].opcode not in ("jmp", "jmpq"):
        _fail("archive call has an unsupported straight-line state body")
    interval = {item.address for item in items[start:after + 1]}
    for left, targets in successors.items():
        for target in targets:
            if target in interval and target != items[start].address and left not in interval:
                _fail("archive CFG bypasses a selected call window")
    for current, next_item in zip(items[start:after], items[start + 1:after + 1]):
        if successors[current.address] != (next_item.address,):
            _fail("archive selected call window has a side exit")
    return items[start:after + 1]


def _entry(items, name, state, state_slot, initial):
    first = 2 if name == ACQUIRE else 1
    slots = (0x30, 0x3c, 0x40, 0x48, 0x50, 0x58, 0x60) if name == ACQUIRE else (
        0x40, 0x4c, 0x50, 0x58, 0x60, 0x68, 0x70)
    displaced = (0x100, 0xf8, 0xf0) if name == ACQUIRE else (0xf0, 0xe8, 0xe0)
    expected = [("movq", ("%r9", f"{slots[0]:#x}(%rsp)")),
                ("movl", ("%r8d", f"{slots[1]:#x}(%rsp)")),
                ("movq", ("%rdx", f"{slots[2]:#x}(%rsp)")),
                ("movq", ("%rcx", f"{slots[3]:#x}(%rsp)"))]
    for source, dest in zip(displaced, slots[4:]):
        expected += [("movq", (f"{source:#x}(%rsp)", "%rax")),
                     ("movq", ("%rax", f"{dest:#x}(%rsp)"))]
    _exact(items[first:first + len(expected)], expected, f"{name} Win64 entry sources")
    initializer, branch = items[first + len(expected):first + len(expected) + 2]
    if (initializer.opcode != "movl" or
            initializer.operands != (f"${state:#x}", f"{state_slot:#x}(%rsp)") or
            initializer.raw[:7] != b"\xc7\x84\x24" + struct.pack("<I", state_slot) or
            initializer.raw[7:] != struct.pack("<I", state) or
            branch.opcode not in ("jmp", "jmpq")):
        _fail(f"{name} has an unsupported initialized dispatcher state")
    if _branch_target(branch, {item.address for item in items}) != initial:
        _fail(f"{name} entry does not reach its selected dispatcher")
    return slots


def _register(operand):
    match = REGISTER.fullmatch(operand)
    if match and operand in STACK_POINTERS:
        return "rsp"
    if match and match[1] in HIGH_BYTES:
        return HIGH_BYTES[match[1]]
    return ALIASES.get(match[1]) if match else None


def _memory(operand):
    match = MEMORY.fullmatch(operand)
    return (int(match[1], 0) if match[1] else 0, _register(match[2])) if match else None


def _protected_stack_slots(items, slots, first, successors, entry_index):
    # Propagate only pointers explicitly derived from this frame's RSP. An
    # external pointer's aliasing and any callee write remain outside scope.
    protected = [(slot, 4 if index == 1 else 8) for index, slot in enumerate(slots)]
    for item in items[first:]:
        if not item.operands or item.opcode in ("cmpl", "cmpq", "testb"):
            continue
        match = STACK.fullmatch(item.operands[-1])
        if match is None:
            continue
        slot = int(match[1], 16)
        width = 8 if item.opcode.endswith("q") else (1 if item.opcode.endswith("b") else 4)
        if any(slot < old + length and old < slot + width for old, length in protected):
            _fail("captured Win64 argument slot is overwritten after entry")
    by_address = {item.address: (index, item) for index, item in enumerate(items)}
    start = items[entry_index].address
    incoming = {start: ({"rsp": frozenset((0,))}, {})}
    pending = deque((start,))
    writes = {"movq", "movl", "movb", "addq", "addl", "subq", "subl",
              "xorl", "xorq", "orq", "andb", "shrl", "sete", "setne", "imull"}

    def source_alias(operand, registers, stack):
        register = _register(operand)
        if register:
            return registers.get(register, frozenset())
        memory = _memory(operand)
        if memory:
            displacement, base = memory
            return frozenset().union(*(stack.get(origin + displacement, frozenset())
                                       for origin in registers.get(base, ())))
        return frozenset()

    steps = 0
    while pending:
        steps += 1
        if steps > 20_000:
            _fail("frame-derived alias propagation exceeds bounded profile")
        address = pending.popleft()
        index, item = by_address[address]
        old_registers, old_stack = incoming[address]
        registers, stack = dict(old_registers), dict(old_stack)
        operation = item.opcode
        operands = item.operands
        if operation in ("call", "callq"):
            for register in CALLER_SAVED:
                registers.pop(register, None)
        elif operation == "divq":
            registers.pop("rax", None)
            registers.pop("rdx", None)
        elif operands and operation not in ("cmpl", "cmpq", "testb", "pushq"):
            destination = operands[-1]
            destination_memory = _memory(destination)
            if destination_memory and operation in writes:
                displacement, base = destination_memory
                origins = registers.get(base, ())
                width = 8 if operation.endswith("q") else (1 if operation.endswith("b") else 4)
                for origin in origins:
                    slot = origin + displacement
                    if index >= first and any(slot < old + length and old < slot + width
                                              for old, length in protected):
                        _fail("frame-derived pointer overwrites a captured Win64 argument")
                    if operation == "movq":
                        alias = source_alias(operands[0], registers, stack)
                        if alias:
                            stack[slot] = alias
                        else:
                            stack.pop(slot, None)
                    elif slot in stack:
                        _fail("partial write changes a frame-derived pointer")
            elif operation in writes and not destination_memory and "(" in destination:
                # A newly introduced indexed store needs a separate alias proof.
                _fail("archive route has an unmodeled indirect memory write")
            destination_register = _register(destination)
            if destination_register and destination_register != "rsp":
                old_aliases = registers.get(destination_register, frozenset())
                if operation == "leaq" and (memory := _memory(operands[0])):
                    displacement, base = memory
                    aliases = frozenset(origin + displacement
                                        for origin in registers.get(base, ()))
                elif operation == "movq":
                    aliases = source_alias(operands[0], registers, stack)
                elif operation.startswith("cmov"):
                    aliases = registers.get(destination_register, frozenset()) | \
                              source_alias(operands[0], registers, stack)
                elif (old_aliases and operation in ("xorl", "xorq") and
                      _register(operands[0]) == destination_register):
                    aliases = frozenset()
                else:
                    if old_aliases:
                        _fail("archive route mutates an unmodeled frame-derived pointer")
                    aliases = frozenset()
                if aliases:
                    registers[destination_register] = aliases
                else:
                    registers.pop(destination_register, None)
        for target in successors[address]:
            previous = incoming.get(target)
            if previous is None:
                incoming[target] = (registers, stack)
                pending.append(target)
                continue
            merged_registers = {key: previous[0].get(key, frozenset()) |
                                registers.get(key, frozenset())
                                for key in previous[0].keys() | registers.keys()}
            merged_stack = {key: previous[1].get(key, frozenset()) |
                            stack.get(key, frozenset())
                            for key in previous[1].keys() | stack.keys()}
            if sum(map(len, merged_registers.values())) + sum(
                    map(len, merged_stack.values())) > 1024:
                _fail("frame-derived aliases exceed bounded profile")
            if (merged_registers, merged_stack) != previous:
                incoming[target] = (merged_registers, merged_stack)
                pending.append(target)


def _intervals(image, spans):
    return tuple((image.preferred_base + span.rva,
                  image.preferred_base + span.rva + span.size)
                 for span in spans.values())


def _require_route(items, successors, recipe, object_bytes, obj, resolver, image, spans):
    state = _states(REQUIRE, recipe)[0]
    dispatcher = _branch_target(items[12], {item.address for item in items})
    slots = _entry(items, REQUIRE, state, 0xb4, dispatcher)
    call = _selected_call(items, ACQUIRE)
    _call_target(object_bytes, obj, resolver, image, spans, REQUIRE, call, ACQUIRE)
    _protected_stack_slots(items, slots, 13, successors, 1)
    window = _window(items, call, successors)
    if _dispatcher_destination(items, dispatcher, state, 0xb4) != window[0].address:
        _fail("require initial state bypasses acquire call")
    prefix = [
        ("movq", ("0x60(%rsp)", "%rax")),
        ("movq", ("0x68(%rsp)", "%rcx")),
        ("movq", ("0x70(%rsp)", "%rdx")),
        ("movq", ("0x40(%rsp)", "%r8")),
        ("movl", ("0x4c(%rsp)", "%r9d")),
        ("movq", ("0x50(%rsp)", "%r10")),
        ("movq", ("0x58(%rsp)", "%r11")),
    ]
    temporaries = (("%r11", "0x78", "movq"), ("%r10", "0x80", "movq"),
                   ("%r9d", "0x8c", "movl"), ("%r8", "0x90", "movq"),
                   ("%rdx", "0x98", "movq"), ("%rcx", "0xa0", "movq"),
                   ("%rax", "0xa8", "movq"))
    prefix += [(op, (reg, f"{slot}(%rsp)")) for reg, slot, op in temporaries]
    prefix += [(op, (f"{slot}(%rsp)", reg)) for slot, reg, op in (
        ("0x78", "%rcx", "movq"), ("0x80", "%rdx", "movq"),
        ("0x8c", "%r8d", "movl"), ("0x90", "%r9", "movq"),
        ("0x98", "%r11", "movq"), ("0xa0", "%r10", "movq"),
        ("0xa8", "%rax", "movq"))]
    prefix += [("movq", ("%r11", "0x20(%rsp)")),
               ("movq", ("%r10", "0x28(%rsp)")),
               ("movq", ("%rax", "0x30(%rsp)"))]
    _exact(window[:len(prefix)], prefix, "require seven-argument acquire route")
    if window[len(prefix)] != call:
        _fail("require acquire call is not adjacent to its seven arguments")
    after = window[len(prefix) + 1:]
    _exact(after[:2], [("movl", ("%eax", "0xb0(%rsp)")),
                       ("movl", ("0xb0(%rsp)", "%r8d"))],
           "require acquire result")
    compare = _one([index for index, item in enumerate(items) if item.opcode == "cmpl" and
                    item.operands == ("$0x0", "%r8d")],
                   "require lacks a unique acquisition result comparison")
    if items[compare - 1].operands != ("$0xe9b13637", "%edx"):
        _fail("require result is detached from its encoded state arms")
    false_arm, true_arm, salt, _ = _transition(items, compare, dispatcher, 0xb4)
    if (items[compare + 1].opcode != "cmovnel" or
            items[compare].raw != b"\x41\x83\xf8\x00" or
            _dispatcher_destination(items, dispatcher,
                (state + (_mix(state ^ salt) ^ false_arm)) & MASK32, 0xb4) !=
                next(item.address for item in items if item.opcode in ("addq",) and
                     item.operands == ("$0xb8", "%rsp")) or
            _dispatcher_destination(items, dispatcher,
                (state + (_mix(state ^ salt) ^ true_arm)) & MASK32, 0xb4) !=
                next(item.address for item in items if item.operands ==
                     ("0xb0(%rsp)", "%ecx"))):
        _fail("require result state does not distinguish return and failure")


def _acquire_route(items, successors, recipe, object_bytes, obj, resolver, image, spans):
    state = _states(ACQUIRE, recipe)[0]
    dispatcher = _branch_target(items[13], {item.address for item in items})
    slots = _entry(items, ACQUIRE, state, 0xbc, dispatcher)
    calls = {name: _selected_call(items, name) for name in (PARSE, ACCESS, DECODE)}
    _protected_stack_slots(items, slots, 14, successors, 2)
    windows = {}
    for name, call in calls.items():
        _call_target(object_bytes, obj, resolver, image, spans, ACQUIRE, call, name)
        windows[name] = _window(items, call, successors)
    if _dispatcher_destination(items, dispatcher, state, 0xbc) != windows[PARSE][0].address:
        _fail("acquire initial state bypasses parse call")
    parse_prefix = [("leaq", ("0x68(%rsp)", "%rcx")),
                    ("xorl", ("%edx", "%edx")),
                    ("movl", ("$0x30", "%r8d"))]
    _exact(windows[PARSE][:3], parse_prefix, "acquire record-view setup")
    setup = windows[PARSE][3]
    if (setup.opcode not in ("call", "callq") or
            not setup.operands[0].endswith(" <memset>")):
        _fail("acquire record-view initialization is absent")
    _exact(windows[PARSE][4:8], [
        ("movq", ("0x48(%rsp)", "%rcx")),
        ("movq", ("0x40(%rsp)", "%rdx")),
        ("movl", ("0x3c(%rsp)", "%r8d")),
        ("leaq", ("0x68(%rsp)", "%r9"))], "acquire parse argument chain")
    if windows[PARSE][8] != calls[PARSE]:
        _fail("acquire parse call is detached from its arguments")
    _exact(windows[ACCESS][:2], [
        ("movq", ("0x50(%rsp)", "%rdx")),
        ("leaq", ("0x68(%rsp)", "%rcx"))], "acquire access argument chain")
    if windows[ACCESS][2] != calls[ACCESS]:
        _fail("acquire access call is detached from its arguments")
    _exact(windows[DECODE][:13], [
        ("movq", ("0x30(%rsp)", "%r8")),
        ("movq", ("0x50(%rsp)", "%rdx")),
        ("movq", ("0x58(%rsp)", "%rax")),
        ("movq", ("0x60(%rsp)", "%rcx")),
        ("movl", ("0x3c(%rsp)", "%r9d")),
        ("movq", ("0x40(%rsp)", "%r10")),
        ("movq", ("0x48(%rsp)", "%r11")),
        ("movq", ("%r11", "0x8(%rax)")),
        ("movq", ("%r10", "0x10(%rax)")),
        ("movl", ("%r9d", "0x18(%rax)")),
        ("movq", ("%r8", "0x20(%rax)")),
        ("movq", ("%rcx", "0x28(%rax)")),
        ("leaq", ("0x68(%rsp)", "%rcx"))], "acquire decode argument chain")
    if windows[DECODE][13] != calls[DECODE]:
        _fail("acquire decode call is detached from its arguments")


def verify_builder_archive_decoder_linkage(object_bytes: bytes, image_bytes: bytes,
                                           report_bytes: bytes, codes: dict[str, str]) -> dict:
    """Refuse unless five selected compiler roots and their local call routes bind."""
    try:
        if (type(object_bytes) is not bytes or type(image_bytes) is not bytes or
                type(codes) is not dict or set(codes) != set(ARCHIVE_DECODER_CALLEES) or
                any(type(value) is not str for value in codes.values())):
            _fail("unsupported artifact or five-symbol disassembly input")
        recipes = _recipes(report_bytes)
        obj, image = parse_object(object_bytes), parse_image(image_bytes)
        resolver = Resolver(obj, image, image_symbols(image_bytes, image))
        spans = _subjects(object_bytes, image_bytes, image)
        instructions = {name: _items(codes[name], image_bytes, image, name, spans[name])
                        for name in ARCHIVE_DECODER_CALLEES}
        for name, items in instructions.items():
            _frame(image_bytes, image, spans[name], items, name)
        allowed = {REQUIRE: {_selected_call(instructions[REQUIRE], ACQUIRE).address},
                   ACQUIRE: {_selected_call(instructions[ACQUIRE], name).address
                             for name in (PARSE, ACCESS, DECODE)}}
        intervals = _intervals(image, spans)
        graphs = {name: _cfg(items, intervals, allowed.get(name, set()),
                             route=name in (REQUIRE, ACQUIRE))
                  for name, items in instructions.items()}
        for name, items in instructions.items():
            _frame_edges(items, graphs[name], name)
        _require_route(instructions[REQUIRE], graphs[REQUIRE], recipes[REQUIRE], object_bytes, obj,
                       resolver, image, spans)
        _acquire_route(instructions[ACQUIRE], graphs[ACQUIRE], recipes[ACQUIRE], object_bytes, obj,
                       resolver, image, spans)
        return {
            "verified": True,
            "decoder_linkage_verified": True,
            "require_to_acquire_verified": True,
            "acquire_to_children_verified": True,
            "argument_chain_verified": True,
            "decoder_effect_verified": False,
            "cache_effect_verified": False,
            "platform_crypto_verified": False,
            "acquire_inter_state_reachability_verified": False,
            "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
            "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        }
    except (AttributeError, IndexError, KeyError, OverflowError, StopIteration,
            TypeError, struct.error) as error:
        raise ValueError("archive decoder linkage: unsupported artifact shape") from error
