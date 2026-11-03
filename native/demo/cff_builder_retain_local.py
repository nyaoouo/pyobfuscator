"""Bind the selected retain-context guards and increment to one linked PE.

Only the two observed Windows x64 CLANG64 lowerings are accepted. This is a
local route witness; lock implementation and caller effects are separate.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_binding_status_effects import (
    _at, _boundaries, _choice, _exact, _plain_transition,
)
from cff_builder_bound_call import LOCK, RETAIN, UNLOCK
from cff_builder_local_callees import _check_plain_unwind
from cff_builder_original_predicates import _states
from cff_joint_machine_evidence import DIRECT, Instruction, _instructions
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import parse_image, read_rva


MAXIMUM = "_ZNSt3__114numeric_limitsIjE3maxB9nqe220108Ev"
MAXIMUM_BODY = "_ZNSt3__123__libcpp_numeric_limitsIjLb1EE3maxB9nqe220108Ev"
CALL_TARGETS = (LOCK, UNLOCK, MAXIMUM)
STATE_SLOT = "0x54(%rsp)"
SALT = 0x3b1a8c19
STACK = re.compile(r"(?:0x([0-9a-f]+))?\(%rsp\)")


def _fail(reason):
    raise ValueError(f"retain local route: {reason}")


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _fail("duplicate raw compiler report key")
        result[name] = value
    return result


def _recipe(report_bytes):
    if type(report_bytes) is not bytes or not 0 < len(report_bytes) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        report = json.loads(report_bytes.decode("utf-8"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _fail("nonfinite report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("retain local route: invalid raw compiler report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw compiler report lacks bounded function rows")
    selected = [row for row in rows if type(row) is dict and row.get("function") == RETAIN]
    if (len(selected) != 1 or selected[0].get("selected") is not True or
            selected[0].get("status") != "transformed" or
            selected[0].get("strategy") != "relative-tree" or
            selected[0].get("coverage_kind") != "decision-flow"):
        _fail("raw report lacks one transformed retain-context owner")
    row = selected[0]
    recipe = row.get("effective_recipe")
    roles = row.get("site_totals")
    roles = roles.get("body_roles") if type(roles) is dict else None
    count = roles.get("real") if type(roles) is dict else None
    if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
            recipe.get("strategy") != "relative-tree" or count not in (5, 8)):
        _fail("unsupported retain-context recipe or real-body count")
    return recipe, count


def _subject(object_bytes, image_bytes, image, name, tag):
    try:
        subject = function_subject(object_bytes, image_bytes, image, tag, name)
    except ValueError as error:
        _fail(f"{name} COFF/PE contribution: {error}")
    if subject.kind != "function-contribution" or len(subject.ranges) != 1:
        _fail(f"{name} has an unsupported contribution extent")
    return subject.ranges[0]


def _maximum_source(object_bytes, image_bytes, image, spans):
    """The selected libc++ two-function chain returns exactly UINT32_MAX."""
    wrapper = spans[MAXIMUM]
    body = spans[MAXIMUM_BODY]
    if wrapper.size not in (5, 15) or body.size != 6:
        _fail("numeric limit helper has an unsupported extent")
    wrapper_bytes = read_rva(image_bytes, image, wrapper.rva, wrapper.size)
    constant = read_rva(image_bytes, image, body.rva, body.size)
    if constant != b"\xb8\xff\xff\xff\xff\xc3":
        _fail("numeric limit helper does not return UINT32_MAX")
    if wrapper.size == 5:
        if (wrapper_bytes[:1] != b"\xe9" or
                wrapper.rva + 5 + struct.unpack_from("<i", wrapper_bytes, 1)[0] != body.rva):
            _fail("numeric limit tail jump does not reach UINT32_MAX")
        relocation_offset = 1
    else:
        if (wrapper_bytes[:5] != b"\x48\x83\xec\x28\xe8" or
                wrapper_bytes[9:] != b"\x90\x48\x83\xc4\x28\xc3" or
                wrapper.rva + 9 + struct.unpack_from("<i", wrapper_bytes, 5)[0] != body.rva):
            _fail("numeric limit framed call does not reach UINT32_MAX")
        prologue = Instruction(image.preferred_base + wrapper.rva,
                               wrapper_bytes[:4], "subq", ("$0x28", "%rsp"))
        try:
            _check_plain_unwind(image_bytes, image, wrapper, prologue, 0x28)
        except ValueError as error:
            _fail(f"numeric limit frame/unwind: {error}")
        relocation_offset = 5
    obj = parse_object(object_bytes)
    roots = {name: [symbol for symbol in obj.symbols if symbol.name == name and
                    symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
             for name in (MAXIMUM, MAXIMUM_BODY)}
    if any(len(found) != 1 for found in roots.values()):
        _fail("numeric limit helper lacks exact COFF roots")
    section = obj.sections[roots[MAXIMUM][0].section - 1]
    if (len(section.relocations) != 1 or
            section.relocations[0].offset != relocation_offset or
            section.relocations[0].kind != 4 or
            section.relocations[0].target != roots[MAXIMUM_BODY][0].index or
            struct.unpack_from("<i", object_bytes,
                               section.offset + relocation_offset)[0] != 0 or
            obj.sections[roots[MAXIMUM_BODY][0].section - 1].relocations):
        _fail("numeric limit helper lacks its exact COFF jump target")


def _calls(object_bytes, image, spans, items):
    obj = parse_object(object_bytes)
    roots = {name: [symbol for symbol in obj.symbols if symbol.name == name and
                    symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
             for name in (RETAIN, *CALL_TARGETS)}
    if any(len(found) != 1 for found in roots.values()):
        _fail("retain route lacks unique COFF caller/callee roots")
    section = obj.sections[roots[RETAIN][0].section - 1]
    if section.size != spans[RETAIN].size or len(section.relocations) != 3:
        _fail("retain COFF relocation inventory differs from selected route")
    calls = [item for item in items if item.opcode in ("call", "callq")]
    if len(calls) != 3:
        _fail("retain route has an unexpected call inventory")
    names = {}
    for item in calls:
        display = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
        matching = [name for name in CALL_TARGETS if display and display[2] == name.lower()]
        if (item.raw[:1] != b"\xe8" or len(item.raw) != 5 or
                len(matching) != 1):
            _fail("retain route has an indirect or unknown call")
        name = matching[0]
        target = image.preferred_base + spans[name].rva
        offset = item.address - image.preferred_base - spans[RETAIN].rva
        overlapping = [rel for rel in section.relocations if
                       rel.offset < offset + 5 and
                       offset < rel.offset + (8 if rel.kind == 1 else 4)]
        if (int(display[1], 16) != target or
                item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target or
                len(overlapping) != 1 or overlapping[0].offset != offset + 1 or
                overlapping[0].kind != 4 or
                overlapping[0].target != roots[name][0].index or
                struct.unpack_from("<i", object_bytes, section.offset + offset + 1)[0] != 0):
            _fail(f"{name} call misses its exact COFF/PE target")
        names[item.address] = name
    if set(names.values()) != set(CALL_TARGETS):
        _fail("retain route does not call lock, unlock and numeric maximum once")
    return names


def _stack_layout(items):
    intervals = set()
    for item in items:
        operands = [operand for operand in item.operands if "%rsp" in operand]
        if not operands:
            continue
        if item.opcode in ("subq", "addq") and operands == ["%rsp"]:
            continue
        if item.opcode not in ("movb", "movl", "movq") or len(operands) != 1:
            _fail("stack access has an unsupported alias or width")
        match = STACK.fullmatch(operands[0])
        if match is None:
            _fail("stack access has an unsupported addressing mode")
        start = int(match[1] or "0", 16)
        width = {"movb": 1, "movl": 4, "movq": 8}[item.opcode]
        if start < 0x20 or start + width > 0x58:
            _fail("stack value enters Win64 call shadow or exceeds frame")
        intervals.add((start, start + width))
    ordered = sorted(intervals)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        _fail("stack values overlap in the selected retain route")


def _dispatcher(items, root, body_starts, copy_slot):
    tree = items[_at(items, root):]
    if (len(tree) < 5 or tree[0].opcode != "movl" or
            tree[0].operands != (STATE_SLOT, "%eax") or
            tree[1].opcode != "movl" or
            tree[1].operands != ("%eax", copy_slot)):
        _fail("retain dispatcher does not copy the encoded state")
    for item in tree[2:]:
        if item.opcode == "movl":
            if item.operands != (copy_slot, "%eax"):
                _fail("dispatcher has another state read or stack write")
        elif item.opcode == "cmpl":
            if (len(item.operands) != 2 or item.operands[1] != "%eax" or
                    not item.operands[0].startswith("$") or
                    not item.raw.startswith(b"\x3d") or len(item.raw) != 5):
                _fail("dispatcher compares an unmodeled value")
        elif item.opcode == "jae":
            continue
        elif item.opcode in ("jmp", "jmpq"):
            target = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
            if target is None or (int(target[1], 16) < root and
                                  int(target[1], 16) not in body_starts):
                _fail("dispatcher enters a protected body interior")
        else:
            _fail("dispatcher has an unmodeled side effect")


def _control_graph(items):
    """Check exact instruction-boundary control flow without narrowing data widths."""
    by_address = {item.address: item for item in items}
    if len(by_address) != len(items):
        _fail("retain disassembly repeats an instruction boundary")
    edges = {}
    calls = []
    for index, item in enumerate(items):
        following = item.address + len(item.raw)
        if item.opcode in ("ret", "retq"):
            destinations = ()
        elif item.opcode in ("call", "callq"):
            calls.append(item)
            destinations = (following,)
        elif item.opcode in ("jmp", "jmpq", "jae"):
            display = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
            if display is None:
                _fail("retain control transfer is not direct")
            target = int(display[1], 16)
            if item.raw[:1] in (b"\xeb", b"\x73") and len(item.raw) == 2:
                displacement = struct.unpack_from("<b", item.raw, 1)[0]
            elif item.raw[:1] == b"\xe9" and len(item.raw) == 5:
                displacement = struct.unpack_from("<i", item.raw, 1)[0]
            elif item.raw[:2] == b"\x0f\x83" and len(item.raw) == 6:
                displacement = struct.unpack_from("<i", item.raw, 2)[0]
            else:
                _fail("retain control transfer has unsupported PE encoding")
            if target != following + displacement:
                _fail("retain control transfer display differs from PE bytes")
            destinations = (target, following) if item.opcode == "jae" else (target,)
        elif item.opcode.startswith("j") or item.opcode in ("int3", "ud2", "syscall"):
            _fail("retain route has an unmodeled control operation")
        else:
            destinations = (following,)
        if any(destination not in by_address for destination in destinations):
            _fail("retain control transfer misses an instruction boundary")
        edges[item.address] = destinations
    return by_address, edges, calls


def _plain(items, index, root, state, next_state, *, fallthrough=False):
    checked = items
    if fallthrough:
        root_index = _at(items, root)
        if (items[root_index - 1].opcode != "movl" or
                items[root_index - 1].operands != ("%eax", STATE_SLOT) or
                items[root_index - 1].address + len(items[root_index - 1].raw) != root):
            _fail("last retain body does not fall into dispatcher")
        checked = items[:root_index] + [Instruction(root, b"\xeb\x00", "jmp",
                                                    (f"{root:#x}",))]
    if _plain_transition(checked, index, STATE_SLOT, root, state, SALT) != next_state:
        _fail("retain body reaches a different state")
    return index + 18 - int(fallthrough)


def _choice_route(items, index, root, state, arms, opcode, operands,
                  *, fallthrough=False):
    compare = items[index + 3]
    if _choice(items, compare.address, root, STATE_SLOT, state, SALT,
               opcode, operands) != arms:
        _fail("retain predicate reaches the wrong state pair")
    return index + 22 - int(fallthrough)


def _expect_calls(calls, items, sites):
    expected = {items[index].address: name for index, name in sites}
    if calls != expected:
        _fail("retain body calls a different exact root")


def _body_none(items, body, states, root, calls):
    b = [_at(items, body[state]) for state in states]
    starts = {body[state] for state in states}
    i = _exact(items, b[0], [
        ("movb", ("0x3f(%rsp)", "%al")),
        ("movq", ("0x30(%rsp)", "%rcx")),
        ("movq", ("%rcx", "0x40(%rsp)")),
        ("andb", ("$0x1", "%al")),
        ("movb", ("%al", "0x4f(%rsp)")),
        ("movq", ("0x40(%rsp)", "%rcx")),
        ("addq", ("$0x38", "%rcx")),
        ("callq", None),
        ("movl", ("$0x0", "0x50(%rsp)")),
        ("movb", ("0x4f(%rsp)", "%r8b"))], "source-none retain entry")
    lock = i - 3
    end = {0: _choice_route(items, i, root, states[0], (states[1], states[3]),
                            "testb", ("$0x1", "%r8b"))}
    i = _exact(items, b[1], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movb", ("0x44(%rax)", "%r8b"))], "source-none closing field")
    end[1] = _choice_route(items, i, root, states[1], (states[3], states[2]),
                            "testb", ("$0x1", "%r8b"))
    i = _exact(items, b[2], [("movl", ("$0x8", "0x50(%rsp)"))],
               "source-none closed status")
    end[2] = _plain(items, i, root, states[2], states[7], fallthrough=True)
    i = _exact(items, b[3], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movl", ("0x3c(%rax)", "%eax")),
        ("movl", ("%eax", "0x2c(%rsp)")),
        ("callq", None),
        ("movl", ("0x2c(%rsp)", "%r8d")),
        ("movl", ("%eax", "%r9d"))], "source-none maximum input")
    maximum = i - 3
    end[3] = _choice_route(items, i, root, states[3], (states[5], states[4]),
                            "cmpl", ("%r9d", "%r8d"))
    i = _exact(items, b[4], [("movl", ("$0x7", "0x50(%rsp)"))],
               "source-none reference-limit status")
    end[4] = _plain(items, i, root, states[4], states[6])
    i = _exact(items, b[5], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movl", ("0x3c(%rax)", "%ecx")),
        ("addl", ("$0x1", "%ecx")),
        ("movl", ("%ecx", "0x3c(%rax)"))], "source-none reference increment")
    end[5] = _plain(items, i, root, states[5], states[6])
    end[6] = _plain(items, b[6], root, states[6], states[7])
    i = _exact(items, b[7], [
        ("movq", ("0x40(%rsp)", "%rcx")),
        ("addq", ("$0x38", "%rcx")),
        ("callq", None),
        ("movl", ("0x50(%rsp)", "%eax")),
        ("addq", ("$0x58", "%rsp")),
        ("retq", ())], "source-none unlock and return")
    end[7] = i
    unlock = b[7] + 2
    _expect_calls(calls, items, ((lock, LOCK), (maximum, MAXIMUM), (unlock, UNLOCK)))
    _closed_body_inventory(items, b, end, root)
    return starts, "0x28(%rsp)"


def _body_o2(items, body, states, root, calls):
    b = [_at(items, body[state]) for state in states]
    starts = {body[state] for state in states}
    i = _exact(items, b[0], [
        ("movq", ("0x30(%rsp)", "%rax")),
        ("addq", ("$0x38", "%rax")),
        ("movq", ("%rax", "0x40(%rsp)")),
        ("movq", ("0x40(%rsp)", "%rcx")),
        ("callq", None),
        ("movb", ("0x3b(%rsp)", "%r8b"))], "optimized retain lock and mode")
    lock = i - 2
    end = {0: _choice_route(items, i, root, states[0], (states[1], states[2]),
                            "testb", ("$0x1", "%r8b"))}
    i = _exact(items, b[1], [
        ("movq", ("0x30(%rsp)", "%rax")),
        ("movb", ("0x44(%rax)", "%r8b")),
        ("movl", ("$0x8", "0x3c(%rsp)"))], "optimized closing field")
    end[1] = _choice_route(items, i, root, states[1], (states[2], states[4]),
                            "testb", ("$0x1", "%r8b"))
    i = _exact(items, b[2], [
        ("movq", ("0x30(%rsp)", "%rax")),
        ("addq", ("$0x3c", "%rax")),
        ("movq", ("%rax", "0x48(%rsp)")),
        ("movq", ("0x48(%rsp)", "%rax")),
        ("movl", ("(%rax)", "%eax")),
        ("movl", ("%eax", "0x28(%rsp)")),
        ("callq", None),
        ("movl", ("0x28(%rsp)", "%r8d")),
        ("movl", ("%eax", "%r9d")),
        ("movl", ("$0x7", "0x3c(%rsp)"))], "optimized maximum input")
    maximum = i - 4
    end[2] = _choice_route(items, i, root, states[2], (states[3], states[4]),
                            "cmpl", ("%r9d", "%r8d"), fallthrough=True)
    i = _exact(items, b[3], [
        ("movq", ("0x48(%rsp)", "%rax")),
        ("movl", ("(%rax)", "%ecx")),
        ("addl", ("$0x1", "%ecx")),
        ("movq", ("0x48(%rsp)", "%rax")),
        ("movl", ("%ecx", "(%rax)")),
        ("movl", ("$0x0", "0x3c(%rsp)"))], "optimized reference increment")
    end[3] = _plain(items, i, root, states[3], states[4])
    i = _exact(items, b[4], [
        ("movl", ("0x3c(%rsp)", "%eax")),
        ("movl", ("%eax", "0x2c(%rsp)")),
        ("movq", ("0x40(%rsp)", "%rcx")),
        ("callq", None),
        ("movl", ("0x2c(%rsp)", "%eax")),
        ("addq", ("$0x58", "%rsp")),
        ("retq", ())], "optimized unlock and return")
    end[4] = i
    unlock = b[4] + 3
    _expect_calls(calls, items, ((lock, LOCK), (maximum, MAXIMUM), (unlock, UNLOCK)))
    _closed_body_inventory(items, b, end, root)
    return starts, "0x24(%rsp)"


def _closed_body_inventory(items, starts, ends, root):
    ordered = sorted((items[start].address, start, ends[role])
                     for role, start in enumerate(starts))
    expected = [address for address, _, _ in ordered[1:]] + [root]
    for (address, start, end), following in zip(ordered, expected):
        if end > len(items) or end <= start or \
                (items[end].address if end < len(items) else None) != following:
            _fail(f"retain body at {address:#x} has an unmodeled instruction gap")


def verify_builder_retain_local(object_bytes: bytes, image_bytes: bytes,
                                report_bytes: bytes, codes: dict) -> dict:
    """Prove the selected local retain route, without transitive SDK effects."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(codes) is not dict or set(codes) != {RETAIN} or
            type(codes[RETAIN]) is not str or not codes[RETAIN]):
        _fail("exact object, image and retain disassembly are required")
    recipe, count = _recipe(report_bytes)
    image = parse_image(image_bytes)
    spans = {name: _subject(object_bytes, image_bytes, image, name, 0xbd00 + index)
             for index, name in enumerate((RETAIN, LOCK, UNLOCK, MAXIMUM, MAXIMUM_BODY))}
    _maximum_source(object_bytes, image_bytes, image, spans)
    try:
        items = _instructions(codes[RETAIN], image_bytes, RETAIN.lower())
    except ValueError as error:
        _fail(f"retain disassembly: {error}")
    owner = spans[RETAIN]
    if (not items or items[0].address != image.preferred_base + owner.rva or
            items[-1].address + len(items[-1].raw) !=
            image.preferred_base + owner.rva + owner.size):
        _fail("retain disassembly misses exact COFF/PE contribution")
    if items[0].opcode != "subq" or items[0].operands != ("$0x58", "%rsp"):
        _fail("retain route lacks the selected Win64 frame")
    try:
        _check_plain_unwind(image_bytes, image, owner, items[0], 0x58)
    except ValueError as error:
        _fail(f"Win64 frame/unwind: {error}")
    _stack_layout(items)
    states = _states(RETAIN, recipe)[:count]
    if count == 8:
        entry = [("movq", ("%rcx", "0x30(%rsp)")),
                 ("movb", ("%dl", "0x3f(%rsp)"))]
    else:
        entry = [("movq", ("%rcx", "0x30(%rsp)")),
                 ("movb", ("%dl", "0x3b(%rsp)"))]
    _exact(items, 1, entry, "retain Win64 argument spills")
    state = items[3]
    if (state.opcode != "movl" or state.operands !=
            (f"${states[0]:#x}", STATE_SLOT) or
            state.raw != b"\xc7\x44\x24\x54" + struct.pack("<I", states[0])):
        _fail("retain entry state differs from the frozen recipe")
    jump = items[4]
    target = DIRECT.fullmatch(jump.operands[0]) if len(jump.operands) == 1 else None
    if jump.opcode not in ("jmp", "jmpq") or target is None:
        _fail("retain entry does not jump to a dispatcher")
    root = int(target[1], 16)
    body = _boundaries(items, root, states, STATE_SLOT)
    if min(body.values()) != items[5].address:
        _fail("retain entry has an unmodeled gap before its first body")
    graph, edges, graph_calls = _control_graph(items)
    if len(graph_calls) != 3 or root not in graph:
        _fail("retain CFG has an unsupported call or dispatcher inventory")
    calls = _calls(object_bytes, image, spans, items)
    if count == 8:
        starts, copy_slot = _body_none(items, body, states, root, calls)
    else:
        starts, copy_slot = _body_o2(items, body, states, root, calls)
    _dispatcher(items, root, starts, copy_slot)
    for address, successors in edges.items():
        if address < root and address not in starts:
            for successor in successors:
                if successor in starts and successor != address + len(graph[address].raw):
                    _fail("retain CFG bypasses dispatcher into a protected body")
    return {
        "verified": True,
        "selected_retain_route_verified": True,
        "closing_guard_verified": True,
        "reference_limit_guard_verified": True,
        "increment_store_verified": True,
        "status_route_verified": True,
        "lock_pair_route_verified": True,
        "full_retain_effect_verified": False,
        "platform_lock_effect_verified": False,
        "publication_source_verified": False,
        "invoke_body_verified": False,
        "callback_effect_verified": False,
        "transitive_binding_closed": False,
        "scope": "selected-retain-local-increment-win64-v1",
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
