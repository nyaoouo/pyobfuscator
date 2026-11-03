"""Prove the selected Win64 invoke route in exact COFF and linked PE bytes.

The witness ends at the two direct callee entries and the indirect callback
call site. It deliberately makes no claim about effects inside those callees.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_binding_status_effects import (
    _at, _boundaries, _choice, _exact, _plain_transition,
)
from cff_builder_bound_call import INVOKE
from cff_builder_original_predicates import _states
from cff_builder_retain_local import _control_graph
from cff_builder_local_callees import _check_plain_unwind
from cff_joint_machine_evidence import DIRECT, Instruction, _instructions
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import parse_image, read_rva


ADMIT = "_ZN12pyobfuscator6native6detail18admit_context_callEPNS1_21BootstrapContextStateE"
COMPLETE = "_ZN12pyobfuscator6native6detail21complete_context_callEPNS1_21BootstrapContextStateE"
SALT = 0x0d79e103


def _fail(reason):
    raise ValueError(f"invoke local route: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate raw report key")
        result[key] = value
    return result


def _recipe(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _fail("nonfinite report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invoke local route: invalid raw compiler report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw compiler report lacks bounded function rows")
    selected = [row for row in rows if type(row) is dict and row.get("function") == INVOKE]
    if (len(selected) != 1 or selected[0].get("selected") is not True or
            selected[0].get("status") != "transformed" or
            selected[0].get("strategy") != "relative-tree" or
            selected[0].get("coverage_kind") != "decision-flow"):
        _fail("raw report lacks one transformed invoke owner")
    row = selected[0]
    recipe = row.get("effective_recipe")
    roles = row.get("site_totals")
    roles = roles.get("body_roles") if type(roles) is dict else None
    count = roles.get("real") if type(roles) is dict else None
    if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
            recipe.get("strategy") != "relative-tree" or type(count) is not int or
            count not in (8, 10)):
        _fail("unsupported invoke recipe or real-body count")
    return recipe, count


def _subject(object_bytes, image_bytes, image, name, tag):
    try:
        subject = function_subject(object_bytes, image_bytes, image, tag, name)
    except ValueError as error:
        _fail(f"{name} COFF/PE contribution: {error}")
    if subject.kind != "function-contribution" or len(subject.ranges) != 1:
        _fail(f"{name} has an unsupported contribution extent")
    return subject.ranges[0]


def _calls(object_bytes, image_bytes, image, owner, callees, items):
    obj = parse_object(object_bytes)
    roots = {name: [symbol for symbol in obj.symbols if symbol.name == name and
                    symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
             for name in (INVOKE, ADMIT, COMPLETE)}
    if any(len(found) != 1 for found in roots.values()):
        _fail("invoke and callees need unique COFF roots")
    section = obj.sections[roots[INVOKE][0].section - 1]
    if section.size != owner.size or len(section.relocations) != 2:
        _fail("invoke COFF relocation inventory differs from selected route")
    names = {symbol.index: symbol.name for symbol in obj.symbols}
    seen = {}
    obj_code = bytearray(object_bytes[section.offset:section.offset + section.size])
    pe_code = bytearray(read_rva(image_bytes, image, owner.rva, owner.size))
    for rel in section.relocations:
        name = names.get(rel.target)
        if (name not in (ADMIT, COMPLETE) or name in seen or rel.kind != 4 or
                rel.offset < 1 or rel.offset + 4 > section.size or
                rel.target != roots[name][0].index or
                struct.unpack_from("<i", obj_code, rel.offset)[0] != 0):
            _fail("invoke has an unsupported exact REL32 call root")
        address = image.preferred_base + owner.rva + rel.offset - 1
        matching = [item for item in items if item.address == address]
        if (len(matching) != 1 or matching[0].opcode not in ("call", "callq") or
                matching[0].raw[:1] != b"\xe8" or len(matching[0].raw) != 5):
            _fail("invoke relocation does not belong to a direct call")
        item = matching[0]
        display = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
        target = image.preferred_base + callees[name].rva
        if (display is None or int(display[1], 16) != target or
                item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target):
            _fail("invoke direct call differs from exact PE callee")
        seen[name] = item.address
        obj_code[rel.offset:rel.offset + 4] = b"\0" * 4
        pe_code[rel.offset:rel.offset + 4] = b"\0" * 4
    if set(seen) != {ADMIT, COMPLETE} or obj_code != pe_code:
        _fail("invoke COFF/PE nonrelocated bytes or callees differ")
    all_calls = [item.address for item in items if item.opcode in ("call", "callq")]
    if len(all_calls) != 3 or set(all_calls) != {*seen.values(),
                                               next((item.address for item in items
                                                     if item.raw == b"\xff\xd0"), -1)}:
        _fail("invoke has an unmodeled direct or indirect call")
    return seen


def _plain(items, index, root, current, following, slot, *, fallthrough=False):
    checked = items
    if fallthrough:
        root_index = _at(items, root)
        if (items[root_index - 1].opcode != "movl" or
                items[root_index - 1].operands != ("%eax", slot) or
                items[root_index - 1].address + len(items[root_index - 1].raw) != root):
            _fail("last invoke body does not fall into dispatcher")
        checked = items[:root_index] + [Instruction(root, b"\xeb\x00", "jmp",
                                                    (f"{root:#x}",))]
    if _plain_transition(checked, index, slot, root, current, SALT) != following:
        _fail("invoke unconditional body reaches another state")
    return index + 18 - int(fallthrough)


def _choice_route(items, index, root, current, arms, slot, opcode, operands,
                  *, selector=None, fallthrough=False):
    compare = items[index + 3]
    if _choice(items, compare.address, root, slot, current, SALT, opcode,
               operands, selector=selector) != arms:
        _fail("invoke guard reaches another state pair")
    return index + 22 - int(fallthrough)


def _closed_inventory(items, body, ends, root):
    ordered = sorted((items[body[role]].address, body[role], ends[role])
                     for role in range(len(body)))
    following = [entry[0] for entry in ordered[1:]] + [root]
    for (address, start, end), successor in zip(ordered, following):
        if (end <= start or end >= len(items) or items[end].address != successor):
            _fail(f"invoke body at {address:#x} has an unmodeled instruction gap")


def _body_o2(items, body, states, root, calls):
    b = [_at(items, body[state]) for state in states]
    slot = "0x54(%rsp)"
    ends = {}
    i = _exact(items, b[0], [
        ("movq", ("0x30(%rsp)", "%rax")), ("movq", ("(%rax)", "%rax")),
        ("movq", ("%rax", "0x48(%rsp)")),
        ("movq", ("0x48(%rsp)", "%r8"))], "captured context source")
    ends[0] = _choice_route(items, i, root, states[0], (states[2], states[1]),
                            slot, "cmpq", ("$0x0", "%r8"), selector="cmovel")
    i = _exact(items, b[1], [
        ("movq", ("0x38(%rsp)", "%rax")),
        ("movq", ("0x30(%rsp)", "%rcx")),
        ("movl", ("0x8(%rcx)", "%ecx")),
        ("movl", ("%ecx", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "null context result")
    ends[1] = _plain(items, i, root, states[1], states[7], slot)
    i = _exact(items, b[2], [
        ("movq", ("0x28(%rsp)", "%rax")),
        ("movq", ("0x8(%rax)", "%rdx")),
        ("movq", ("0x10(%rax)", "%rcx")),
        ("testq", ("%rcx", "%rcx")), ("setne", ("%al",)),
        ("testq", ("%rdx", "%rdx")), ("sete", ("%dl",)),
        ("andb", ("%dl", "%al")),
        ("cmpq", ("$0x10000", "%rcx")), ("seta", ("%r8b",)),
        ("orb", ("%al", "%r8b"))], "complete request guard")
    ends[2] = _choice_route(items, i, root, states[2], (states[4], states[3]),
                            slot, "testb", ("$0x1", "%r8b"))
    i = _exact(items, b[3], [
        ("movq", ("0x38(%rsp)", "%rax")),
        ("movl", ("$0x3", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "invalid request result")
    ends[3] = _plain(items, i, root, states[3], states[7], slot)
    i = _exact(items, b[4], [
        ("movq", ("0x48(%rsp)", "%rcx")), ("callq", None),
        ("movl", ("%eax", "0x50(%rsp)")),
        ("movl", ("0x50(%rsp)", "%r8d"))], "admit call and status")
    if items[i - 3].address != calls[ADMIT]:
        _fail("admit call is not in the status guard body")
    ends[4] = _choice_route(items, i, root, states[4], (states[5], states[6]),
                            slot, "cmpl", ("$0x0", "%r8d"), selector="cmovel",
                            fallthrough=True)
    i = _exact(items, b[5], [
        ("movq", ("0x38(%rsp)", "%rax")),
        ("movl", ("0x50(%rsp)", "%ecx")), ("movl", ("%ecx", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "admit status result")
    ends[5] = _plain(items, i, root, states[5], states[7], slot)
    i = _exact(items, b[6], [
        ("movq", ("0x28(%rsp)", "%rdx")),
        ("movq", ("0x38(%rsp)", "%rcx")),
        ("movq", ("0x48(%rsp)", "%rax")),
        ("movq", ("0x8(%rax)", "%rax")),
        ("movq", ("0x48(%rsp)", "%r8")),
        ("movq", ("0x10(%r8)", "%r8")),
        ("callq", ("*%rax",)),
        ("movq", ("0x48(%rsp)", "%rcx")),
        ("callq", None)], "callback and complete route")
    if items[i - 3].raw != b"\xff\xd0" or items[i - 1].address != calls[COMPLETE]:
        _fail("callback or complete call is not exact")
    ends[6] = _plain(items, i, root, states[6], states[7], slot)
    i = _exact(items, b[7], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("addq", ("$0x58", "%rsp")), ("retq", ())], "result return")
    ends[7] = i
    _closed_inventory(items, b, ends, root)
    return set(body.values()), "0x24(%rsp)"


def _body_none(items, body, states, root, calls):
    b = [_at(items, body[state]) for state in states]
    slot = "0x84(%rsp)"
    ends = {}
    i = _exact(items, b[0], [
        ("movq", ("0x30(%rsp)", "%rax")),
        ("movq", ("0x38(%rsp)", "%rcx")),
        ("movq", ("0x40(%rsp)", "%rdx")),
        ("movq", ("%rdx", "0x50(%rsp)")),
        ("movq", ("%rcx", "0x58(%rsp)")),
        ("movq", ("%rax", "0x60(%rsp)")),
        ("movq", ("0x58(%rsp)", "%rax")),
        ("movq", ("%rax", "0x78(%rsp)")),
        ("movq", ("0x78(%rsp)", "%rax")),
        ("movq", ("(%rax)", "%rax")),
        ("movq", ("%rax", "0x68(%rsp)")),
        ("movq", ("0x68(%rsp)", "%r8"))], "captured context source")
    ends[0] = _choice_route(items, i, root, states[0], (states[2], states[1]),
                            slot, "cmpq", ("$0x0", "%r8"), selector="cmovel")
    i = _exact(items, b[1], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movq", ("0x78(%rsp)", "%rcx")),
        ("movl", ("0x8(%rcx)", "%ecx")),
        ("movl", ("%ecx", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "null context result")
    ends[1] = _plain(items, i, root, states[1], states[9], slot)
    i = _exact(items, b[2], [
        ("movq", ("0x60(%rsp)", "%rax")),
        ("movq", ("0x10(%rax)", "%r8"))], "request size nonzero")
    ends[2] = _choice_route(items, i, root, states[2], (states[4], states[3]),
                            slot, "cmpq", ("$0x0", "%r8"), selector="cmovnel")
    i = _exact(items, b[3], [
        ("movq", ("0x60(%rsp)", "%rax")),
        ("movq", ("0x8(%rax)", "%r8"))], "request input pointer")
    ends[3] = _choice_route(items, i, root, states[3], (states[4], states[5]),
                            slot, "cmpq", ("$0x0", "%r8"), selector="cmovel")
    i = _exact(items, b[4], [
        ("movq", ("0x60(%rsp)", "%rax")),
        ("movq", ("0x10(%rax)", "%r8"))], "request input size maximum")
    ends[4] = _choice_route(items, i, root, states[4], (states[6], states[5]),
                            slot, "cmpq", ("$0x10000", "%r8"), selector="cmoval")
    i = _exact(items, b[5], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movl", ("$0x3", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "invalid request result")
    ends[5] = _plain(items, i, root, states[5], states[9], slot)
    i = _exact(items, b[6], [
        ("movq", ("0x68(%rsp)", "%rcx")), ("callq", None),
        ("movl", ("%eax", "0x74(%rsp)")),
        ("movl", ("0x74(%rsp)", "%r8d"))], "admit call and status")
    if items[i - 3].address != calls[ADMIT]:
        _fail("admit call is not in the status guard body")
    ends[6] = _choice_route(items, i, root, states[6], (states[8], states[7]),
                            slot, "cmpl", ("$0x0", "%r8d"), selector="cmovnel")
    i = _exact(items, b[7], [
        ("movq", ("0x40(%rsp)", "%rax")),
        ("movl", ("0x74(%rsp)", "%ecx")),
        ("movl", ("%ecx", "(%rax)")),
        ("movq", ("$0x0", "0x8(%rax)"))], "admit status result")
    ends[7] = _plain(items, i, root, states[7], states[9], slot)
    i = _exact(items, b[8], [
        ("movq", ("0x40(%rsp)", "%rcx")),
        ("movq", ("0x68(%rsp)", "%rax")),
        ("movq", ("0x8(%rax)", "%rax")),
        ("movq", ("0x60(%rsp)", "%rdx")),
        ("movq", ("0x68(%rsp)", "%r8")),
        ("movq", ("0x10(%r8)", "%r8")),
        ("callq", ("*%rax",)),
        ("movq", ("0x68(%rsp)", "%rcx")),
        ("callq", None)], "callback and complete route")
    if items[i - 3].raw != b"\xff\xd0" or items[i - 1].address != calls[COMPLETE]:
        _fail("callback or complete call is not exact")
    ends[8] = _plain(items, i, root, states[8], states[9], slot,
                     fallthrough=True)
    i = _exact(items, b[9], [
        ("movq", ("0x48(%rsp)", "%rax")),
        ("addq", ("$0x88", "%rsp")), ("retq", ())], "result return")
    ends[9] = i
    _closed_inventory(items, b, ends, root)
    return set(body.values()), "0x2c(%rsp)"


def _dispatcher_exact(items, root, starts, copy_slot, state_slot):
    tree = items[_at(items, root):]
    if (len(tree) < 5 or tree[0].opcode != "movl" or
            tree[0].operands != (state_slot, "%eax") or
            tree[1].opcode != "movl" or
            tree[1].operands != ("%eax", copy_slot)):
        _fail("invoke dispatcher does not copy encoded state")
    for item in tree[2:]:
        if item.opcode == "movl":
            if item.operands != (copy_slot, "%eax"):
                _fail("invoke dispatcher has another state read or stack write")
        elif item.opcode == "cmpl":
            if (len(item.operands) != 2 or item.operands[1] != "%eax" or
                    not item.operands[0].startswith("$") or
                    not item.raw.startswith(b"\x3d") or len(item.raw) != 5):
                _fail("invoke dispatcher compares an unmodeled value")
        elif item.opcode == "jae":
            target = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
            if target is None or not root <= int(target[1], 16) <= items[-1].address:
                _fail("invoke dispatcher branch leaves its decision tree")
        elif item.opcode in ("jmp", "jmpq"):
            target = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
            if target is None or int(target[1], 16) not in starts:
                _fail("invoke dispatcher enters a body interior")
        else:
            _fail("invoke dispatcher has an unmodeled side effect")


def verify_builder_invoke_local(object_bytes: bytes, image_bytes: bytes,
                                report_bytes: bytes, codes: dict) -> dict:
    """Prove this selected route only, without called-body or runtime effects."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(codes) is not dict or set(codes) != {INVOKE} or
            type(codes[INVOKE]) is not str or not codes[INVOKE]):
        _fail("exact object, image and invoke disassembly are required")
    recipe, count = _recipe(report_bytes)
    image = parse_image(image_bytes)
    owner = _subject(object_bytes, image_bytes, image, INVOKE, 0xbe00)
    callees = {name: _subject(object_bytes, image_bytes, image, name, 0xbe01 + index)
               for index, name in enumerate((ADMIT, COMPLETE))}
    try:
        items = _instructions(codes[INVOKE], image_bytes, INVOKE.lower())
    except ValueError as error:
        _fail(f"invoke disassembly: {error}")
    if (not items or items[0].address != image.preferred_base + owner.rva or
            items[-1].address + len(items[-1].raw) !=
            image.preferred_base + owner.rva + owner.size):
        _fail("invoke disassembly misses exact COFF/PE contribution")
    frame, slot = ((0x88, "0x84(%rsp)") if count == 10 else
                   (0x58, "0x54(%rsp)"))
    if items[0].opcode != "subq" or items[0].operands != (f"${frame:#x}", "%rsp"):
        _fail("invoke has another Win64 frame")
    try:
        _check_plain_unwind(image_bytes, image, owner, items[0], frame)
    except ValueError as error:
        _fail(f"Win64 frame/unwind: {error}")
    states = _states(INVOKE, recipe)[:count]
    entry = [("movq", ("%r8", "0x30(%rsp)" if count == 10 else "0x28(%rsp)")),
             ("movq", ("%rdx", "0x38(%rsp)" if count == 10 else "0x30(%rsp)")),
             ("movq", ("%rcx", "0x40(%rsp)" if count == 10 else "0x38(%rsp)")),
             ("movq", ("%rcx", "0x48(%rsp)" if count == 10 else "0x40(%rsp)"))]
    _exact(items, 1, entry, "Win64 hidden result, lease and request arguments")
    state = items[5]
    prefix = (b"\xc7\x84\x24\x84\x00\x00\x00" if count == 10 else
              b"\xc7\x44\x24\x54")
    if (state.opcode != "movl" or state.operands != (f"${states[0]:#x}", slot) or
            state.raw != prefix + struct.pack("<I", states[0])):
        _fail("invoke entry state differs from frozen recipe")
    jump = items[6]
    target = DIRECT.fullmatch(jump.operands[0]) if len(jump.operands) == 1 else None
    if jump.opcode not in ("jmp", "jmpq") or target is None:
        _fail("invoke entry does not jump to dispatcher")
    root = int(target[1], 16)
    body = _boundaries(items, root, states, slot)
    if min(body.values()) != items[7].address:
        _fail("invoke entry has an unmodeled gap before bodies")
    graph, edges, graph_calls = _control_graph(items)
    if len(graph_calls) != 3 or root not in graph:
        _fail("invoke CFG has an unsupported call inventory")
    calls = _calls(object_bytes, image_bytes, image, owner, callees, items)
    if count == 10:
        starts, copy_slot = _body_none(items, body, states, root, calls)
    else:
        starts, copy_slot = _body_o2(items, body, states, root, calls)
    _dispatcher_exact(items, root, starts, copy_slot, slot)
    for address, successors in edges.items():
        if address < root and address not in starts:
            for successor in successors:
                if successor in starts and successor != address + len(graph[address].raw):
                    _fail("invoke CFG bypasses dispatcher into protected body")
    return {
        "verified": True,
        "request_guard_route_verified": True,
        "admit_status_route_verified": True,
        "callback_argument_route_verified": True,
        "callback_call_route_verified": True,
        "complete_call_route_verified": True,
        "result_return_route_verified": True,
        "admit_effect_verified": False,
        "complete_effect_verified": False,
        "callback_identity_verified": False,
        "callback_effect_verified": False,
        "platform_lock_effect_verified": False,
        "runtime_memory_integrity_verified": False,
        "transitive_binding_closed": False,
        "scope": "selected-invoke-local-route-win64-v1",
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
