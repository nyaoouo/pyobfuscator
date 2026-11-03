"""Bounded COFF/PE proof for the context availability closing decision.

This accepts the two observed CLANG64 lowerings. The lock and unlock bodies
are bound to exact contributions, but their atomic effects are not inferred.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_binding_status_effects import (
    _at, _boundaries, _entry, _exact, _imm, _plain_transition,
    _single_call_and_return, _stack_layout,
)
from cff_builder_local_callees import _check_plain_unwind
from cff_builder_original_predicates import _states
from cff_joint_machine_evidence import DIRECT, _instructions
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import parse_image


CONTEXT_EFFECT_CALLEES = (
    "_ZN12pyobfuscator6native6detail20context_availabilityEPNS1_21BootstrapContextStateE",
    "_ZN12pyobfuscator6native6detail12context_lockERNSt3__16atomicIjEE",
    "_ZN12pyobfuscator6native6detail14context_unlockERNSt3__16atomicIjEE",
)
AVAILABILITY, LOCK, UNLOCK = CONTEXT_EFFECT_CALLEES


def _fail(reason):
    raise ValueError(f"context availability: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate compiler report key")
        result[key] = value
    return result


def _recipe(report_bytes):
    if type(report_bytes) is not bytes or not 0 < len(report_bytes) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        report = json.loads(report_bytes.decode("utf-8"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _fail("nonfinite compiler report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("context availability: invalid raw compiler report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw compiler report lacks bounded function rows")
    selected = [row for row in rows if type(row) is dict and row.get("function") == AVAILABILITY]
    if (len(selected) != 1 or selected[0].get("selected") is not True or
            selected[0].get("status") != "transformed" or
            selected[0].get("strategy") != "relative-tree" or
            selected[0].get("coverage_kind") != "shape-only"):
        _fail("raw report lacks one transformed context availability function")
    row = selected[0]
    recipe = row.get("effective_recipe")
    roles = row.get("site_totals")
    roles = roles.get("body_roles") if type(roles) is dict else None
    if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
            recipe.get("strategy") != "relative-tree" or
            type(roles) is not dict or roles.get("real") != 1 or
            roles.get("shape") != 2):
        _fail("unsupported context availability CFF recipe")
    return recipe


def _subjects(object_bytes, image_bytes, image):
    spans = {}
    for index, name in enumerate(CONTEXT_EFFECT_CALLEES):
        try:
            subject = function_subject(object_bytes, image_bytes, image,
                                       0xb900 + index, name)
        except ValueError as error:
            _fail(f"{name} COFF/PE contribution: {error}")
        if (subject.kind != "function-contribution" or subject.label != name or
                len(subject.ranges) != 1):
            _fail(f"{name} has an unsupported contribution extent")
        spans[name] = subject.ranges[0]
    ordered = sorted((span.rva, span.rva + span.size) for span in spans.values())
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        _fail("context and lock contributions overlap")
    return spans


def _items(code, image_bytes, image, name, span):
    try:
        items = _instructions(code, image_bytes, name.lower())
    except ValueError as error:
        _fail(f"{name} disassembly: {error}")
    if (not items or items[0].address != image.preferred_base + span.rva or
            items[-1].address + len(items[-1].raw) !=
            image.preferred_base + span.rva + span.size):
        _fail(f"{name} disassembly misses exact contribution")
    return items


def _call_target(object_bytes, image, spans, calls):
    obj = parse_object(object_bytes)
    roots = {}
    for name in CONTEXT_EFFECT_CALLEES:
        found = [symbol for symbol in obj.symbols if symbol.name == name and
                 symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
        if len(found) != 1:
            _fail(f"missing unique COFF function root: {name}")
        roots[name] = found[0]
    section = obj.sections[roots[AVAILABILITY].section - 1]
    if section.size != spans[AVAILABILITY].size:
        _fail("context availability COFF/PE extents differ")
    for item, name in zip(calls, (LOCK, UNLOCK)):
        display = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
        target = image.preferred_base + spans[name].rva
        if (item.opcode not in ("call", "callq") or item.raw[:1] != b"\xe8" or
                len(item.raw) != 5 or display is None or
                display[2] != name.lower() or int(display[1], 16) != target or
                item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target):
            _fail(f"call does not reach exact linked {name} body")
        offset = item.address - image.preferred_base - spans[AVAILABILITY].rva
        overlapping = [rel for rel in section.relocations if
                       rel.offset < offset + 5 and
                       offset < rel.offset + (8 if rel.kind == 1 else 4)]
        if (len(overlapping) != 1 or overlapping[0].offset != offset + 1 or
                overlapping[0].kind != 4 or
                overlapping[0].target != roots[name].index or
                struct.unpack_from("<i", object_bytes, section.offset + offset + 1)[0] != 0):
            _fail(f"{name} call lacks exact root-symbol REL32 relocation")


def _body(items, entry, frame, pointer, state_slot, lock_address, unlock_address):
    index = _at(items, entry)
    if pointer == "0x38(%rsp)":
        index = _exact(items, index, [
            ("movq", (pointer, "%rcx")), ("addq", ("$0x38", "%rcx")),
            ("movq", ("%rcx", "0x28(%rsp)"))], "optimized lock argument")
        gate = "0x28(%rsp)"
    elif pointer == "0x30(%rsp)":
        index = _exact(items, index, [
            ("movq", (pointer, "%rax")), ("movq", ("%rax", "0x38(%rsp)")),
            ("movq", ("0x38(%rsp)", "%rcx")),
            ("addq", ("$0x38", "%rcx"))], "source-none lock argument")
        gate = None
    else:
        _fail("unsupported context pointer spill")
    lock_item = items[index]
    index += 1
    if pointer == "0x38(%rsp)":
        index = _exact(items, index, [
            ("movq", (pointer, "%rax")), ("movq", (gate, "%rcx")),
            ("movb", ("0x44(%rax)", "%r8b")),
            ("xorl", ("%eax", "%eax")), ("movl", ("$0x8", "%edx")),
            ("testb", ("$0x1", "%r8b")), ("cmovnel", ("%edx", "%eax")),
            ("movl", ("%eax", "0x34(%rsp)"))], "optimized closing status")
        if (items[index - 3].raw != b"\x41\xf6\xc0\x01" or
                items[index - 4].raw != b"\xba\x08\x00\x00\x00"):
            _fail("optimized closing mask or closed status encoding differs")
        result_slot = "0x34(%rsp)"
    else:
        index = _exact(items, index, [
            ("movq", ("0x38(%rsp)", "%rax")),
            ("movb", ("0x44(%rax)", "%dl")),
            ("xorl", ("%eax", "%eax")), ("movl", ("$0x8", "%ecx")),
            ("testb", ("$0x1", "%dl")), ("cmovnel", ("%ecx", "%eax")),
            ("movl", ("%eax", "0x40(%rsp)")),
            ("movq", ("0x38(%rsp)", "%rcx")),
            ("addq", ("$0x38", "%rcx"))], "source-none closing status")
        if (items[index - 5].raw != b"\xf6\xc2\x01" or
                items[index - 6].raw != b"\xb9\x08\x00\x00\x00"):
            _fail("source-none closing mask or closed status encoding differs")
        result_slot = "0x40(%rsp)"
    unlock_item = items[index]
    _exact(items, index + 1, [
        ("movl", (result_slot, "%eax")),
        ("addq", (f"${frame:#x}", "%rsp")), ("retq", ())],
        "context availability return")
    if state_slot in (pointer, result_slot, gate) or result_slot == pointer:
        _fail("context state, input and return slots overlap")
    if (lock_item.address >= unlock_item.address or
            lock_item.address + len(lock_item.raw) >= unlock_item.address):
        _fail("lock/unlock call order is unsupported")
    if (lock_item.address != lock_address or unlock_item.address != unlock_address):
        _fail("lock/unlock call sites differ from body route")


def verify_builder_context_availability(object_bytes: bytes, image_bytes: bytes,
                                        report_bytes: bytes, codes: dict) -> dict:
    """Prove the local closing status and lock/unlock call route only."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(codes) is not dict or set(codes) != set(CONTEXT_EFFECT_CALLEES) or
            any(type(code) is not str or not code for code in codes.values())):
        _fail("exact object, image and three linked disassemblies are required")
    recipe = _recipe(report_bytes)
    try:
        image = parse_image(image_bytes)
    except ValueError as error:
        _fail(f"invalid PE image: {error}")
    spans = _subjects(object_bytes, image_bytes, image)
    items = {name: _items(codes[name], image_bytes, image, name, spans[name])
             for name in CONTEXT_EFFECT_CALLEES}
    body = items[AVAILABILITY]
    _single_call_and_return(body, 2)
    if body[0].opcode != "subq" or len(body[0].operands) != 2 or \
            body[0].operands[1] != "%rsp":
        _fail("context availability lacks a plain Win64 frame")
    frame = int(body[0].operands[0][1:], 0)
    if frame != 0x48:
        _fail("unsupported context availability frame size")
    try:
        _check_plain_unwind(image_bytes, image, spans[AVAILABILITY], body[0], frame)
    except ValueError as error:
        _fail(f"context frame/unwind: {error}")
    _stack_layout(body, frame)
    states = _states(AVAILABILITY, recipe)
    (pointer,), state_slot, dispatcher = _entry(body, states[0], ("%rcx",))
    routes = _boundaries(body, dispatcher, states[:3], state_slot)
    first, second, decision = (routes[state] for state in states[:3])
    if not decision < first < second < dispatcher:
        _fail("context availability bodies have an unsupported physical order")
    if (body[_at(body, first) - 1].opcode != "retq" or
            body[_at(body, first) - 1].address +
            len(body[_at(body, first) - 1].raw) != first or
            body[_at(body, second) - 1].opcode not in ("jmp", "jmpq") or
            body[_at(body, second) - 1].address +
            len(body[_at(body, second) - 1].raw) != second):
        _fail("context availability body and mixers contain an unmodeled gap")
    first_index = _at(body, first)
    salt = _imm(body[first_index + 2], b"\x81\xf1")
    # The final mixer is physically adjacent to the dispatcher. Supply only
    # a synthetic branch boundary after proving its actual fallthrough.
    from cff_joint_machine_evidence import Instruction

    second_index = _at(body, second)
    root_index = _at(body, dispatcher)
    if second_index >= root_index or body[root_index - 1].opcode != "movl" or \
            body[root_index - 1].operands != ("%eax", state_slot) or \
            body[root_index - 1].address + len(body[root_index - 1].raw) != dispatcher:
        _fail("final CFF mixer does not fall into its dispatcher")
    shadow = body[:root_index] + [Instruction(dispatcher, b"\xeb\x00", "jmp",
                                             (f"{dispatcher:#x}",))]
    if (_plain_transition(body, first_index, state_slot, dispatcher, states[0], salt) !=
            states[1] or
            _plain_transition(shadow, second_index, state_slot, dispatcher,
                              states[1], salt) != states[2]):
        _fail("context availability CFF transition misses its decision body")
    calls = [item for item in body if item.opcode in ("call", "callq")]
    _body(body, decision, frame, pointer, state_slot,
          calls[0].address, calls[1].address)
    _call_target(object_bytes, image, spans, calls)
    return {
        "verified": True, "context_availability_body_verified": True,
        "closing_field_route_verified": True, "lock_pair_route_verified": True,
        "platform_lock_effect_verified": False, "transitive_binding_closed": False,
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
