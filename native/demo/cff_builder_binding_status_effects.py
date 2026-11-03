"""Bounded machine proof for the mixed POST binding-status return decision.

The accepted lowering is the Windows x64 relative-tree profile. Each selected
COFF contribution is matched to its relocated PE bytes; the disassembly is
then checked against its unwind extent and the state route. This does not
establish whole-callgraph binding or integrity of arbitrary runtime memory.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_local_callees import (BINDING_STATUS, REQUIRE_BINDING,
                                       _check_plain_unwind)
from cff_builder_original_predicates import (_dispatcher_destination, _mix,
                                             _states, _transition)
from cff_joint_machine_evidence import DIRECT, _instructions
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image


EFFECT_CALLEES = (
    "_ZN12pyobfuscator6native6detail22BootstrapContextAccess5stateERKNS0_21BootstrapContextLeaseE",
    "_ZNK12pyobfuscator6native21BootstrapContextLease10generationEv",
    "_ZNK12pyobfuscator6native21BootstrapContextLease12availabilityEv",
)
STATE, GENERATION, AVAILABILITY = EFFECT_CALLEES
CONTEXT_AVAILABILITY = (
    "_ZN12pyobfuscator6native6detail20context_availabilityEPNS1_21BootstrapContextStateE")
MASK32 = 0xffffffff
STACK_SLOT = re.compile(r"(0x[0-9a-f]+)?\(%rsp\)\Z")


def _fail(reason):
    raise ValueError(f"binding-status effects: {reason}")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("duplicate raw report key")
        result[key] = value
    return result


def _report(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: _fail("nonfinite raw report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("binding-status effects: invalid raw compiler report") from error
    rows = document.get("functions") if type(document) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw compiler report lacks bounded function rows")
    recipes = {}
    counts = {}
    for name in (BINDING_STATUS, *EFFECT_CALLEES):
        selected = [row for row in rows if type(row) is dict and row.get("function") == name]
        expected_kind = "shape-only" if name == STATE else "decision-flow"
        if (len(selected) != 1 or selected[0].get("selected") is not True or
                selected[0].get("status") != "transformed" or
                selected[0].get("strategy") != "relative-tree" or
                selected[0].get("coverage_kind") != expected_kind):
            _fail(f"raw report lacks one transformed function: {name}")
        recipe = selected[0].get("effective_recipe")
        if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
                recipe.get("strategy") != "relative-tree"):
            _fail(f"unsupported frozen function recipe: {name}")
        totals = selected[0].get("site_totals")
        roles = totals.get("body_roles") if type(totals) is dict else None
        real = roles.get("real") if type(roles) is dict else None
        if (type(real) is not int or real not in {
                BINDING_STATUS: (7, 13), STATE: (1,),
                GENERATION: (3, 4), AVAILABILITY: (4,)}[name] or
                (name == STATE and roles.get("shape") != 2)):
            _fail(f"unsupported real-body role count: {name}")
        recipes[name] = recipe
        counts[name] = real
    recipes["_real_counts"] = counts
    return recipes


def _subject(object_bytes, image_bytes, image, name, tag):
    try:
        subject = function_subject(object_bytes, image_bytes, image, tag, name)
    except ValueError as error:
        _fail(f"{name} COFF/PE contribution: {error}")
    if (subject.kind != "function-contribution" or subject.label != name or
            len(subject.ranges) != 1):
        _fail(f"{name} has an unsupported contribution extent")
    return subject.ranges[0]


def _items(code, image_bytes, name, span, base):
    try:
        items = _instructions(code, image_bytes, name.lower())
    except ValueError as error:
        _fail(f"{name} disassembly: {error}")
    if not items or items[0].address != base + span.rva or \
            items[-1].address + len(items[-1].raw) != base + span.rva + span.size:
        _fail(f"{name} disassembly misses exact function contribution")
    return items


def _at(items, address):
    matches = [i for i, item in enumerate(items) if item.address == address]
    if len(matches) != 1:
        _fail("state route misses an instruction boundary")
    return matches[0]


def _exact(items, index, expected, label):
    if len(items) < index + len(expected):
        _fail(f"{label} is truncated")
    for item, (opcode, operands) in zip(items[index:], expected):
        if item.opcode != opcode or (operands is not None and
                                    (len(item.operands) != len(operands) or
                                     any(want is not None and got != want
                                         for got, want in zip(item.operands, operands)))):
            _fail(f"{label} has an unsupported machine operation")
    return index + len(expected)


def _slot(item, register, width="q"):
    if item.opcode != "mov" + width or len(item.operands) != 2 or \
            item.operands[0] != register or not item.operands[1].endswith("(%rsp)"):
        _fail(f"{register} lacks its fixed Win64 argument spill")
    return item.operands[1]


def _stack_layout(items, frame):
    """Reject unmodeled stack aliases throughout each exact function subject."""
    intervals = set()
    has_call = any(item.opcode in ("call", "callq") for item in items)
    for item in items:
        stack = [operand for operand in item.operands if "%rsp" in operand]
        if not stack:
            continue
        if (item.opcode in ("subq", "addq") and len(item.operands) == 2 and
                stack == ["%rsp"] and item.operands[1] == "%rsp"):
            continue
        if item.opcode not in ("movl", "movq") or len(stack) != 1 or \
                len(item.operands) != 2:
            _fail("stack access has an unsupported alias or width")
        match = STACK_SLOT.fullmatch(stack[0])
        if match is None:
            _fail("stack access has an unsupported addressing mode")
        start = int(match[1] or "0", 16)
        end = start + (8 if item.opcode == "movq" else 4)
        if end > frame:
            _fail("stack access exceeds the verified Win64 frame")
        if has_call and start < 0x20:
            # The callee owns the first 32 bytes at the caller's current rsp.
            _fail("stack value enters Win64 outgoing call shadow space")
        intervals.add((start, end))
    ordered = sorted(intervals)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        _fail("stack value intervals overlap in the verified function")


def _call(items, index, name, address):
    item = items[index]
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    if item.opcode not in ("call", "callq") or match is None or \
            match[2] != name.lower() or int(match[1], 16) != address:
        _fail(f"call does not reach the exact linked {name} body")
    return index + 1


def _relocated_calls(object_bytes, image_bytes, image, spans, items):
    """Bind call opcodes to direct root-symbol REL32 fixups and PE targets."""
    obj = parse_object(object_bytes)
    linked = Resolver(obj, image, image_symbols(image_bytes, image))
    expected = {**{name: image.preferred_base + spans[name].rva for name in EFFECT_CALLEES},
                CONTEXT_AVAILABILITY: image.preferred_base + linked.named(CONTEXT_AVAILABILITY)}
    roots = {}
    for name in expected:
        matches = [symbol for symbol in obj.symbols if symbol.name == name and
                   symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
        if len(matches) != 1:
            _fail(f"call target has no unique COFF function root: {name}")
        roots[name] = matches[0]
    for caller in (BINDING_STATUS, AVAILABILITY):
        source = roots[caller] if caller == AVAILABILITY else next(
            (symbol for symbol in obj.symbols if symbol.name == caller and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0), None)
        if source is None:
            _fail("binding status has no unique COFF caller root")
        section = obj.sections[source.section - 1]
        span = spans[caller]
        if section.size != span.size:
            _fail("caller's exact COFF and PE contribution extents differ")
        targets = set(EFFECT_CALLEES) if caller == BINDING_STATUS else {CONTEXT_AVAILABILITY}
        for item in items[caller]:
            if item.opcode not in ("call", "callq"):
                continue
            display = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
            if item.raw[:1] != b"\xe8" or len(item.raw) != 5 or display is None:
                _fail("call has an unsupported direct E8 encoding")
            named = [name for name in targets if name.lower() == display[2]]
            if len(named) != 1:
                _fail("call's displayed target is outside its closed symbol set")
            name = named[0]
            numeric = item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0]
            if numeric != int(display[1], 16) or numeric != expected[name]:
                _fail("E8 raw displacement misses the exact linked callee")
            relative = item.address - image.preferred_base - span.rva
            overlapping = [rel for rel in section.relocations
                           if rel.offset < relative + 5 and
                           relative < rel.offset + (8 if rel.kind == 1 else 4)]
            if (len(overlapping) != 1 or overlapping[0].offset != relative + 1 or
                    overlapping[0].kind != 4 or overlapping[0].target != roots[name].index or
                    struct.unpack_from("<i", object_bytes,
                                       section.offset + relative + 1)[0] != 0):
                _fail("call lacks its exact root-symbol REL32 relocation and zero addend")


def _branch(items, index, dispatcher):
    if index == len(items) and items[-1].address + len(items[-1].raw) == dispatcher:
        return
    if index >= len(items):
        _fail("body does not return to dispatcher")
    item = items[index]
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    if item.opcode not in ("jmp", "jmpq") or match is None or \
            int(match[1], 16) != dispatcher:
        _fail("body does not return to dispatcher")


def _imm(item, prefix):
    if not item.raw.startswith(prefix) or len(item.raw) != len(prefix) + 4 or \
            not item.operands or not item.operands[0].startswith("$"):
        _fail("state immediate has unsupported encoding")
    value = struct.unpack_from("<I", item.raw, len(prefix))[0]
    if int(item.operands[0][1:], 0) & MASK32 != value:
        _fail("state immediate differs from PE bytes")
    return value


def _plain_transition(items, index, state_slot, dispatcher, current, salt):
    """Validate the unconditional relative-tree mixer and its next state."""
    expected = [
        ("movl", (state_slot, "%eax")), ("movl", ("%eax", "%ecx")),
        ("xorl", None), ("movl", ("%ecx", "%edx")),
        ("shrl", ("$0x10", "%edx")), ("xorl", ("%edx", "%ecx")),
        ("imull", ("$0x7feb352d", "%ecx", "%ecx")),
        ("movl", ("%ecx", "%edx")), ("shrl", ("$0xf", "%edx")),
        ("xorl", ("%edx", "%ecx")),
        ("imull", ("$0x846ca68b", "%ecx", "%ecx")),
        ("movl", ("%ecx", "%edx")), ("shrl", ("$0x10", "%edx")),
        ("xorl", ("%edx", "%ecx")), ("xorl", None),
        ("addl", ("%ecx", "%eax")), ("movl", ("%eax", state_slot)),
    ]
    end = _exact(items, index, expected, "unconditional state mixer")
    if (_imm(items[index + 2], b"\x81\xf1") != salt or
            items[index + 6].raw != b"\x69\xc9\x2d\x35\xeb\x7f" or
            items[index + 10].raw != b"\x69\xc9\x8b\xa6\x6c\x84" or
            items[index + 14].operands[1] != "%ecx"):
        _fail("unconditional state mixer differs from exact PE encoding")
    delta = _imm(items[index + 14], b"\x81\xf1")
    _branch(items, end, dispatcher)
    return (current + (_mix(current ^ salt) ^ delta)) & MASK32


def _choice(items, address, dispatcher, state_slot, current, salt, opcode, operands,
            selector=None):
    index = _at(items, address)
    item = items[index]
    if item.opcode != opcode or item.operands != operands:
        _fail("binding predicate has an unsupported comparison")
    root_index = _at(items, dispatcher)
    checked = items
    if (root_index > index and items[root_index - 1].opcode == "movl" and
            items[root_index - 1].operands == ("%eax", state_slot)):
        # A final body can reach the adjacent dispatcher by fallthrough.
        from cff_joint_machine_evidence import Instruction
        checked = items[:root_index] + [Instruction(
            dispatcher, b"\xeb\x00", "jmp", (f"{dispatcher:#x}",))]
    try:
        false_arm, true_arm, observed_salt, _ = _transition(checked, index,
                                                              dispatcher,
                                                              int(state_slot.split("(")[0], 0))
    except ValueError as error:
        _fail(f"binding predicate transition: {error}")
    if observed_salt != salt:
        _fail("binding predicate uses another transition salt")
    condition = items[index + 1]
    expected_selector = selector or ("cmovnel" if opcode == "testb" else "cmovel")
    if condition.opcode != expected_selector:
        _fail("binding predicate has the wrong conditional selector")
    false_state = (current + (false_arm ^ _mix(current ^ salt))) & MASK32
    true_state = (current + (true_arm ^ _mix(current ^ salt))) & MASK32
    # Both conditional moves retain ecx when the condition is false and
    # choose edx when it is true; the branch condition itself differs.
    return false_state, true_state


def _entry(items, state, args):
    if not items or items[0].opcode != "subq" or len(items[0].operands) != 2 or \
            items[0].operands[1] != "%rsp" or items[0].raw[:3] not in \
            (b"\x48\x83\xec", b"\x48\x81\xec"):
        _fail("binding function has an unsupported Win64 frame")
    frame = int(items[0].operands[0][1:], 0)
    if (frame < 0x18 or frame > 0x200 or
            items[0].raw != (b"\x48\x83\xec" + bytes((frame,)) if frame <= 0x7f
                             else b"\x48\x81\xec" + struct.pack("<I", frame))):
        _fail("Win64 frame allocation differs from exact PE bytes")
    spills = [_slot(items[index + 1], register) for index, register in enumerate(args)]
    if len(set(spills)) != len(spills):
        _fail("Win64 arguments alias one stack spill")
    state_item = items[len(args) + 1]
    if state_item.opcode != "movl" or state_item.operands[0] != f"${state:#x}" or \
            len(state_item.operands) != 2 or not state_item.operands[1].endswith("(%rsp)"):
        _fail("entry state differs from report-derived CFF layout")
    if (state_item.raw[:3] not in (b"\xc7\x44\x24", b"\xc7\x84\x24") or
            _imm(state_item, state_item.raw[:-4]) != state):
        _fail("entry state differs from exact PE immediate")
    jump = items[len(args) + 2]
    match = DIRECT.fullmatch(jump.operands[0]) if len(jump.operands) == 1 else None
    if jump.opcode not in ("jmp", "jmpq") or match is None:
        _fail("entry does not jump to relative-tree dispatcher")
    return spills, state_item.operands[1], int(match[1], 16)


def _destination(items, dispatcher, state, state_slot):
    try:
        return _dispatcher_destination(items, dispatcher, state, int(state_slot.split("(")[0], 0))
    except ValueError as error:
        _fail(f"dispatcher route: {error}")


def _boundaries(items, root, states, state_slot):
    mapping = {state: _destination(items, root, state, state_slot) for state in states}
    if len(set(mapping.values())) != len(states):
        _fail("independent CFF states fold to one body")
    if any(destination >= root or destination <= items[0].address for destination in mapping.values()):
        _fail("CFF state leaves its expected body area")
    return mapping


def _binding(items, states, callee_addresses):
    if len(states) < 7:
        _fail("binding status has too few report-derived states")
    spills, state_slot, dispatcher = _entry(items, states[0], ("%rdx", "%rcx"))
    lease, scope = spills
    _single_call_and_return(items, 6)
    where = _boundaries(items, dispatcher, states[:7], state_slot)
    initial, pointer, parent_gen, lease_gen, parent_av, lease_av, returning = \
        (where[value] for value in states[:7])
    # Derive the single transition salt from an actual conditional mixer.
    pointer_compare = next((item for item in items if item.raw == b"\x41\xf6\xc0\x01" and
                            pointer <= item.address < lease_av), None)
    if pointer_compare is None:
        _fail("state-pointer identity has no combined Boolean test")
    pointer_index = _at(items, pointer_compare.address)
    salt = _imm(items[pointer_index + 3], b"\x81\xf2")
    i = _at(items, initial)
    i = _exact(items, i, [("movq", (scope, "%rax")),
                          ("movl", ("0x220(%rax)", "%r8d"))], "initial status source")
    status_slot = items[i].operands[1]
    if status_slot in (scope, lease, state_slot):
        _fail("status result aliases an argument or dispatcher state")
    i = _exact(items, i, [("movl", ("%r8d", status_slot))], "initial status copy")
    initial_compare = next((item for item in items[i:] if item.opcode == "cmpl" and
                            item.operands == ("$0x0", "%r8d") and
                            initial < item.address < dispatcher), None)
    if initial_compare is None:
        _fail("initial status is not checked against success")
    # The last body falls directly into the dispatcher instead of jumping.
    first = _at(items, initial_compare.address)
    if first - 3 != i:
        _fail("initial status has an unmodeled pre-transition operation")
    if items[first + 1].opcode != "cmovel":
        _fail("initial status zero does not select the continuation")
    _initial_transition = items[first - 3:first + 18]
    if len(_initial_transition) != 21 or \
            _initial_transition[-1].address + len(_initial_transition[-1].raw) != dispatcher:
        _fail("initial status transition does not fall into dispatcher")
    # A temporary one-instruction suffix lets the shared exact mixer parser
    # check the fallthrough body without claiming the suffix is PE code.
    from cff_joint_machine_evidence import Instruction
    synthetic = Instruction(dispatcher, b"\xeb\x00", "jmp", (f"{dispatcher:#x}",))
    shadow = items[:_at(items, dispatcher)] + [synthetic]
    initial_route = _choice(shadow, initial_compare.address, dispatcher, state_slot,
                            states[0], salt, "cmpl", ("$0x0", "%r8d"))
    if initial_route != (states[6], states[1]):
        _fail("initial status does not return on error and continue on success")
    # The pointer pair must be the two exact lease->state calls, preserving
    # each return value through null checks and a cross-register equality.
    i = _at(items, pointer)
    i = _exact(items, i, [("movq", (scope, "%rcx"))], "parent state argument")
    i = _call(items, i, STATE, callee_addresses[STATE])
    i = _exact(items, i, [("movq", (lease, "%rcx")),
                          ("movq", ("%rax", None))], "state-pointer save")
    saved = items[i - 1].operands[1]
    if not saved.endswith("(%rsp)") or saved in (scope, lease, state_slot, status_slot):
        _fail("parent state pointer has no distinct protected spill")
    i = _call(items, i, STATE, callee_addresses[STATE])
    i = _exact(items, i, [
        ("movq", (saved, "%rcx")), ("movq", ("%rax", "%rdx")),
        ("cmpq", ("$0x0", "%rcx")), ("setne", ("%al",)),
        ("cmpq", ("$0x0", "%rdx")), ("setne", ("%r8b",)),
        ("andb", ("%r8b", "%al")), ("cmpq", ("%rdx", "%rcx")),
        ("sete", ("%r8b",)), ("andb", ("%al", "%r8b")),
        ("movl", ("$0xa", status_slot)),
    ], "state-pointer null and identity chain")
    if items[i - 4].raw != b"\x48\x39\xd1":
        _fail("state-pointer equality uses a self-comparison or unmodeled encoding")
    if i != pointer_index - 3:
        _fail("state-pointer comparison has an unmodeled side operation")
    if _choice(items, pointer_compare.address, dispatcher, state_slot,
               states[1], salt, "testb", ("$0x1", "%r8b")) != (states[6], states[2]):
        _fail("state-pointer mismatch does not stop generation checks")
    i = _at(items, parent_gen)
    i = _exact(items, i, [("movq", (scope, "%rcx"))], "parent generation argument")
    i = _call(items, i, GENERATION, callee_addresses[GENERATION])
    generation_slot = items[i].operands[1]
    if generation_slot in (scope, lease, state_slot, status_slot, saved):
        _fail("parent generation aliases another protected value")
    i = _exact(items, i, [("movq", ("%rax", generation_slot)),
                          ("movq", (generation_slot, "%r8")),
                          ("movl", ("$0xa", status_slot))], "parent generation save")
    nonzero = next((item for item in items[i:] if item.opcode == "cmpq" and
                    item.operands == ("$0x0", "%r8") and
                    parent_gen < item.address < returning), None)
    if nonzero is None or _choice(items, nonzero.address, dispatcher, state_slot,
                                states[2], salt, "cmpq", ("$0x0", "%r8")) != \
            (states[3], states[6]):
        _fail("zero parent generation does not stop binding")
    if _at(items, nonzero.address) - 3 != i:
        _fail("parent generation has an unmodeled side operation")
    i = _at(items, lease_gen)
    i = _exact(items, i, [("movq", (lease, "%rcx"))], "lease generation argument")
    i = _call(items, i, GENERATION, callee_addresses[GENERATION])
    i = _exact(items, i, [("movq", ("%rax", "%r9")),
                          ("movq", (generation_slot, "%r8")),
                          ("movl", ("$0xa", status_slot))], "generation comparison sources")
    equal = next((item for item in items[i:] if item.raw == b"\x4d\x39\xc8" and
                  lease_gen < item.address < parent_gen), None)
    if equal is None or _choice(items, equal.address, dispatcher, state_slot,
                              states[3], salt, "cmpq", ("%r9", "%r8")) != \
            (states[6], states[4]):
        _fail("different lease generation does not stop binding")
    if _at(items, equal.address) - 3 != i:
        _fail("generation comparison has an unmodeled side operation")
    i = _at(items, parent_av)
    i = _exact(items, i, [("movq", (scope, "%rcx"))], "parent availability argument")
    i = _call(items, i, AVAILABILITY, callee_addresses[AVAILABILITY])
    i = _exact(items, i, [("movl", ("%eax", "%r8d")),
                          ("movl", ("%r8d", status_slot))], "parent availability result")
    parent_ok = next((item for item in items[i:] if item.opcode == "cmpl" and
                     item.operands == ("$0x0", "%r8d") and
                     parent_av < item.address < initial), None)
    if parent_ok is None or _choice(items, parent_ok.address, dispatcher, state_slot,
                                  states[4], salt, "cmpl", ("$0x0", "%r8d")) != \
            (states[6], states[5]):
        _fail("parent availability error is not preserved")
    if _at(items, parent_ok.address) - 3 != i:
        _fail("parent availability has an unmodeled side operation")
    i = _at(items, lease_av)
    i = _exact(items, i, [("movq", (lease, "%rcx"))], "lease availability argument")
    i = _call(items, i, AVAILABILITY, callee_addresses[AVAILABILITY])
    i = _exact(items, i, [("movl", ("%eax", status_slot))], "lease availability result")
    if _plain_transition(items, i, state_slot, dispatcher, states[5], salt) != states[6]:
        _fail("lease availability does not reach shared return")
    i = _at(items, returning)
    i = _exact(items, i, [("movl", (status_slot, "%eax")),
                          ("addq", (items[0].operands[0], "%rsp")),
                          ("retq", ())], "shared status return")
    if i > len(items):
        _fail("shared return exceeds linked function")
    return {"dispatcher": dispatcher, "states": states[:7], "status_slot": status_slot}


def _none_choice(items, index, root, slot, state, salt, opcode, operands,
                 selector, destinations):
    if len(items) <= index + 3:
        _fail("source-none predicate is truncated")
    compare = items[index + 3]
    actual = _choice(items, compare.address, root, slot, state, salt,
                     opcode, operands, selector)
    if actual != destinations:
        _fail("source-none predicate chooses an incorrect state route")


def _binding_none(items, states, addresses):
    """The unoptimized source-none lowering keeps each guard in its own body."""
    if len(states) < 13:
        _fail("source-none binding requires thirteen independent states")
    _single_call_and_return(items, 7)
    spills, slot, root = _entry(items, states[0], ("%rdx", "%rcx"))
    if (items[0].raw != b"\x48\x81\xec\x88\x00\x00\x00" or
            spills != ["0x38(%rsp)", "0x40(%rsp)"] or slot != "0x84(%rsp)"):
        _fail("source-none binding has an unsupported 0x88 frame profile")
    where = _boundaries(items, root, states[:13], slot)
    b = [where[value] for value in states[:13]]
    if b[0] != items[5].address:
        _fail("source-none entry does not reach the initial status body")
    status = "0x4c(%rsp)"
    scope_holder, lease_holder, subject = "0x50(%rsp)", "0x58(%rsp)", "0x78(%rsp)"
    parent_state, lease_state = "0x60(%rsp)", "0x68(%rsp)"
    parent_availability, selected_availability = "0x70(%rsp)", "0x74(%rsp)"
    i = _at(items, b[0])
    i = _exact(items, i, [
        ("movq", (spills[0], "%rax")), ("movq", (spills[1], "%rcx")),
        ("movq", ("%rcx", scope_holder)), ("movq", ("%rax", lease_holder)),
        ("movq", (scope_holder, "%rax")), ("movq", ("%rax", subject)),
        ("movq", (subject, "%rax")), ("movl", ("0x220(%rax)", "%r8d")),
    ], "source-none initial Scope status")
    salt = _imm(items[i + 6], b"\x81\xf2")
    _none_choice(items, i, root, slot, states[0], salt, "cmpl", ("$0x0", "%r8d"),
                 "cmovnel", (states[2], states[1]))
    i = _at(items, b[1])
    i = _exact(items, i, [("movq", (subject, "%rax")),
                          ("movl", ("0x220(%rax)", "%eax")),
                          ("movl", ("%eax", status))], "source-none initial error result")
    if _plain_transition(items, i, slot, root, states[1], salt) != states[12]:
        _fail("initial error does not reach return")
    i = _at(items, b[2])
    i = _exact(items, i, [("movq", (subject, "%rcx"))], "parent state argument")
    i = _call(items, i, STATE, addresses[STATE])
    i = _exact(items, i, [("movq", ("%rax", parent_state)),
                          ("movq", (lease_holder, "%rcx"))], "parent state result")
    i = _call(items, i, STATE, addresses[STATE])
    i = _exact(items, i, [("movq", ("%rax", lease_state)),
                          ("movq", (parent_state, "%r8"))], "lease state result")
    _none_choice(items, i, root, slot, states[2], salt, "cmpq", ("$0x0", "%r8"),
                 "cmovel", (states[3], states[7]))
    i = _at(items, b[3])
    i = _exact(items, i, [("movq", (lease_state, "%r8"))], "lease state null source")
    _none_choice(items, i, root, slot, states[3], salt, "cmpq", ("$0x0", "%r8"),
                 "cmovel", (states[4], states[7]))
    i = _at(items, b[4])
    i = _exact(items, i, [("movq", (parent_state, "%r8")),
                          ("movq", (lease_state, "%r9"))],
               "cross-lease state pointer sources")
    if items[i + 3].raw != b"\x4d\x39\xc8":
        _fail("source-none state identity uses a self-comparison")
    _none_choice(items, i, root, slot, states[4], salt, "cmpq", ("%r9", "%r8"),
                 "cmovnel", (states[5], states[7]))
    i = _at(items, b[5])
    i = _exact(items, i, [("movq", (subject, "%rcx"))], "parent generation argument")
    i = _call(items, i, GENERATION, addresses[GENERATION])
    i = _exact(items, i, [("movq", ("%rax", "%r8"))], "parent generation result")
    _none_choice(items, i, root, slot, states[5], salt, "cmpq", ("$0x0", "%r8"),
                 "cmovel", (states[6], states[7]))
    i = _at(items, b[6])
    i = _exact(items, i, [("movq", (subject, "%rcx"))], "parent generation comparison")
    i = _call(items, i, GENERATION, addresses[GENERATION])
    i = _exact(items, i, [("movq", ("%rax", "0x30(%rsp)")),
                          ("movq", (lease_holder, "%rcx"))],
               "generation comparison parent save")
    i = _call(items, i, GENERATION, addresses[GENERATION])
    i = _exact(items, i, [("movq", ("0x30(%rsp)", "%r8")),
                          ("movq", ("%rax", "%r9"))],
               "generation comparison lease source")
    if items[i + 3].raw != b"\x4d\x39\xc8":
        _fail("source-none generation equality uses a self-comparison")
    _none_choice(items, i, root, slot, states[6], salt, "cmpq", ("%r9", "%r8"),
                 "cmovnel", (states[8], states[7]))
    i = _at(items, b[7])
    i = _exact(items, i, [("movl", ("$0xa", status))], "binding mismatch status")
    if _plain_transition(items, i, slot, root, states[7], salt) != states[12]:
        _fail("binding mismatch does not reach return")
    i = _at(items, b[8])
    i = _exact(items, i, [("movq", (subject, "%rcx"))],
               "parent availability argument")
    i = _call(items, i, AVAILABILITY, addresses[AVAILABILITY])
    i = _exact(items, i, [("movl", ("%eax", parent_availability)),
                          ("movl", (parent_availability, "%r8d"))],
               "parent availability result")
    _none_choice(items, i, root, slot, states[8], salt, "cmpl", ("$0x0", "%r8d"),
                 "cmovel", (states[10], states[9]))
    i = _at(items, b[9])
    i = _exact(items, i, [("movq", (lease_holder, "%rcx"))],
               "lease availability argument")
    i = _call(items, i, AVAILABILITY, addresses[AVAILABILITY])
    i = _exact(items, i, [("movl", ("%eax", selected_availability))],
               "lease availability result")
    if _plain_transition(items, i, slot, root, states[9], salt) != states[11]:
        _fail("lease availability does not reach selection")
    i = _at(items, b[10])
    i = _exact(items, i, [("movl", (parent_availability, "%eax")),
                          ("movl", ("%eax", selected_availability))],
               "parent availability error selection")
    if _plain_transition(items, i, slot, root, states[10], salt) != states[11]:
        _fail("parent availability error does not reach selection")
    i = _at(items, b[11])
    i = _exact(items, i, [("movl", (selected_availability, "%eax")),
                          ("movl", ("%eax", status))], "selected availability status")
    if _plain_transition(items, i, slot, root, states[11], salt) != states[12]:
        _fail("selected availability does not reach return")
    i = _at(items, b[12])
    _exact(items, i, [("movl", (status, "%eax")),
                      ("addq", ("$0x88", "%rsp")), ("retq", ())],
           "source-none binding status return")


def verify_builder_binding_status_effects(object_bytes: bytes, image_bytes: bytes,
                                          report_bytes: bytes, local_codes: dict,
                                          callee_codes: dict) -> dict:
    """Prove only the linked binding-status pointer, generation and status route."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(local_codes) is not dict or set(local_codes) != {REQUIRE_BINDING, BINDING_STATUS} or
            type(callee_codes) is not dict or set(callee_codes) != set(EFFECT_CALLEES) or
            any(type(value) is not str or not value for value in
                (*local_codes.values(), *callee_codes.values()))):
        _fail("exact object, image and five linked disassemblies are required")
    recipes = _report(report_bytes)
    image = parse_image(image_bytes)
    spans = {name: _subject(object_bytes, image_bytes, image, name, 0xb600 + index)
             for index, name in enumerate((BINDING_STATUS, *EFFECT_CALLEES))}
    intervals = sorted((span.rva, span.rva + span.size, name) for name, span in spans.items())
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        _fail("binding and effect callee contributions overlap")
    codes = {**local_codes, **callee_codes}
    items = {name: _items(codes[name], image_bytes, name, span, image.preferred_base)
             for name, span in spans.items()}
    for name, span in spans.items():
        frame = int(items[name][0].operands[0][1:], 0) if \
            items[name][0].opcode == "subq" and len(items[name][0].operands) == 2 else -1
        if frame <= 0:
            _fail(f"{name} lacks a plain Win64 frame")
        try:
            _check_plain_unwind(image_bytes, image, span, items[name][0], frame)
        except ValueError as error:
            _fail(f"{name} frame/unwind: {error}")
        _stack_layout(items[name], frame)
    states = _states(BINDING_STATUS, recipes[BINDING_STATUS])
    addresses = {name: image.preferred_base + spans[name].rva for name in EFFECT_CALLEES}
    none_profile = items[BINDING_STATUS][0].raw == b"\x48\x81\xec\x88\x00\x00\x00"
    counts = recipes["_real_counts"]
    if (counts[BINDING_STATUS] != (13 if none_profile else 7) or
            counts[GENERATION] != (4 if none_profile else 3)):
        _fail("raw report body count differs from linked profile")
    if none_profile:
        _binding_none(items[BINDING_STATUS], states, addresses)
    else:
        _binding(items[BINDING_STATUS], states, addresses)
    # The three effect functions are all exact COFF/PE subjects. Their
    # independent machine return routes are checked below.
    _effect_callees(items, recipes)
    _relocated_calls(object_bytes, image_bytes, image, spans, items)
    return {"verified": True, "state_pointer_identity_verified": True,
            "generation_guard_verified": True, "availability_route_verified": True,
            "transitive_binding_closed": False,
            "context_availability_body_verified": False,
            "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
            "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest()}


def _effect_callees(items, recipes):
    _state_effect(items[STATE], _states(STATE, recipes[STATE]))
    if items[GENERATION][0].operands[0] == "$0x30":
        _generation_effect_none(items[GENERATION], _states(GENERATION, recipes[GENERATION]))
    else:
        _generation_effect(items[GENERATION], _states(GENERATION, recipes[GENERATION]))
    if items[AVAILABILITY][0].operands[0] == "$0x58":
        _availability_effect_none(items[AVAILABILITY], _states(AVAILABILITY, recipes[AVAILABILITY]))
    else:
        _availability_effect(items[AVAILABILITY], _states(AVAILABILITY, recipes[AVAILABILITY]))


def _single_call_and_return(items, calls):
    actual = [item for item in items if item.opcode in ("call", "callq")]
    returns = [item for item in items if item.opcode in ("ret", "retq")]
    if len(actual) != calls or len(returns) != 1 or returns[0].opcode != "retq":
        _fail("effect callee has an extra call or return")


def _state_effect(items, states):
    if len(states) < 3:
        _fail("state accessor lacks three independent CFF states")
    _single_call_and_return(items, 0)
    (lease,), slot, root = _entry(items, states[0], ("%rcx",))
    routes = _boundaries(items, root, states[:3], slot)
    first, second, return_body = (routes[value] for value in states[:3])
    i = _at(items, first)
    salt = _imm(items[i + 2], b"\x81\xf1")
    if _plain_transition(items, i, slot, root, states[0], salt) != states[1]:
        _fail("state accessor first body misses second state")
    i = _at(items, second)
    if _plain_transition(items, i, slot, root, states[1], salt) != states[2]:
        _fail("state accessor second body misses return state")
    i = _at(items, return_body)
    body = [("movq", (lease, "%rax"))]
    if items[0].operands[0] == "$0x20":
        body += [("movq", ("%rax", "0x10(%rsp)")),
                 ("movq", ("0x10(%rsp)", "%rax"))]
    elif items[0].operands[0] != "$0x18":
        _fail("state accessor has an unsupported frame profile")
    i = _exact(items, i, body + [("movq", ("(%rax)", "%rax")),
                          ("addq", (items[0].operands[0], "%rsp")),
                          ("retq", ())], "state accessor pointer return")


def _generation_effect(items, states):
    if len(states) < 3:
        _fail("generation accessor lacks three independent CFF states")
    _single_call_and_return(items, 0)
    (lease,), slot, root = _entry(items, states[0], ("%rcx",))
    routes = _boundaries(items, root, states[:3], slot)
    initial, load_generation, returning = (routes[value] for value in states[:3])
    i = _at(items, initial)
    i = _exact(items, i, [("movq", (lease, "%rax")),
                          ("movq", ("(%rax)", "%rax")),
                          ("movq", ("%rax", None)),
                          ("movq", (None, "%r8")),
                          ("movq", ("$0x0", None))],
               "generation accessor null context route")
    context_slot = items[i - 3].operands[1]
    result_slot = items[i - 1].operands[1]
    if (not context_slot.endswith("(%rsp)") or
            items[i - 2].operands[0] != context_slot or
            not result_slot.endswith("(%rsp)") or
            len({context_slot, result_slot, lease, slot}) != 4):
        _fail("generation context/result slots alias or lose provenance")
    compare = next((item for item in items[i:] if item.opcode == "cmpq" and
                    item.operands == ("$0x0", "%r8") and
                    initial < item.address < load_generation), None)
    if compare is None:
        _fail("generation accessor lacks context null comparison")
    k = _at(items, compare.address)
    salt = _imm(items[k + 3], b"\x81\xf2")
    if _choice(items, compare.address, root, slot, states[0], salt,
               "cmpq", ("$0x0", "%r8")) != (states[1], states[2]):
        _fail("generation context null path does not return zero")
    i = _at(items, load_generation)
    i = _exact(items, i, [("movq", (context_slot, "%rax")),
                          ("movq", ("0x20(%rax)", "%rax")),
                          ("movq", ("%rax", result_slot))],
               "generation context field read")
    if _plain_transition(items, i, slot, root, states[1], salt) != states[2]:
        _fail("generation field read misses shared return")
    i = _at(items, returning)
    _exact(items, i, [("movq", (result_slot, "%rax")),
                      ("addq", (items[0].operands[0], "%rsp")),
                      ("retq", ())], "generation value return")


def _availability_effect(items, states):
    if len(states) < 4:
        _fail("availability accessor lacks four independent CFF states")
    _single_call_and_return(items, 1)
    (lease,), slot, root = _entry(items, states[0], ("%rcx",))
    routes = _boundaries(items, root, states[:4], slot)
    initial, null_body, context_body, returning = (routes[value] for value in states[:4])
    i = _at(items, initial)
    i = _exact(items, i, [("movq", (lease, "%rax")),
                          ("movq", ("(%rax)", "%rax")),
                          ("movq", ("%rax", None)),
                          ("movq", (None, "%r8"))],
               "availability accessor context source")
    context_slot = items[i - 2].operands[1]
    if (not context_slot.endswith("(%rsp)") or
            context_slot in (lease, slot) or
            items[i - 1].operands[0] != context_slot):
        _fail("availability accessor loses context pointer")
    compare = next((item for item in items[i:] if item.opcode == "cmpq" and
                    item.operands == ("$0x0", "%r8") and
                    initial < item.address < returning), None)
    if compare is None:
        _fail("availability accessor lacks context null comparison")
    k = _at(items, compare.address)
    salt = _imm(items[k + 3], b"\x81\xf2")
    if _choice(items, compare.address, root, slot, states[0], salt,
               "cmpq", ("$0x0", "%r8")) != (states[2], states[1]):
        _fail("availability context null route is reversed")
    i = _at(items, null_body)
    i = _exact(items, i, [("movq", (lease, "%rax")),
                          ("movl", ("0x8(%rax)", "%eax")),
                          ("movl", ("%eax", None))],
               "availability null-context fallback")
    result_slot = items[i - 1].operands[1]
    if not result_slot.endswith("(%rsp)") or result_slot in (lease, context_slot, slot):
        _fail("availability result aliases an input or dispatcher state")
    if _plain_transition(items, i, slot, root, states[1], salt) != states[3]:
        _fail("availability null-context result misses return")
    i = _at(items, context_body)
    i = _exact(items, i, [("movq", (context_slot, "%rcx"))],
               "availability context argument")
    target = items[i]
    match = DIRECT.fullmatch(target.operands[0]) if len(target.operands) == 1 else None
    if (target.opcode not in ("call", "callq") or match is None or
            match[2] != "_zn12pyobfuscator6native6detail20context_availabilityepns1_21bootstrapcontextstatee"):
        _fail("availability nonnull route misses context availability")
    i = _exact(items, i + 1, [("movl", ("%eax", result_slot))],
               "availability context result")
    if _plain_transition(items, i, slot, root, states[2], salt) != states[3]:
        _fail("availability context result misses return")
    i = _at(items, returning)
    _exact(items, i, [("movl", (result_slot, "%eax")),
                      ("addq", (items[0].operands[0], "%rsp")),
                      ("retq", ())], "availability status return")


def _generation_effect_none(items, states):
    if len(states) < 4:
        _fail("source-none generation needs four independent states")
    _single_call_and_return(items, 0)
    (lease,), slot, root = _entry(items, states[0], ("%rcx",))
    if lease != "0x8(%rsp)" or slot != "0x2c(%rsp)":
        _fail("source-none generation has an unsupported frame profile")
    where = _boundaries(items, root, states[:4], slot)
    initial, zero, nonnull, returning = (where[value] for value in states[:4])
    i = _at(items, initial)
    i = _exact(items, i, [
        ("movq", (lease, "%rax")), ("movq", ("%rax", "0x10(%rsp)")),
        ("movq", ("0x10(%rsp)", "%rax")), ("movq", ("%rax", "0x20(%rsp)")),
        ("movq", ("0x20(%rsp)", "%rax")), ("movq", ("(%rax)", "%r8")),
    ], "source-none generation context pointer")
    salt = _imm(items[i + 6], b"\x81\xf2")
    _none_choice(items, i, root, slot, states[0], salt, "cmpq", ("$0x0", "%r8"),
                 "cmovel", (states[2], states[1]))
    i = _at(items, zero)
    i = _exact(items, i, [("movq", ("$0x0", "0x18(%rsp)"))],
               "source-none zero generation")
    if _plain_transition(items, i, slot, root, states[1], salt) != states[3]:
        _fail("zero generation misses return")
    i = _at(items, nonnull)
    i = _exact(items, i, [("movq", ("0x20(%rsp)", "%rax")),
                          ("movq", ("(%rax)", "%rax")),
                          ("movq", ("0x20(%rax)", "%rax")),
                          ("movq", ("%rax", "0x18(%rsp)"))],
               "source-none generation context field")
    if _plain_transition(items, i, slot, root, states[2], salt) != states[3]:
        _fail("generation context field misses return")
    i = _at(items, returning)
    _exact(items, i, [("movq", ("0x18(%rsp)", "%rax")),
                      ("addq", ("$0x30", "%rsp")), ("retq", ())],
           "source-none generation return")


def _availability_effect_none(items, states):
    if len(states) < 4:
        _fail("source-none availability needs four independent states")
    _single_call_and_return(items, 1)
    (lease,), slot, root = _entry(items, states[0], ("%rcx",))
    if lease != "0x30(%rsp)" or slot != "0x54(%rsp)":
        _fail("source-none availability has an unsupported frame profile")
    where = _boundaries(items, root, states[:4], slot)
    initial, null_body, context_body, returning = (where[value] for value in states[:4])
    i = _at(items, initial)
    i = _exact(items, i, [
        ("movq", (lease, "%rax")), ("movq", ("%rax", "0x38(%rsp)")),
        ("movq", ("0x38(%rsp)", "%rax")), ("movq", ("%rax", "0x48(%rsp)")),
        ("movq", ("0x48(%rsp)", "%rax")), ("movq", ("(%rax)", "%r8")),
    ], "source-none availability context pointer")
    salt = _imm(items[i + 6], b"\x81\xf2")
    _none_choice(items, i, root, slot, states[0], salt, "cmpq", ("$0x0", "%r8"),
                 "cmovel", (states[2], states[1]))
    i = _at(items, null_body)
    i = _exact(items, i, [("movq", ("0x48(%rsp)", "%rax")),
                          ("movl", ("0x8(%rax)", "%eax")),
                          ("movl", ("%eax", "0x44(%rsp)"))],
               "source-none null-context availability")
    if _plain_transition(items, i, slot, root, states[1], salt) != states[3]:
        _fail("null-context availability misses return")
    i = _at(items, context_body)
    i = _exact(items, i, [("movq", ("0x48(%rsp)", "%rax")),
                          ("movq", ("(%rax)", "%rcx"))],
               "source-none nonnull availability argument")
    target = items[i]
    match = DIRECT.fullmatch(target.operands[0]) if len(target.operands) == 1 else None
    if (target.opcode not in ("call", "callq") or match is None or
            match[2] != "_zn12pyobfuscator6native6detail20context_availabilityepns1_21bootstrapcontextstatee"):
        _fail("source-none context availability target differs")
    i = _exact(items, i + 1, [("movl", ("%eax", "0x44(%rsp)"))],
               "source-none nonnull availability result")
    if _plain_transition(items, i, slot, root, states[2], salt) != states[3]:
        _fail("nonnull availability misses return")
    i = _at(items, returning)
    _exact(items, i, [("movl", ("0x44(%rsp)", "%eax")),
                      ("addq", ("$0x58", "%rsp")), ("retq", ())],
           "source-none availability return")
