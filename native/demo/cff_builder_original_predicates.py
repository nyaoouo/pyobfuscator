"""Bounded original-predicate proof for the two Windows x64 mixed POST owners.

The accepted lowering is deliberately narrow: the unoptimized relative-tree
body, its fixed stack frame, a compare/conditional move, and the standard
encoded-state delta. Unsupported optimized or archive-derived comparisons
fail closed instead of being treated as equivalent to the input IR.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_entry_states import _expected_state
from cff_builder_subjects import verify_builder_subjects
from cff_joint_machine_evidence import (ALIASES, CALLER_SAVED, DIRECT, STACK, _dispatcher_state,
                                        _entry_spills, _graph, _instructions)
from payload_binding import OWNER, WRAPPER
from post_mixed_binding import _plan


OWNERS = (OWNER, WRAPPER)
OBSERVATION = "_ZNK12pyobfuscator6native12contribution6scoped5Scope11observationEv"
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
IMM = re.compile(r"^\$((?:0x[0-9a-f]+)|(?:-?\d+))$")
RSP = re.compile(r"^(?:(0x[0-9a-f]+)|(-?\d+))?\(%rsp\)$")
INDIRECT = re.compile(r"^(0x[0-9a-f]+)\(%(rax|rcx)\)$")


def _fail(reason):
    raise ValueError(f"builder original predicates: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: _fail("duplicate JSON key")
        result[key] = value
    return result


def _document(raw, limit, name):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        _fail(f"{name} must be bounded bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _fail("nonfinite JSON number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"builder original predicates: invalid {name}") from error


def _imm(operand):
    match = IMM.fullmatch(operand)
    if match is None: _fail("unmodeled immediate operand")
    return int(match[1], 0) & MASK32


def _encoded_immediate(item, prefix):
    if not item.raw.startswith(prefix) or len(item.raw) != len(prefix) + 4:
        _fail("predicate encoded immediate has unmodeled x64 bytes")
    value = struct.unpack_from("<I", item.raw, len(prefix))[0]
    if _imm(item.operands[0]) != value:
        _fail("predicate displayed immediate differs from exact PE bytes")
    return value


def _slot(operand):
    match = RSP.fullmatch(operand)
    if match is None: _fail("unmodeled fixed-frame stack operand")
    return int(match[1] or match[2] or "0", 0)


def _register(operand):
    return ALIASES.get(operand[1:]) if operand.startswith("%") else None


def _mix(value):
    value ^= value >> 16
    value = value * 0x7feb352d & MASK32
    value ^= value >> 15
    value = value * 0x846ca68b & MASK32
    return value ^ (value >> 16)


def _states(owner, recipe):
    components = recipe.get("components") if type(recipe) is dict else None
    if type(components) is not list or any(type(item) is not dict for item in components):
        _fail("frozen recipe components are unsupported")
    seeds = [item.get("seed") for item in components if item.get("component") == "cfg"]
    seed = seeds[0] if len(seeds) == 1 else None
    if type(seed) is not int or not 0 <= seed <= MASK32:
        _fail("frozen CFG seed is unsupported")
    name_hash = 0xcbf29ce484222325
    for character in owner.encode("utf-8"):
        name_hash = (name_hash ^ character) * 0x100000001b3 & MASK64
    random_state = ((seed << 32) ^ name_hash) & MASK64
    used = set()
    states = []
    for index in range(129):
        random_state = (random_state + 0x9e3779b97f4a7c15) & MASK64
        value = random_state
        value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & MASK64
        candidate = (value ^ (value >> 31)) & MASK32
        if index == 0: continue  # the first draw supplies the transition salt
        if (4 <= candidate <= MASK32 - 4 and
                all(abs(candidate - previous) >= 4 for previous in used)):
            used.add(candidate)
            states.append(candidate)
    if not states or states[0] != _expected_state(owner, recipe):
        _fail("state generator differs from frozen entry seed")
    return states


def _ir_function(ir, owner):
    pattern = re.compile(r"(?m)^define [^\n]*@" + re.escape(owner) + r"\([^\n]*\) [^\n]*\{\n(.*?)^\}", re.S | re.M)
    matches = pattern.findall(ir)
    if len(matches) != 1: _fail(f"frozen IR owner is absent or repeated: {owner}")
    return matches[0]


def _ir_contract(input_ir_bytes):
    if type(input_ir_bytes) is not bytes or not input_ir_bytes or len(input_ir_bytes) > 16 << 20:
        _fail("frozen input IR must be bounded bytes")
    try:
        ir = input_ir_bytes.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("builder original predicates: input IR is not UTF-8") from error
    compute = _ir_function(ir, OWNER)
    wrapper = _ir_function(ir, WRAPPER)
    # These checks bind the accepted machine predicates to the exact source
    # expressions and to the branch polarities in the frozen pre-CFF IR.
    compute_match = re.search(
        r"store i32 %2, ptr (?P<slot>%\d+).*?"
        r"(?P<first_load>%\d+) = load i32, ptr (?P=slot)\b.*?"
        r"(?P<first_compare>%\d+) = icmp slt i32 (?P=first_load), 0.*?"
        r"br i1 (?P=first_compare), label %\d+, label %\d+[^\n]*"
        r"!pyobf\.cff\.site !(?P<first_site>\d+).*?"
        r"(?P<second_load>%\d+) = load i32, ptr (?P=slot)\b.*?"
        r"(?P<second_compare>%\d+) = icmp eq i32 (?P=second_load), 0.*?"
        r"br i1 (?P=second_compare), label %\d+, label %\d+[^\n]*"
        r"!pyobf\.cff\.site !(?P<second_site>\d+)", compute, re.S)
    if len(re.findall(r"\bicmp\b", compute)) != 2 or compute_match is None:
        _fail("frozen compute IR has an unmodeled original predicate")
    wrapper_match = re.search(
        r"store ptr %1, ptr (?P<parent_slot>%\d+).*?"
        r"store ptr %3, ptr (?P<handoff_slot>%\d+).*?"
        r"(?P<handoff>%\d+) = load ptr, ptr (?P=handoff_slot)\b.*?"
        r"(?P<generation_ptr>%\d+) = getelementptr[^\n]*PayloadHandoff[^\n]*"
        r"ptr (?P=handoff), i32 0, i32 2.*?"
        r"(?P<generation>%\d+) = load i64, ptr (?P=generation_ptr)\b.*?"
        r"(?P<parent>%\d+) = load ptr, ptr (?P=parent_slot)\b.*?"
        r"(?P<observation>%\d+) = call[^\n]*@" + OBSERVATION +
        r"\([^\n]* (?P=parent)\)[^\n]*.*?"
        r"(?P<subject_ptr>%\d+) = getelementptr[^\n]*Observation[^\n]*"
        r"ptr (?P=observation), i32 0, i32 3.*?"
        r"(?P<subject>%\d+) = load i64, ptr (?P=subject_ptr)\b.*?"
        r"(?P<compare>%\d+) = icmp ne i64 (?P=generation), (?P=subject).*?"
        r"br i1 (?P=compare), label %\d+, label %\d+[^\n]*"
        r"!pyobf\.cff\.site !(?P<site>\d+)", wrapper, re.S)
    if len(re.findall(r"\bicmp\b", wrapper)) != 1 or wrapper_match is None:
        _fail("frozen wrapper IR has an unmodeled original predicate")
    if (not re.search(r'PayloadHandoff" = type \{ i32, i32, i64, ptr', ir) or
            not re.search(r'Observation" = type \{', ir)):
        _fail("frozen source field layout is unsupported")
    definitions = dict(re.findall(r'(?m)^!(\d+) = !\{!"(original\.[^"]+)"\}$', ir))
    references = {OWNER: [compute_match["first_site"], compute_match["second_site"]],
                  WRAPPER: [wrapper_match["site"]]}
    if any(reference not in definitions for items in references.values() for reference in items):
        _fail("original branch provenance is absent from frozen IR")
    return {owner: [definitions[reference] for reference in items]
            for owner, items in references.items()}


def _entry_spill(instructions, source, width):
    matches = [item for item in instructions[:12] if item.opcode == "mov" + width and
               len(item.operands) == 2 and item.operands[0] == source and
               RSP.fullmatch(item.operands[1])]
    if len(matches) != 1: _fail(f"entry argument {source} lacks one fixed spill")
    spill = matches[0]
    register = _register(source)
    if register is None or source not in (f"%{register}", f"%{register}d"):
        _fail(f"entry argument {source} has an unmodeled register width")
    prologue_end = 2 if instructions[0].opcode == "pushq" else 1
    for position, item in enumerate(instructions):
        if item.address >= spill.address: break
        if item.opcode in ("call", "callq", "jmp", "jmpq", "jae", "ret", "retq", "popq"):
            _fail(f"entry argument {source} crosses control flow before its first spill")
        if _writes_register(item, register):
            _fail(f"entry argument {source} changes before its first spill")
        if position >= prologue_end and _writes_register(item, "rsp"):
            _fail(f"entry frame changes before {source} first spill")
    return _slot(spill.operands[1])


def _only_stack_write(instructions, slot, width, allowed):
    end = slot + width
    for item in instructions:
        if not item.operands: continue
        if item.opcode == "leaq" and RSP.fullmatch(item.operands[0]):
            address = _slot(item.operands[0])
            if slot <= address < end:
                _fail("original predicate source stack address escapes")
        if item.opcode in ("cmpl", "cmpq", "jae", "jmp", "jmpq", "ret", "retq",
                           "call", "callq", "pushq", "popq", "nop", "nopl", "nopw"):
            continue
        target = item.operands[-1]
        if not RSP.fullmatch(target): continue
        address = _slot(target)
        size = 8 if item.opcode == "movq" else 4
        if address < end and slot < address + size and item.address not in allowed:
            _fail("original predicate source stack slot has another writer")


def _writes_register(item, register):
    if (item.opcode in ("cmpl", "cmpq", "jae", "jmp", "jmpq", "ret", "retq",
                        "nop", "nopl", "nopw", "pushq") or not item.operands):
        return False
    return _register(item.operands[-1]) == register


def _block_start(instructions, compare_index):
    index = compare_index - 1
    while index >= 0 and instructions[index].opcode not in ("jmp", "jmpq", "jae", "ret", "retq"):
        index -= 1
    if index < 0: _fail("original predicate has no distinct CFF body")
    return instructions[index + 1].address


def _dispatcher_destination(instructions, root, state, state_slot):
    by_address = {item.address: item for item in instructions}
    registers, slots = {}, {state_slot: state}
    cursor, flags = root, None
    for _ in range(80):
        if cursor < root:
            return cursor
        item = by_address.get(cursor)
        if item is None: _fail("dispatcher leaves exact owner interval")
        op, args = item.opcode, item.operands
        following = cursor + len(item.raw)
        if op == "movl" and len(args) == 2:
            if RSP.fullmatch(args[0]): value = slots.get(_slot(args[0]))
            elif args[0] in registers: value = registers[args[0]]
            else: value = None
            if value is None: _fail("dispatcher reads an unmodeled state value")
            if RSP.fullmatch(args[1]): slots[_slot(args[1])] = value
            else: registers[args[1]] = value
        elif op == "cmpl" and len(args) == 2 and args[1] == "%eax":
            if item.raw[0] != 0x3d or len(item.raw) != 5:
                _fail("dispatcher comparison encoding is unsupported")
            if "%eax" not in registers:
                _fail("dispatcher comparison lacks its state read")
            flags = registers["%eax"] >= _imm(args[0])
        elif op == "jae":
            if flags is None: _fail("dispatcher branch lacks comparison flags")
            cursor = int(DIRECT.fullmatch(args[0])[1], 16) if flags else following
            continue
        elif op in ("jmp", "jmpq"):
            target = DIRECT.fullmatch(args[0])
            if target is None: _fail("dispatcher has an indirect leaf")
            cursor = int(target[1], 16)
            continue
        else:
            _fail("dispatcher has unmodeled lowering")
        cursor = following
    _fail("dispatcher path did not terminate")


def _transition(instructions, index, dispatcher, state_slot):
    """Decode the exact local flags-to-encoded-state span, with no side exit."""
    item = instructions[index]
    previous = instructions[index - 3:index]
    if (len(previous) != 3 or previous[0].opcode != "movl" or
            previous[0].operands != (f"{state_slot:#x}(%rsp)", "%eax") or
            [entry.opcode for entry in previous[1:]] != ["movl", "movl"] or
            previous[1].operands[1] != "%ecx" or previous[2].operands[1] != "%edx"):
        _fail("predicate lacks an adjacent current-state read and two encoded arms")
    false_arm = _encoded_immediate(previous[1], b"\xb9")
    true_arm = _encoded_immediate(previous[2], b"\xba")
    condition = instructions[index + 1]
    if (condition.address != item.address + len(item.raw) or
            condition.operands != ("%edx", "%ecx")):
        _fail("comparison flags do not feed the state choice")
    expected = [
        ("movl", ("%eax", "%edx")), ("xorl", None),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0x10", "%r8d")),
        ("xorl", ("%r8d", "%edx")),
        ("imull", ("$0x7feb352d", "%edx", "%edx")),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0xf", "%r8d")),
        ("xorl", ("%r8d", "%edx")),
        ("imull", ("$0x846ca68b", "%edx", "%edx")),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0x10", "%r8d")),
        ("xorl", ("%r8d", "%edx")), ("xorl", ("%edx", "%ecx")),
        ("addl", ("%ecx", "%eax")),
        ("movl", ("%eax", f"{state_slot:#x}(%rsp)")),
    ]
    span = instructions[index + 2:index + 2 + len(expected)]
    if len(span) != len(expected): _fail("predicate transition is truncated")
    for actual, (opcode, operands) in zip(span, expected):
        if actual.opcode != opcode or (operands is not None and actual.operands != operands):
            _fail("predicate choice does not reach the expected state write")
    if span[1].operands[1] != "%edx":
        _fail("predicate state mixer has an unknown salt operand")
    salt = _encoded_immediate(span[1], b"\x81\xf2")
    if (span[5].raw != b"\x69\xd2\x2d\x35\xeb\x7f" or
            span[9].raw != b"\x69\xd2\x8b\xa6\x6c\x84"):
        _fail("predicate state mixer differs from exact x64 encoding")
    if index + 2 + len(expected) >= len(instructions):
        _fail("predicate transition has no dispatcher return")
    branch = instructions[index + 2 + len(expected)]
    target = DIRECT.fullmatch(branch.operands[0]) if len(branch.operands) == 1 else None
    if (branch.opcode not in ("jmp", "jmpq") or target is None or
            int(target[1], 16) != dispatcher):
        _fail("predicate state write does not return to its dispatcher")
    return false_arm, true_arm, salt, span[-1].address


def _compute_source(instructions, index):
    item = instructions[index]
    if item.raw != b"\x41\x83\xf8\x00" or item.operands != ("$0x0", "%r8d"):
        _fail("compute predicate no longer compares the argument against zero")
    if index < 4: _fail("compute predicate source path is truncated")
    read = instructions[index - 4]
    if read.opcode != "movl" or read.operands[1] != "%r8d" or not RSP.fullmatch(read.operands[0]):
        _fail("compute predicate lacks a direct argument read")
    source_slot = _slot(read.operands[0])
    argument_slot = _entry_spill(instructions, "%r8d", "l")
    entry_write = next(entry for entry in instructions[:12] if entry.opcode == "movl" and
                       entry.operands == ("%r8d", f"{argument_slot:#x}(%rsp)"))
    writes = [n for n, entry in enumerate(instructions) if entry.opcode == "movl" and
              len(entry.operands) == 2 and entry.operands[1] == read.operands[0]]
    if len(writes) != 1 or instructions[writes[0]].operands[0] != "%eax":
        _fail("compute argument copy has an ambiguous source")
    block = _block_start(instructions, writes[0])
    preceding = [entry for entry in instructions if block <= entry.address < instructions[writes[0]].address]
    loads = [entry for entry in preceding if entry.opcode == "movl" and
             entry.operands == (f"{argument_slot:#x}(%rsp)", "%eax")]
    if len(loads) != 1 or any(entry.opcode in ("call", "callq") for entry in preceding):
        _fail("compute value is not copied from its entry argument on this path")
    if any(_writes_register(entry, "rsp") for entry in preceding):
        _fail("compute argument path changes its fixed frame")
    if any(_writes_register(entry, "rax") and entry.address > loads[0].address
           for entry in preceding):
        _fail("compute argument register is overwritten before its copy")
    _only_stack_write(instructions, argument_slot, 4, {entry_write.address})
    _only_stack_write(instructions, source_slot, 4, {instructions[writes[0]].address})
    return source_slot


def _wrapper_source(instructions, index):
    item = instructions[index]
    if item.raw != b"\x4d\x39\xc8" or item.operands != ("%r9", "%r8"):
        _fail("wrapper predicate no longer compares two independent values")
    handoff = _entry_spill(instructions, "%r9", "q")
    parent = _entry_spill(instructions, "%rdx", "q")
    handoff_write = next(entry for entry in instructions[:12] if entry.opcode == "movq" and
                         entry.operands == ("%r9", f"{handoff:#x}(%rsp)"))
    parent_write = next(entry for entry in instructions[:12] if entry.opcode == "movq" and
                        entry.operands == ("%rdx", f"{parent:#x}(%rsp)"))
    _only_stack_write(instructions, handoff, 8, {handoff_write.address})
    _only_stack_write(instructions, parent, 8, {parent_write.address})
    start = _block_start(instructions, index)
    values = {"r9": "handoff", "rdx": "parent"}
    slots = {handoff: "handoff", parent: "parent"}
    saw_generation = saw_subject = saw_call = False
    for entry in instructions:
        if not start <= entry.address < item.address: continue
        op, args = entry.opcode, entry.operands
        if op == "movq" and len(args) == 2:
            source, destination = args
            if RSP.fullmatch(source): value = slots.get(_slot(source))
            elif source.startswith("%"):
                register = _register(source)
                if register is None or source != f"%{register}":
                    _fail("wrapper source uses an unmodeled register width")
                value = values.get(register)
            else:
                indirect = INDIRECT.fullmatch(source)
                if indirect is None: _fail("wrapper source uses an unmodeled memory read")
                offset, base = int(indirect[1], 0), indirect[2]
                if (offset, values.get(base)) == (8, "handoff"):
                    value, saw_generation = "generation", True
                elif (offset, values.get(base)) == (0x58, "observation"):
                    value, saw_subject = "subject", True
                else:
                    _fail("wrapper source reads a different object field")
            if RSP.fullmatch(destination):
                address = _slot(destination)
                if any(previous != address and previous < address + 8 and
                       address < previous + 8 for previous in slots):
                    _fail("wrapper source has an overlapping stack write")
                slots[address] = value
            elif destination.startswith("%"):
                register = _register(destination)
                if register is None or destination != f"%{register}" or register == "rsp":
                    _fail("wrapper source changes its fixed frame or register width")
                values[register] = value
            else:
                _fail("wrapper source has an unmodeled memory write")
        elif op in ("call", "callq"):
            target = DIRECT.fullmatch(args[0]) if len(args) == 1 else None
            if target is None or target[2] != OBSERVATION.lower() or values.get("rcx") != "parent":
                _fail("wrapper observation call lacks its original parent")
            saw_call = True
            for register in CALLER_SAVED:
                values.pop(register, None)
            values["rax"] = "observation"
        elif op in ("nop", "nopl", "nopw", "cmpl", "cmpq"):
            continue
        elif op.endswith("l") and args:
            target = args[-1]
            if RSP.fullmatch(target):
                address = _slot(target)
                if any(previous < address + 4 and address < previous + 8
                       for previous in slots):
                    _fail("wrapper source has an unmodeled stack update")
            else:
                register = _register(target)
                if register is None or register == "rsp":
                    _fail("wrapper source has an unmodeled register or frame write")
                values.pop(register, None)
        elif op in ("leaq", "addq", "subq"):
            _fail("wrapper source path contains unmodeled pointer arithmetic")
        else:
            _fail("wrapper source path contains an unmodeled instruction")
    if not (saw_generation and saw_subject and saw_call and
            values.get("r8") == "generation" and values.get("r9") == "subject"):
        _fail("wrapper comparison does not read handoff generation and parent observation")


def _predicate_groups(plan, report, owner, ir_sites):
    planned = next(row for row in plan["owners"] if row["owner"] == owner)
    functions = report.get("functions") if type(report) is dict else None
    if type(functions) is not list or any(type(row) is not dict for row in functions):
        _fail("compiler report has no bounded function inventory")
    rows = [row for row in functions if row.get("function") == owner]
    if len(rows) != 1: _fail("report lacks one original owner")
    contribution = rows[0].get("runtime_contribution")
    edges = contribution.get("original_edges") if type(contribution) is dict else None
    actual = edges.get("edges") if type(edges) is dict else None
    if type(actual) is not list or any(type(row) is not dict for row in actual):
        _fail("compiler report has no original edge inventory")
    if len(actual) != len(planned["edges"]): _fail("original edge count differs from plan")
    groups = {}
    for wanted, observed in zip(planned["edges"], actual):
        if (wanted["id"] != observed.get("id") or
                wanted["successor_index"] != observed.get("successor") or
                wanted["label"] != observed.get("point") or
                type(observed.get("dispatch_state")) is not int or
                not 0 <= observed["dispatch_state"] <= MASK32):
            _fail("reported edge differs from frozen plan")
        key = wanted["id"].split(":instance:", 1)[0]
        group = groups.setdefault(key, {})
        if wanted["successor_index"] in group:
            _fail("original condition has a repeated successor")
        group[wanted["successor_index"]] = observed["dispatch_state"]
    pairs = []
    for source_id in ir_sites:
        group = groups.get(source_id)
        if group is None or set(group) != {0, 1}: _fail("plan lacks a frozen IR decision edge")
        pairs.append(group)
    if len(pairs) != (2 if owner == OWNER else 1) or len({id(group) for group in pairs}) != len(pairs):
        _fail("original condition edge inventory is unsupported")
    return planned, pairs


def verify_builder_original_predicates(object_bytes: bytes, image_bytes: bytes,
                                       report_bytes: bytes, input_ir_bytes: bytes,
                                       plan_bytes: bytes, owner_codes: dict[str, str]) -> dict:
    """Prove only the modeled original conditions in two exact mixed POST owners."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(owner_codes) is not dict or set(owner_codes) != set(OWNERS) or
            any(type(code) is not str or not code for code in owner_codes.values())):
        _fail("exact COFF, linked PE and both owner disassemblies are required")
    verify_builder_subjects(object_bytes, image_bytes)
    plan = _plan(plan_bytes)
    report = _document(report_bytes, 8 << 20, "compiler report")
    if report.get("original_edge_plan_sha256") != hashlib.sha256(plan_bytes).hexdigest():
        _fail("compiler report differs from frozen POST plan")
    ir_sites = _ir_contract(input_ir_bytes)
    result = []
    for owner in OWNERS:
        instructions = _instructions(owner_codes[owner], image_bytes, owner)
        _, graph, _ = _graph(instructions, allow_indirect=True)
        frame, _ = _entry_spills(instructions, image_bytes)
        absolute_slot = _dispatcher_state(instructions, graph, frame)
        state_slot = absolute_slot + frame
        first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
        dispatcher = graph[first_branch.address][0]
        planned, pairs = _predicate_groups(plan, report, owner, ir_sites[owner])
        expected_entry = _expected_state(owner, planned["recipe"])
        candidates = _states(owner, planned["recipe"])
        compares = [(index, item) for index, item in enumerate(instructions)
                    if item.opcode in ("cmpl", "cmpq") and index + 1 < len(instructions) and
                    instructions[index + 1].opcode in ("cmovll", "cmovel", "cmovnel")]
        if len(compares) != len(pairs):
            _fail(f"{owner} has extra, missing or unmodeled original comparisons")
        if owner == OWNER:
            semantic_order = {"cmovll": 0, "cmovel": 1}
            if set(instructions[index + 1].opcode for index, _ in compares) != set(semantic_order):
                _fail("compute comparison inventory differs from frozen IR")
            compares.sort(key=lambda pair: semantic_order[instructions[pair[0] + 1].opcode])
        proven = []
        for (index, item), pair in zip(compares, pairs):
            if owner == OWNER:
                _compute_source(instructions, index)
                wanted = (("cmovll", b"\x0f\x4c\xca") if len(proven) == 0 else
                          ("cmovel", b"\x0f\x44\xca"))
            else:
                _wrapper_source(instructions, index)
                wanted = ("cmovnel", b"\x0f\x45\xca")
            chosen = instructions[index + 1]
            if chosen.opcode != wanted[0] or chosen.raw != wanted[1]:
                _fail(f"{owner} condition polarity differs from frozen IR")
            false_arm, true_arm, salt, state_write = _transition(
                instructions, index, dispatcher, state_slot)
            start = _block_start(instructions, index)
            found = []
            for before in candidates:
                if _dispatcher_destination(instructions, dispatcher, before, state_slot) != start:
                    continue
                mask = _mix(before ^ salt)
                false_state = (before + (false_arm ^ mask)) & MASK32
                true_state = (before + (true_arm ^ mask)) & MASK32
                if (true_state, false_state) == (pair[0], pair[1]):
                    found.append(before)
            if len(found) != 1 or (not proven and found[0] != expected_entry):
                _fail(f"{owner} condition arms do not reach reported successor states")
            proven.append({"condition": "slt-zero" if owner == OWNER and not proven else
                           "eq-zero" if owner == OWNER else "generation-ne-subject",
                           "compare_rva": item.address - instructions[0].address,
                           "state_write_rva": state_write - instructions[0].address,
                           "source_state": found[0], "true_state": pair[0],
                           "false_state": pair[1]})
        result.append({"owner": owner, "conditions": proven})
    return {"verified": True, "scope": "mixed-post-original-predicates-win64-unoptimized-v1",
            "input_ir_sha256": hashlib.sha256(input_ir_bytes).hexdigest(), "owners": result}
