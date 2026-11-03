"""Bind the outer session's callback assignment to exact linked functions."""

import hashlib
import json
import re
import struct
from dataclasses import dataclass

from code_subject import MAX_RUNTIME_FUNCTIONS, unwind_interval
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import data_directory, parse_image, read_rva


INITIALIZE = ("_ZN12pyobfuscator6native4demo18initialize_session"
              "ERNS1_14RuntimeSessionEPFvjPvES4_")
DISPATCH = ("_ZN12pyobfuscator6native4demo18dispatch_lifecycle"
            "ERKNS0_23BootstrapContextRequestEPv")
CREATE = ("_ZN12pyobfuscator6native24create_bootstrap_context"
          "ERKNS0_20BootstrapContextSpecE")
SUBJECTS = (INITIALIZE, DISPATCH, CREATE)
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
ENTRY_PREFIX = bytes.fromhex(
    "4881ec38010000"  # subq $0x138, %rsp
    "4c89442440"      # preserve observer
    "4889542448"      # preserve user_data
    "48894c2450"      # preserve session
    "c7842434010000"  # initialize the CFF state slot
)
DISPATCH_ROOT = bytes.fromhex("8b8424340100008944242c8b44242c3d")
ENTRY_BODY = bytes.fromhex(
    "488b442440488b4c2448488b542450"
    "488954246048894c24684889442470"
    "488b4424604c8b00"
)
O2_ENTRY_PREFIX = bytes.fromhex(
    "4881ecc80000004c89442448488954245048894c2458c78424c4000000"
)
O2_DISPATCH_ROOT = bytes.fromhex("8b8424c40000008944242c8b44242c3d")
# The two observed O2 builds spill the copied state into one of these exact slots.
O2_DISPATCH_ROOT_24 = bytes.fromhex("8b8424c4000000894424248b4424243d")
O2_ENTRY_BODY = bytes.fromhex("488b4424584c8b00c68424a700000000")
HEADER = re.compile(r"^\s*([0-9a-f]+) <([^>]+)>:$")
LINE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?: [0-9a-f]{2})*)\s*\t([a-z][a-z0-9]*)\t?(.*)$")
DIRECT = re.compile(r"^(0x[0-9a-f]+)(?: <([^>]+)>)?$")
PROTECTION_FAILURE = "_zn12pyobfuscator6native8platform18protection_failureej"
TERMINAL_CALLS = {PROTECTION_FAILURE, "abort", "_zst9terminatev"}
RETURNING_CALLS = {
    "_zn12pyobfuscator6native21bootstrapcontextleaseaseos1_",
    "_zn12pyobfuscator6native21bootstrapcontextleased2ev",
    "_zn12pyobfuscator6native21bootstrapcontextowneraseos1_",
    "_zn12pyobfuscator6native24bootstrapcontextcreationd2ev",
    CREATE.lower(),
    "_zn12pyobfuscator6native4demo17read_build_configev",
    "_zn12pyobfuscator6native4demo23destroy_runtime_contextepv",
    "_zn12pyobfuscator6native8platform8allocateey",
    "_znk12pyobfuscator6native21bootstrapcontextlease12availabilityev",
    "_znk12pyobfuscator6native21bootstrapcontextowner10generationev",
    "_znk12pyobfuscator6native21bootstrapcontextowner5leaseev",
    "_znst3__16atomicijec2b9nqe220108ej",
}
ORDINARY_OPCODES = {
    "addl", "addq", "andb", "cmovel", "cmovnel", "cmpl", "cmpq", "imull",
    "leaq", "movb", "movl", "movq", "nop", "nopl", "nopw", "sete", "shrl",
    "subq", "xorl",
}
ASSIGNMENT_OFFSETS = (0, 11, 18, 26, 34, 42, 49, 57, 65, 73, 78)

# This compiler lowering leaves four adjacent fields in the same stack spec.
# The two LEA/call displacement fields are checked against exact COFF fixups.
ASSIGNMENT = re.compile(
    rb"\xc7\x84\x24(?P<spec>.{4})\x01\x00\x00\x00"
    rb"\x48\x8d\x05(?P<callback>.{4})"
    rb"\x48\x89\x84\x24(?P<dispatch_slot>.{4})"
    rb"\x48\x8b\x84\x24(?P<context_source>.{4})"
    rb"\x48\x89\x84\x24(?P<context_slot>.{4})"
    rb"\x48\x8d\x05(?P<destroy>.{4})"
    rb"\x48\x89\x84\x24(?P<destroy_slot>.{4})"
    rb"\x48\x8d\x8c\x24(?P<result_slot>.{4})"
    rb"\x48\x8d\x94\x24(?P<spec_arg>.{4})"
    rb"\xe8(?P<creator>.{4})",
    re.DOTALL,
)
O2_ASSIGNMENT_OFFSETS = (0, 8, 15, 20, 28, 36, 43, 51, 56, 61, 66)
O2_ASSIGNMENT = re.compile(
    rb"\xc7\x44\x24(?P<spec>.)\x01\x00\x00\x00"
    rb"\x48\x8d\x05(?P<callback>.{4})"
    rb"\x48\x89\x44\x24(?P<dispatch_slot>.)"
    rb"\x48\x8b\x84\x24(?P<context_source>.{4})"
    rb"\x48\x89\x84\x24(?P<context_slot>.{4})"
    rb"\x48\x8d\x05(?P<destroy>.{4})"
    rb"\x48\x89\x84\x24(?P<destroy_slot>.{4})"
    rb"\x48\x8d\x4c\x24(?P<result_slot>.)"
    rb"\x48\x8d\x54\x24(?P<spec_arg>.)"
    rb"\xe8(?P<creator>.{4})",
    re.DOTALL,
)


@dataclass(frozen=True)
class Lowering:
    name: str
    entry_prefix: bytes
    dispatch_roots: tuple[tuple[bytes, int], ...]
    entry_body: bytes
    assignment: re.Pattern
    assignment_offsets: tuple[int, ...]
    frame: int
    state_slot: int
    spec: int
    result: int
    source: int
    unwind: bytes


LOWERINGS = (
    Lowering("source-none", ENTRY_PREFIX, ((DISPATCH_ROOT, 0x2c),), ENTRY_BODY,
             ASSIGNMENT, ASSIGNMENT_OFFSETS, 0x138, 0x134, 0x98, 0x88,
             0x80, bytes.fromhex("0107020007012700")),
    Lowering("outer-source-o2", O2_ENTRY_PREFIX,
             ((O2_DISPATCH_ROOT, 0x2c), (O2_DISPATCH_ROOT_24, 0x24)),
             O2_ENTRY_BODY, O2_ASSIGNMENT, O2_ASSIGNMENT_OFFSETS,
             0xc8, 0xc4, 0x70, 0x60, 0xb0,
             bytes.fromhex("0107020007011900")),
)


def _invalid(reason):
    raise ValueError(f"parent callback: {reason}")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("raw compiler report has a duplicate JSON key")
        result[key] = value
    return result


def _report(report_bytes):
    if len(report_bytes) > 16 * 1024 * 1024:
        _invalid("raw compiler report exceeds the byte budget")
    try:
        report = json.loads(report_bytes, object_pairs_hook=_unique_pairs)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _invalid(f"raw compiler report is invalid: {error}")
    if type(report) is not dict or type(report.get("functions")) is not list:
        _invalid("raw compiler report lacks selected function rows")
    rows = {name: [] for name in SUBJECTS}
    for row in report["functions"]:
        if type(row) is not dict:
            _invalid("raw compiler report has an invalid function row")
        name = row.get("function")
        if type(name) is not str:
            _invalid("raw compiler report has a non-string function name")
        if name in rows:
            rows[name].append(row)
    if any(len(rows[name]) != 1 or rows[name][0].get("selected") is not True or
           rows[name][0].get("status") != "transformed" or
           rows[name][0].get("coverage_kind") != "decision-flow" for name in SUBJECTS):
        _invalid("session, callback and creator need distinct transformed decision-flow rows")
    return rows[INITIALIZE][0]


def _expected_entry_state(row):
    recipe = row.get("effective_recipe")
    components = recipe.get("components") if type(recipe) is dict else None
    cfg = [part for part in components if type(part) is dict and
           part.get("component") == "cfg"] if type(components) is list else []
    if (type(recipe) is not dict or recipe.get("strategy") != "relative-tree" or
            recipe.get("coverage") != "whole" or len(cfg) != 1 or
            type(cfg[0].get("seed")) is not int or not 0 <= cfg[0]["seed"] <= MASK32):
        _invalid("session lacks one bounded whole-function CFG seed")
    name_hash = 0xcbf29ce484222325
    for byte in INITIALIZE.encode("utf-8"):
        name_hash = ((name_hash ^ byte) * 0x100000001b3) & MASK64
    state = ((cfg[0]["seed"] << 32) ^ name_hash) & MASK64
    for step in range(17):
        state = (state + 0x9e3779b97f4a7c15) & MASK64
        value = state
        value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & MASK64
        candidate = (value ^ (value >> 31)) & MASK32
        if step and 4 <= candidate <= MASK32 - 4:
            return candidate
    _invalid("session entry state generator exceeded its bounded candidates")


def _lowering(original):
    matches = [profile for profile in LOWERINGS
               if original.startswith(profile.entry_prefix)]
    if len(matches) != 1:
        _invalid("unsupported entry route or CFF initializer")
    return matches[0]


def _entry_route(original, expected, profile):
    prefix = len(profile.entry_prefix)
    if (len(original) < prefix + 9 or
            struct.unpack_from("<I", original, prefix)[0] != expected or
            original[prefix + 4] != 0xe9):
        _invalid("unsupported entry route or CFF initializer")
    branch = prefix + 5
    target = branch + 4 + struct.unpack_from("<i", original, branch)[0]
    roots = [(offset, temporary) for root, temporary in profile.dispatch_roots
             for offset in range(len(original) - len(root) + 1)
             if original[offset:offset + len(root)] == root]
    if len(roots) != 1 or target != roots[0][0]:
        _invalid("session entry misses its unique stack-state dispatcher")
    return target, roots[0][1]


def _root(object_data, obj, name):
    roots = [symbol for symbol in obj.symbols if symbol.name == name and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    if len(roots) != 1:
        _invalid(f"function lacks one exact COFF root: {name}")
    return obj.sections[roots[0].section - 1]


def _relocation(symbols, section, offset, name):
    matching = [entry for entry in section.relocations
                if symbols[entry.target].name == name]
    if len(matching) != 1 or matching[0].offset != offset or matching[0].kind != 4:
        _invalid(f"callback assignment has no unique exact {name} REL32 fixup")


def _offset(match, name):
    return int.from_bytes(match.group(name), "little")


def _unwind_allocation(image_bytes, image, session, profile):
    try:
        directory, size = data_directory(image, 3)
        if (not directory or directory % 4 or size % 12 or
                size // 12 > MAX_RUNTIME_FUNCTIONS):
            _invalid("session lacks a bounded PE exception directory")
        rows = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
        matched = [(begin, end, unwind) for begin, end, unwind in rows
                   if begin == session.rva and end == session.rva + session.size]
        if len(matched) != 1 or matched[0][2] & 3:
            _invalid("session lacks one exact PE unwind row")
        actual = read_rva(image_bytes, image, matched[0][2], len(profile.unwind))
    except ValueError as error:
        _invalid(f"session PE unwind is invalid: {error}")
    if actual != profile.unwind:
        _invalid("session PE unwind allocation differs from its fixed frame")


def _relative_target(code, displacement_offset, instruction_end):
    displacement = struct.unpack_from("<i", code, displacement_offset)[0]
    return instruction_end + displacement


def _machine_instructions(code, image_bytes, image, session):
    if type(code) is not str or not 0 < len(code) <= 2_000_000:
        _invalid("bounded exact session disassembly is required")
    headers = [(int(match[1], 16), match[2]) for line in code.splitlines()
               if (match := HEADER.match(line))]
    entry = image.preferred_base + session.rva
    if headers != [(entry, INITIALIZE.lower())]:
        _invalid("session disassembly lacks its single exact symbol")
    try:
        unwind = unwind_interval(image_bytes, image, 0xcb01, session.rva)
    except ValueError as error:
        _invalid(f"session has no exact PE unwind interval: {error}")
    if unwind.ranges != (session,):
        _invalid("session disassembly differs from its PE unwind extent")
    expected = read_rva(image_bytes, image, session.rva, session.size)
    instructions = []
    for line in code.splitlines():
        match = LINE.match(line)
        if match is None:
            continue
        address = int(match[1], 16)
        if not entry <= address < entry + session.size:
            continue
        raw = bytes.fromhex(match[2])
        operands = match[4].split("#", 1)[0].strip()
        arguments = tuple(part.strip() for part in operands.split(",")) if operands else ()
        instructions.append((address, raw, match[3], arguments))
    cursor = entry
    for address, raw, _, _ in instructions:
        if address != cursor or expected[cursor - entry:cursor - entry + len(raw)] != raw:
            _invalid("session disassembly has a gap, overlap or PE byte mismatch")
        cursor += len(raw)
    if cursor != entry + session.size:
        _invalid("session disassembly does not cover its exact PE subject")
    return instructions


def _direct_target(item):
    operands = item[3]
    if len(operands) != 1 or (match := DIRECT.fullmatch(operands[0])) is None:
        _invalid(f"session has an indirect or malformed {item[2]}")
    return int(match[1], 16), match[2]


def _call_successors(item, next_address, profile=None):
    target, symbol = _direct_target(item)
    if symbol in TERMINAL_CALLS:
        return target, ()
    if symbol in RETURNING_CALLS or (profile is not None and
                                     profile.name == "outer-source-o2" and
                                     symbol == "memset"):
        return target, (next_address,)
    _invalid(f"session call has no admitted return behavior: {symbol}")


def _reachable(graph, entry, *, blocked=None):
    seen, pending = set(), [entry]
    while pending:
        current = pending.pop()
        if current == blocked or current in seen:
            continue
        seen.add(current)
        pending.extend(graph[current])
    return seen


def _initial_dispatch_leaf(by_address, graph, root, state, profile, temporary_slot):
    cursor, eax, temporary, compared, visited = root, None, None, None, set()
    for _ in range(128):
        if cursor in visited:
            _invalid("initial dispatcher route cycles")
        visited.add(cursor)
        item = by_address.get(cursor)
        if item is None:
            _invalid("initial dispatcher route leaves decoded code")
        address, raw, opcode, operands = item
        following = address + len(raw)
        if opcode == "movl":
            if operands == (f"0x{profile.state_slot:x}(%rsp)", "%eax") and cursor == root:
                eax = state
            elif operands == ("%eax", f"0x{temporary_slot:x}(%rsp)") and eax is not None:
                temporary = eax
            elif operands == (f"0x{temporary_slot:x}(%rsp)", "%eax") and temporary is not None:
                eax = temporary
            else:
                _invalid("initial dispatcher reads an unknown state value")
            cursor = following
        elif opcode == "cmpl":
            if len(operands) != 2 or operands[1] != "%eax" or not operands[0].startswith("$"):
                _invalid("initial dispatcher has an unsupported pivot")
            try:
                compared = eax >= (int(operands[0][1:], 0) & MASK32)
            except (TypeError, ValueError) as error:
                _invalid(f"initial dispatcher pivot is invalid: {error}")
            cursor = following
        elif opcode == "jae":
            if compared is None:
                _invalid("initial dispatcher branches without a comparison")
            cursor = graph[address][0] if compared else graph[address][1]
            compared = None
        elif opcode in ("jmp", "jmpq"):
            target = graph[address][0]
            if target < root:
                leaf = by_address[target]
                if (leaf[2] in ("ret", "retq") or
                        leaf[1] == b"\x48\x81\xc4" + struct.pack("<I", profile.frame)):
                    _invalid("initial state dispatches to the normal-return epilogue")
                return target
            cursor = target
        else:
            _invalid(f"initial dispatcher has an unsupported instruction: {opcode}")
    _invalid("initial dispatcher route exceeds the instruction budget")


def _machine_route(instructions, image, session, match, dispatcher, creator_rva,
                   entry_state, profile, temporary_slot):
    by_address = {item[0]: item for item in instructions}
    if len(by_address) != len(instructions):
        _invalid("session disassembly has duplicate instruction addresses")
    entry = image.preferred_base + session.rva
    sequence = [entry + match.start() + part for part in profile.assignment_offsets]
    for address, following in zip(sequence, sequence[1:]):
        item = by_address.get(address)
        if item is None or address + len(item[1]) != following:
            _invalid("callback assignment is not one decoded instruction sequence")
    creator = sequence[-2]
    target = image.preferred_base + session.rva + dispatcher
    entry_branch = by_address.get(entry + len(profile.entry_prefix) + 4)
    if entry_branch is None or entry_branch[2] not in ("jmp", "jmpq"):
        _invalid("session entry does not end in a direct dispatcher jump")
    graph, calls, returns = {}, [], []
    for item in instructions:
        address, raw, opcode, operands = item
        next_address = address + len(raw)
        changes_stack = (opcode in ("pushq", "popq", "enter", "leave") or
                         bool(operands) and operands[-1] == "%rsp" and
                         opcode not in ("cmpl", "cmpq", "testl", "testq"))
        if changes_stack and not (
                address == entry and raw == b"\x48\x81\xec" + struct.pack("<I", profile.frame) or
                opcode == "addq" and raw == b"\x48\x81\xc4" + struct.pack("<I", profile.frame) and
                next_address in by_address and by_address[next_address][2] in ("ret", "retq")):
            _invalid("session stack pointer escapes its fixed frame")
        if opcode in ("ret", "retq"):
            if operands:
                _invalid("session has a malformed return")
            graph[address] = ()
            returns.append(address)
        elif opcode in ("jmp", "jmpq", "jae"):
            branch, _ = _direct_target(item)
            if branch not in by_address:
                _invalid("session branch leaves its exact function or enters an instruction")
            if opcode == "jae":
                if next_address not in by_address:
                    _invalid("session conditional branch loses its fallthrough")
                graph[address] = (branch, next_address)
            else:
                graph[address] = (branch,)
        elif opcode.startswith("j"):
            _invalid(f"session has an unsupported branch: {opcode}")
        elif opcode in ("int3", "ud2"):
            graph[address] = ()
        else:
            if opcode not in ORDINARY_OPCODES and opcode not in ("call", "callq"):
                _invalid(f"session has an unsupported instruction: {opcode}")
            if next_address not in by_address:
                _invalid("session instruction falls outside its exact function")
            if opcode in ("call", "callq"):
                call_target, successors = _call_successors(item, next_address, profile)
                calls.append((address, call_target))
                graph[address] = successors
            else:
                graph[address] = (next_address,)
    if graph[entry_branch[0]] != (target,) or len(returns) != 1:
        _invalid("session entry or normal-return route is unsupported")
    leaf = _initial_dispatch_leaf(by_address, graph, target, entry_state,
                                  profile, temporary_slot)
    linked = b"".join(item[1] for item in instructions)
    body = profile.entry_body
    entry_bodies = [offset for offset in range(len(linked) - len(body) + 1)
                    if linked[offset:offset + len(body)] == body]
    if len(entry_bodies) != 1 or leaf != entry + entry_bodies[0]:
        _invalid("initial state misses its unique entry body")
    creator_calls = [address for address, call_target in calls
                     if call_target == image.preferred_base + creator_rva]
    if creator_calls != [creator] or by_address[creator][2] not in ("call", "callq"):
        _invalid("session has no unique direct call to its exact creator")
    reachable = _reachable(graph, entry)
    if target not in reachable or any(address not in reachable for address in sequence):
        _invalid("callback assignment and creator call are unreachable from entry")
    if creator not in _reachable(graph, leaf):
        _invalid("initial body has no CFG route to its creator call")
    for address in sequence[:-2]:
        if creator in _reachable(graph, entry, blocked=address):
            _invalid("callback/spec construction does not dominate the creator call")
    return {"entry_cfg_reaches_creator_verified": True,
            "callback_spec_cfg_dominates_creator_verified": True,
            "single_direct_creator_call_verified": True,
            "single_normal_return_verified": True,
            "initial_body_cfg_reaches_creator_verified": True,
            "initial_dispatch_leaf_rva": leaf - image.preferred_base}


def verify_parent_callback(object_bytes: bytes, image_bytes: bytes,
                           report_bytes: bytes, initialize_code: str) -> dict:
    """Prove only the producer's fixed callback assignment and creator call."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(report_bytes) is not bytes or not report_bytes):
        _invalid("exact outer object, linked image and raw report are required")
    session_row = _report(report_bytes)
    image = parse_image(image_bytes)
    obj = parse_object(object_bytes)
    # Index once: relocation symbol indices include auxiliaries and are not
    # interchangeable with positions in obj.symbols.
    symbols = {symbol.index: symbol for symbol in obj.symbols}
    subjects = {}
    for tag, name in enumerate(SUBJECTS, 1):
        subject = function_subject(object_bytes, image_bytes, image, tag, name)
        if len(subject.ranges) != 1:
            _invalid("callback proof requires single-range functions")
        subjects[name] = subject.ranges[0]
    section = _root(object_bytes, obj, INITIALIZE)
    session = subjects[INITIALIZE]
    if section.size != session.size:
        _invalid("session's COFF and PE extents differ")
    original = object_bytes[section.offset:section.offset + section.size]
    entry_state = _expected_entry_state(session_row)
    profile = _lowering(original)
    dispatcher, temporary_slot = _entry_route(original, entry_state, profile)
    matches = list(profile.assignment.finditer(original))
    if len(matches) != 1:
        _invalid("session lacks one adjacent callback/spec/creator assignment")
    match = matches[0]
    if len(original) < 7 or original[:3] != b"\x48\x81\xec":
        _invalid("session has an unsupported fixed stack frame")
    frame = struct.unpack_from("<I", original, 3)[0]
    spec = _offset(match, "spec")
    result = _offset(match, "result_slot")
    source = _offset(match, "context_source")
    if (frame != profile.frame or spec != profile.spec or
            result != profile.result or source != profile.source or
            spec != _offset(match, "spec_arg") or
            _offset(match, "dispatch_slot") != spec + 8 or
            _offset(match, "context_slot") != spec + 16 or
            _offset(match, "destroy_slot") != spec + 24 or
            result < 0x20 or result + 16 > spec or
            source < 0x20 or source + 8 > frame or
            spec < 0x20 or spec + 32 > frame):
        _invalid("callback, spec and call arguments do not share the fixed frame")
    _relocation(symbols, section, match.start("callback"), DISPATCH)
    _relocation(symbols, section, match.start("creator"), CREATE)
    linked = read_rva(image_bytes, image, session.rva, session.size)
    callback_store_rva = session.rva + match.start("dispatch_slot") - 4
    callback_field = match.start("callback")
    callback_target = _relative_target(linked, callback_field,
                                       session.rva + callback_field + 4)
    creator_field = match.start("creator")
    creator_target = _relative_target(linked, creator_field,
                                      session.rva + creator_field + 4)
    if (callback_target != subjects[DISPATCH].rva or
            creator_target != subjects[CREATE].rva):
        _invalid("linked callback or creator target differs from its exact subject")
    _unwind_allocation(image_bytes, image, session, profile)
    instructions = _machine_instructions(initialize_code, image_bytes, image, session)
    route = _machine_route(instructions, image, session, match, dispatcher,
                           subjects[CREATE].rva, entry_state, profile, temporary_slot)
    return {"verified": True, "scope": "outer-creator-callback-route-v1",
            "lowering": profile.name, "pe_unwind_allocation_verified": True,
            "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "subjects": [{"symbol": name, "rva": subjects[name].rva,
                          "size": subjects[name].size} for name in SUBJECTS],
            "callback_assignment_rva": callback_store_rva,
            "creator_call_rva": session.rva + match.start("creator") - 1,
            "spec_stack_offset": spec,
            "entry_state": entry_state, "dispatcher_rva": session.rva + dispatcher,
            "producer_assignment_verified": True, **route}
