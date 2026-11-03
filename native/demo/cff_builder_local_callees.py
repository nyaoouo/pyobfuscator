"""Prove a bounded mixed POST binding route in exact linked child functions."""

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_entry_states import _actual_state, _next_random
from cff_builder_subjects import SUBJECTS
from cff_joint_machine_evidence import (DIRECT, MEASURED, OWNED, STACK, _dispatcher_state,
                                        _entry_spills, _graph, _instructions, _stack, State)
from cff_source_mixed_helper_routes import FAILURE, _check_route, _target
from code_subject import unwind_interval
from function_subject import function_subject
from pe_layout import data_directory, parse_image, read_rva


REQUIRE_BINDING = ("_ZN12pyobfuscator6native12contribution6scoped12_GLOBAL__N_1"
                   "15require_bindingERKNS2_5ScopeERKNS0_21BootstrapContextLeaseE")
BINDING_STATUS = ("_ZNK12pyobfuscator6native12contribution6scoped5Scope"
                  "14binding_statusERKNS0_21BootstrapContextLeaseE")
LOCAL_CALLEES = (REQUIRE_BINDING, BINDING_STATUS)
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff


def _invalid(reason):
    raise ValueError(f"local callees: {reason}")


def _within_frame(slot, width, frame):
    return slot is not None and -frame <= slot and slot + width <= 0


def _overlaps(left, left_width, right, right_width):
    return left < right + right_width and right < left + left_width


def _check_plain_unwind(image_bytes, image, span, prologue, allocation):
    if (prologue.raw[:3] == b"\x48\x83\xec" and len(prologue.raw) == 4 and
            prologue.raw[3] == allocation):
        pass
    elif (prologue.raw[:3] == b"\x48\x81\xec" and len(prologue.raw) == 7 and
          prologue.raw[3:] == struct.pack("<I", allocation)):
        pass
    else:
        _invalid("binding frame has an unsupported plain stack allocation")
    try:
        subject = unwind_interval(image_bytes, image, 0xb520, span.rva)
        if subject.ranges != (span,):
            _invalid("binding frame differs from its exact PE unwind interval")
        directory, size = data_directory(image, 3)
        rows = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
        matches = [unwind for begin, _, unwind in rows if begin == span.rva]
        if len(matches) != 1:
            _invalid("binding frame lacks one exact PE unwind record")
        header = read_rva(image_bytes, image, matches[0], 4)
        if allocation <= 128:
            expected = bytes((len(prologue.raw), 2 | ((allocation // 8 - 1) << 4)))
        else:
            expected = bytes((len(prologue.raw), 1)) + struct.pack("<H", allocation // 8)
        if (header != bytes((1, len(prologue.raw), len(expected) // 2, 0)) or
                read_rva(image_bytes, image, matches[0] + 4, len(expected)) != expected):
            _invalid("binding frame allocation differs from PE unwind codes")
    except ValueError as error:
        if str(error).startswith("local callees:"):
            raise
        _invalid(f"binding frame PE unwind is invalid: {error}")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("raw compiler report has a duplicate JSON key")
        result[key] = value
    return result


def _component_seed(seed, name):
    value = 2166136261 ^ seed
    for part in ("pyobf.cff.v1", name, "cfg"):
        for byte in part.encode("utf-8"):
            value = ((value ^ byte) * 16777619) & MASK32
        value = ((value ^ 0xff) * 16777619) & MASK32
    return value


def _layout(seed, name):
    name_hash = 0xcbf29ce484222325
    for byte in name.encode("utf-8"):
        name_hash = ((name_hash ^ byte) * 0x100000001b3) & MASK64
    random_state = ((seed << 32) ^ name_hash) & MASK64
    random_state, salt = _next_random(random_state)
    states = []
    for _ in range(3):
        for _ in range(32):
            random_state, value = _next_random(random_state)
            candidate = value & MASK32
            if (4 <= candidate <= MASK32 - 4 and
                    all(abs(candidate - prior) >= 4 for prior in states)):
                states.append(candidate)
                break
        else:
            _invalid("state layout exceeded its bounded candidates")
    return salt & MASK32 | 1, states


def _report_seed(report_bytes, build_seed):
    if type(report_bytes) is not bytes or not 0 < len(report_bytes) <= 8_000_000:
        _invalid("bounded raw compiler report is required")
    try:
        report = json.loads(report_bytes.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("local callees: invalid raw compiler report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _invalid("raw report lacks bounded function rows")
    for name in LOCAL_CALLEES:
        selected = [row for row in rows if type(row) is dict and row.get("function") == name]
        if (len(selected) != 1 or selected[0].get("selected") is not True or
                selected[0].get("status") != "transformed" or
                selected[0].get("strategy") != "relative-tree" or
                selected[0].get("coverage_kind") != "decision-flow"):
            _invalid(f"raw report lacks one transformed local function: {name}")
    row = next(row for row in rows if type(row) is dict and row.get("function") == REQUIRE_BINDING)
    recipe = row.get("effective_recipe")
    components = recipe.get("components") if type(recipe) is dict else None
    totals = row.get("site_totals")
    roles = totals.get("body_roles") if type(totals) is dict else None
    cfg = [part for part in components if type(part) is dict and part.get("component") == "cfg"] \
        if type(components) is list else []
    if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
            recipe.get("strategy") != "relative-tree" or len(cfg) != 1 or
            type(cfg[0].get("seed")) is not int or
            cfg[0]["seed"] != _component_seed(build_seed, REQUIRE_BINDING) or
            type(roles) is not dict or roles.get("real") != 3):
        _invalid("binding CFG recipe differs from independent build seed or three-body profile")
    return cfg[0]["seed"]


def _subjects(object_bytes, image_bytes, image):
    ranges = []
    local = {}
    for index, name in enumerate((*SUBJECTS, *LOCAL_CALLEES)):
        subject = function_subject(object_bytes, image_bytes, image, 0xb400 + index, name)
        if subject.kind != "function-contribution" or subject.label != name or not subject.ranges:
            _invalid(f"incomplete exact function subject: {name}")
        for span in subject.ranges:
            ranges.append((span.rva, span.rva + span.size, name))
        if name in LOCAL_CALLEES:
            if len(subject.ranges) != 1:
                _invalid(f"local function has an unsupported fragment layout: {name}")
            local[name] = subject.ranges[0]
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        _invalid("local and existing function subjects overlap")
    return local


def _imm(item, opcode, prefix):
    if (item.opcode != opcode or len(item.operands) != 2 or
            not item.operands[0].startswith("$") or
            item.raw[:len(prefix)] != prefix or len(item.raw) != len(prefix) + 4):
        _invalid(f"unsupported {opcode} immediate in binding route")
    value = struct.unpack_from("<I", item.raw, len(prefix))[0]
    if int(item.operands[0][1:], 0) & MASK32 != value:
        _invalid("binding immediate text differs from PE bytes")
    return value


def _mask(state, salt):
    value = state ^ salt
    value ^= value >> 16
    value = value * 0x7feb352d & MASK32
    value ^= value >> 15
    value = value * 0x846ca68b & MASK32
    return value ^ value >> 16


def _update(instructions, call, state_slot, frame, current, salt):
    index = instructions.index(call)
    steps = instructions[index + 1:index + 20]
    opcodes = ("movl", "movl", "movl", "movl", "cmpl", "cmovnel", "movl",
               "xorl", "movl", "shrl", "xorl", "imull", "movl", "shrl",
               "xorl", "imull", "movl", "shrl", "xorl")
    if len(steps) != len(opcodes):
        _invalid("binding status update has an incomplete instruction span")
    actual = tuple(item.opcode for item in steps)
    if actual != opcodes and actual != tuple("cmovel" if op == "cmovnel" else op for op in opcodes):
        _invalid("binding status update has an unsupported instruction sequence")
    if any(len(item.operands) != (3 if index in (11, 15) else 2)
           for index, item in enumerate(steps)):
        _invalid("binding status update has malformed operands")
    if (steps[0].raw != b"\x41\x89\xc0" or steps[0].operands != ("%eax", "%r8d") or
            steps[1].operands[1] != "%eax" or not STACK.fullmatch(steps[1].operands[0]) or
            _stack(steps[1].operands[0], State(-frame, {}, {}, {}, {}, {}, {}, 0)) != state_slot or
            steps[4].raw != b"\x41\x83\xf8\x00" or
            steps[4].operands != ("$0x0", "%r8d") or
            steps[5].operands != ("%edx", "%ecx") or
            steps[5].raw != (b"\x0f\x45\xca" if steps[5].opcode == "cmovnel"
                             else b"\x0f\x44\xca")):
        _invalid("binding result is not the exact zero-tested transition selector")
    zero_code = _imm(steps[2], "movl", b"\xb9")
    nonzero_code = _imm(steps[3], "movl", b"\xba")
    if (steps[2].operands[1] != "%ecx" or steps[3].operands[1] != "%edx" or
            steps[6].raw != b"\x89\xc2" or
            steps[7].operands[1] != "%edx" or
            _imm(steps[7], "xorl", b"\x81\xf2") != salt or
            tuple(item.raw for item in steps[8:19]) != (
                b"\x41\x89\xd0", b"\x41\xc1\xe8\x10", b"\x44\x31\xc2",
                b"\x69\xd2\x2d\x35\xeb\x7f", b"\x41\x89\xd0",
                b"\x41\xc1\xe8\x0f", b"\x44\x31\xc2",
                b"\x69\xd2\x8b\xa6\x6c\x84", b"\x41\x89\xd0",
                b"\x41\xc1\xe8\x10", b"\x44\x31\xc2")):
        _invalid("binding transition mask differs from the registered encoder")
    tail = instructions[index + 20:index + 23]
    if (len(tail) != 3 or tuple(item.raw for item in tail[:2]) !=
            (b"\x31\xd1", b"\x01\xc8") or tail[2].opcode != "movl" or
            len(tail[2].operands) != 2 or
            tail[2].operands[0] != "%eax" or not STACK.fullmatch(tail[2].operands[1]) or
            _stack(tail[2].operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0)) != state_slot):
        _invalid("binding transition does not write the dispatcher state")
    outcome = {}
    for result in (0, 1):
        selected = (nonzero_code if result else zero_code)
        if (steps[5].opcode == "cmovel") == (result == 0):
            selected = nonzero_code
        else:
            selected = zero_code
        outcome[result] = (current + (selected ^ _mask(current, salt))) & MASK32
    return outcome, tail[-1].address + len(tail[-1].raw)


def _dispatcher(instructions, root, state_slot, frame, entry_slots, state):
    by_address = {item.address: item for item in instructions}
    address, eax, temporary, comparison = root, None, None, None
    seen = set()
    for _ in range(32):
        if address in seen or address not in by_address:
            _invalid("binding dispatcher cycles or leaves its interval")
        seen.add(address)
        item = by_address[address]
        following = address + len(item.raw)
        if comparison is not None and item.opcode != "jae":
            _invalid("binding dispatcher comparison is not adjacent to its branch")
        if item.opcode == "movl" and len(item.operands) == 2 and item.operands[1] == "%eax":
            slot = _stack(item.operands[0], State(-frame, {}, {}, {}, {}, {}, {}, 0))
            if slot == state_slot:
                eax = state
            elif temporary is not None and slot == temporary:
                eax = state
            else:
                _invalid("binding dispatcher reads an unknown state slot")
        elif item.opcode == "movl" and len(item.operands) == 2 and item.operands[0] == "%eax":
            slot = _stack(item.operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0))
            if (eax != state or not _within_frame(slot, 4, frame) or
                    _overlaps(slot, 4, state_slot, 4) or
                    any(_overlaps(slot, 4, prior, 8) for prior in entry_slots)):
                _invalid("binding dispatcher has an unknown copied state")
            temporary = slot
        elif (item.opcode == "cmpl" and len(item.operands) == 2 and
              item.operands[1] == "%eax" and eax == state):
            comparison = _imm(item, "cmpl", b"\x3d")
        elif item.opcode == "jae" and comparison is not None:
            target, _ = _target(item, "branch")
            address = target if state >= comparison else following
            comparison = None
            continue
        elif item.opcode in ("jmp", "jmpq"):
            target, _ = _target(item, "branch")
            if target >= root:
                _invalid("binding dispatcher leaf does not precede its root")
            return target, seen
        else:
            _invalid("binding dispatcher has an unsupported instruction")
        address = following
    _invalid("binding dispatcher exceeds its instruction budget")


def _entry_identities(instructions, frame, state_slot):
    slots = {}
    for item, register, identity in ((instructions[1], "%rdx", "lease"),
                                     (instructions[2], "%rcx", "scope")):
        if (item.opcode != "movq" or len(item.operands) != 2 or
                item.operands[0] != register or
                not STACK.fullmatch(item.operands[1])):
            _invalid("binding entry does not spill distinct Scope and lease arguments")
        slot = _stack(item.operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0))
        if (not _within_frame(slot, 8, frame) or slot in slots or
                _overlaps(slot, 8, state_slot, 4) or
                any(_overlaps(slot, 8, prior, 8) for prior in slots)):
            _invalid("binding entry argument spills alias each other or dispatcher state")
        slots[slot] = identity
    return slots


def verify_builder_local_callees(object_bytes: bytes, image_bytes: bytes,
                                report_bytes: bytes, cff_seed: int,
                                mixed_helpers: dict[str, str],
                                local_codes: dict[str, str]) -> dict:
    """Bind exact local code to a two-outcome status-to-dispatch route."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(cff_seed) is not int or not 0 <= cff_seed <= MASK32 or
            type(mixed_helpers) is not dict or set(mixed_helpers) != {OWNED, MEASURED} or
            type(local_codes) is not dict or set(local_codes) != set(LOCAL_CALLEES) or
            any(type(code) is not str or not code for code in
                (*mixed_helpers.values(), *local_codes.values()))):
        _invalid("exact object, image, seed and four linked disassemblies are required")
    image = parse_image(image_bytes)
    local = _subjects(object_bytes, image_bytes, image)
    cfg_seed = _report_seed(report_bytes, cff_seed)
    salt, states = _layout(cfg_seed, REQUIRE_BINDING)
    instructions = _instructions(local_codes[REQUIRE_BINDING], image_bytes,
                                 REQUIRE_BINDING.lower())
    status_instructions = _instructions(local_codes[BINDING_STATUS], image_bytes,
                                        BINDING_STATUS.lower())
    if (instructions[0].address != image.preferred_base + local[REQUIRE_BINDING].rva or
            status_instructions[0].address != image.preferred_base + local[BINDING_STATUS].rva):
        _invalid("local disassembly does not start at its exact COFF/PE subject")
    _, graph, calls = _graph(instructions)
    frame, _ = _entry_spills(instructions, image_bytes)
    _check_plain_unwind(image_bytes, image, local[REQUIRE_BINDING], instructions[0], frame)
    state_slot = _dispatcher_state(instructions, graph, frame)
    if (frame < 0x28 or frame % 16 != 8 or
            not _within_frame(state_slot, 4, frame) or
            state_slot < -frame + 0x20):
        _invalid("binding dispatcher state or outgoing call area leaves its fixed frame")
    if _actual_state(image_bytes, local_codes[REQUIRE_BINDING], REQUIRE_BINDING.lower()) != states[0]:
        _invalid("binding entry state differs from independent layout")
    direct_calls = [(item, DIRECT.fullmatch(item.operands[0])) for item in calls]
    if any(match is None for _, match in direct_calls):
        _invalid("binding function has an unsupported call target")
    status_calls = [item for item, match in direct_calls if match[2] == BINDING_STATUS.lower()]
    failure_calls = [item for item, match in direct_calls if match[2] == FAILURE]
    if len(calls) != 2 or len(status_calls) != 1 or len(failure_calls) != 1:
        _invalid("binding function lacks its exact status and failure calls")
    status_call, failure_call = status_calls[0], failure_calls[0]
    if _target(status_call, "call")[0] != image.preferred_base + local[BINDING_STATUS].rva:
        _invalid("binding status call misses the exact local callee")
    binding_address = image.preferred_base + local[REQUIRE_BINDING].rva
    helper_routes = {name: _check_route(_instructions(mixed_helpers[name], image_bytes, name), name)
                     for name in (OWNED, MEASURED)}
    if {route["binding"] for route in helper_routes.values()} != {binding_address}:
        _invalid("mixed helper calls miss the exact binding callee")
    if {_target(failure_call, "call")[0]} != {route["failure"] for route in helper_routes.values()}:
        _invalid("local failure call differs from the mixed helper failure target")
    index = instructions.index(status_call)
    result, after_store = _update(instructions, status_call, state_slot, frame, states[0], salt)
    first_branch = next((item for item in instructions if item.opcode in ("jmp", "jmpq", "jae")), None)
    if first_branch is None or instructions.index(first_branch) != 4 or tuple(
            item.opcode for item in instructions[:5]) not in (
                ("subq", "movq", "movq", "movl", "jmp"),
                ("subq", "movq", "movq", "movl", "jmpq")):
        _invalid("binding entry has an unsupported frame and dispatcher shape")
    root, _ = _target(first_branch, "branch")
    following = next((item for item in instructions if item.address == after_store), None)
    if following is None or (after_store != root and
            (following.opcode not in ("jmp", "jmpq") or
             _target(following, "branch")[0] != root)):
        _invalid("binding update does not return to its entry dispatcher")
    if result[0] == result[1] or set(result.values()) != set(states[1:]):
        _invalid("zero/nonzero status fails to select distinct frozen body states")
    entry_slots = _entry_identities(instructions, frame, state_slot)
    dispatch = {value: _dispatcher(instructions, root, state_slot, frame,
                                   entry_slots, value)
                for value in states}
    leaves = {value: result[0] for value, result in dispatch.items()}
    if leaves[states[0]] > status_call.address or leaves[states[0]] < first_branch.address:
        _invalid("initial state does not enter the binding status body")
    failure_index = instructions.index(failure_call)
    if failure_index == 0 or instructions[failure_index - 1].raw != b"\xb9\x02\x07\x00\x00":
        _invalid("failure leaf lacks the expected reason code")
    failure_leaf = instructions[failure_index - 1].address
    returns = [index for index, item in enumerate(instructions) if item.opcode in ("ret", "retq")]
    if len(returns) != 1 or returns[0] == 0:
        _invalid("binding function lacks one normal return")
    before_return = instructions[returns[0] - 1]
    if (before_return.opcode != "addq" or before_return.operands != (f"$0x{frame:x}", "%rsp") or
            before_return.raw[:3] != b"\x48\x83\xc4"):
        _invalid("normal leaf has an unsupported frame return")
    if leaves[result[0]] != before_return.address or leaves[result[1]] != failure_leaf:
        _invalid("binding status does not dispatch zero to return and nonzero to failure")
    by_address = {item.address: item for item in instructions}
    slots = entry_slots.copy()
    registers = {"%rcx": "scope", "%rdx": "lease"}
    body = set()
    cursor = leaves[states[0]]
    while cursor != status_call.address:
        item = by_address.get(cursor)
        if (item is None or item.opcode != "movq" or len(item.operands) != 2 or
                len(body) >= 16):
            _invalid("binding status call has an unsupported pre-call route")
        source, destination = item.operands
        if (source not in ("%rax", "%rcx", "%rdx") and not STACK.fullmatch(source) or
                destination not in ("%rax", "%rcx", "%rdx") and
                not STACK.fullmatch(destination)):
            _invalid("binding pre-call copy accesses unmodelled memory or registers")
        source_slot = _stack(source, State(-frame, {}, {}, {}, {}, {}, {}, 0))
        if source_slot is not None and not _within_frame(source_slot, 8, frame):
            _invalid("binding pre-call copy leaves its fixed frame")
        identity = slots.get(source_slot) if source_slot is not None else registers.get(source)
        if identity not in ("scope", "lease"):
            _invalid("binding pre-call copy reads an unknown Scope or lease identity")
        slot = _stack(destination, State(-frame, {}, {}, {}, {}, {}, {}, 0))
        if slot is not None and not _within_frame(slot, 8, frame):
            _invalid("binding pre-call copy leaves its fixed frame")
        if (destination == "%rsp" or
                slot is not None and slot < state_slot + 4 and state_slot < slot + 8):
            _invalid("binding pre-call copy overwrites dispatcher state")
        if slot is not None:
            if (slot in entry_slots or
                    slot in slots and slots[slot] != identity or
                    any(_overlaps(slot, 8, prior, 8) for prior in slots if prior != slot)):
                _invalid("binding pre-call copy aliases a protected argument spill")
            slots[slot] = identity
        else:
            registers[destination] = identity
        body.add(cursor)
        cursor += len(item.raw)
    if registers.get("%rcx") != "scope" or registers.get("%rdx") != "lease":
        _invalid("binding status call lost its entry Scope or lease identity")
    cursor = status_call.address
    while cursor != after_store:
        item = by_address.get(cursor)
        if item is None or len(body) >= 48:
            _invalid("binding status update has an incomplete linear route")
        body.add(cursor)
        cursor += len(item.raw)
    if after_store != root:
        body.add(after_store)
    covered = ({item.address for item in instructions[:5]} | body |
               {failure_leaf, failure_call.address, before_return.address,
                instructions[returns[0]].address} |
               set().union(*(result[1] for result in dispatch.values())))
    if covered != set(by_address):
        _invalid("binding function contains unmodelled machine instructions")
    return {"verified": True, "scope": "mixed-post-local-binding-route-v1",
            "cfg_seed": cfg_seed, "entry_state": states[0],
            "status_zero_state": result[0], "status_nonzero_state": result[1],
            "subjects": [{"symbol": name, "rva": local[name].rva, "size": local[name].size}
                         for name in LOCAL_CALLEES],
            "local_status_route_verified": True}
