"""Bind mixed helper entry references to the exact local binding call."""

from collections import deque
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_entry_states import _decoded_immediate
from cff_builder_local_callees import BINDING_STATUS, REQUIRE_BINDING, _dispatcher
from cff_joint_machine_evidence import (DIRECT, MEASURED, OWNED, STACK,
                                        _instructions, _register, _stack, State)
from cff_source_mixed_helper_routes import FAILURE, _target
from function_subject import function_subject
from pe_layout import data_directory, parse_image, read_rva


_LOCAL = (REQUIRE_BINDING, BINDING_STATUS)
_INTEGER = {"addl", "subl", "xorl", "orl", "imull", "shll", "shrl",
            "cmovel", "cmovll", "cmovnel"}
_BRANCH = {"jmp", "jmpq", "jae", "je", "jne"}
_PASS_THROUGH = {"ret", "retq", "int3", "nop", "nopl", "nopw"} | _BRANCH


def _invalid(reason):
    raise ValueError(f"helper arguments: {reason}")


def _overlap(left, left_width, right, right_width):
    return left < right + right_width and right < left + left_width


def _frame(instructions, image_bytes):
    if len(instructions) < 2:
        _invalid("helper lacks a fixed-frame prologue")
    pushed = instructions[0].opcode == "pushq"
    first = instructions[1] if pushed else instructions[0]
    if (pushed and (instructions[0].raw != b"\x56" or
                    instructions[0].operands != ("%rsi",)) or
            first.opcode != "subq" or len(first.operands) != 2 or
            first.operands[1] != "%rsp" or not first.operands[0].startswith("$")):
        _invalid("unsupported fixed-frame prologue")
    allocation = int(first.operands[0][1:], 0)
    if not 0 < allocation <= 4096 - (8 if pushed else 0) or allocation % 8:
        _invalid("invalid fixed-frame allocation")
    if (first.raw != (b"\x48\x83\xec" + bytes((allocation,)) if allocation <= 127 else
                     b"\x48\x81\xec" + struct.pack("<I", allocation))):
        _invalid("frame allocation text differs from PE bytes")
    frame = allocation + (8 if pushed else 0)
    image = parse_image(image_bytes)
    rva = instructions[0].address - image.preferred_base
    directory, size = data_directory(image, 3)
    entries = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    unwind = next((item[2] for item in entries if item[0] == rva), None)
    if unwind is None:
        _invalid("fixed frame has no exact PE unwind record")
    header = read_rva(image_bytes, image, unwind, 4)
    prologue_end = first.address + len(first.raw) - instructions[0].address
    if header[0] != 1 or header[1] != prologue_end or header[3] != 0:
        _invalid("fixed frame disagrees with PE unwind header")
    if allocation <= 128:
        codes = bytes((prologue_end, 2 | ((allocation // 8 - 1) << 4)))
    else:
        codes = bytes((prologue_end, 1)) + struct.pack("<H", allocation // 8)
    if pushed:
        codes += bytes((len(instructions[0].raw), 0x60))
    if header[2] * 2 != len(codes) or read_rva(image_bytes, image, unwind + 4, len(codes)) != codes:
        _invalid("fixed frame disagrees with PE unwind codes")
    return frame, pushed


def _source(operand, state, width, frame):
    register = _register(operand)
    if register is not None:
        if register == "rsp" or not operand.startswith("%"):
            _invalid("unmodelled source register")
        return state[1].get(register) if width == 8 and operand[1:] == register else None
    slot = _stack(operand, State(state[0], {}, {}, {}, {}, {}, {}, 0))
    if slot is not None:
        if not (-frame <= slot and slot + width <= 0 or
                slot in (0x28, 0x30, 0x38, 0x40)):
            _invalid("stack read leaves fixed frame and incoming argument slots")
        return state[2].get(slot) if width == 8 else None
    if operand.startswith("$") and width == 4:
        return None
    _invalid("unmodelled source operand")


def _write(operand, state, value, width, frame, pushed):
    rsp, registers, slots, saved = state
    register = _register(operand)
    if register is not None:
        if register == "rsp":
            _invalid("unmodelled stack pointer write")
        if width == 8 and operand[1:] == register and value is not None:
            registers[register] = value
        else:
            registers.pop(register, None)
        return
    slot = _stack(operand, State(rsp, {}, {}, {}, {}, {}, {}, 0))
    top = -8 if pushed else 0
    if slot is None or slot < -frame or slot + width > top:
        _invalid("stack write leaves fixed allocation or aliases saved RSI")
    if any(_overlap(slot, width, prior, 8) for prior in slots):
        _invalid("stack write aliases an established entry reference")
    if width == 8 and value is not None:
        slots[slot] = value


def _step(item, state, frame, pushed, entry, binding):
    rsp, registers, slots, saved = state
    state = (rsp, registers.copy(), slots.copy(), saved)
    rsp, registers, slots, saved = state
    op, args = item.opcode, item.operands
    if op == "pushq":
        if item.address != entry or args != ("%rsi",) or rsp != 0 or saved:
            _invalid("non-entry saved-register push")
        return (-8, registers, slots, True)
    if op == "subq":
        if (item.address != entry + (1 if pushed else 0) or rsp != (-8 if pushed else 0) or
                len(args) != 2 or args[1] != "%rsp" or
                int(args[0][1:], 0) != frame - (8 if pushed else 0)):
            _invalid("non-entry frame allocation")
        return (-frame, registers, slots, saved)
    if op in ("addq", "popq"):
        if op == "addq":
            if (rsp != -frame or args != (f"$0x{frame - (8 if pushed else 0):x}", "%rsp")):
                _invalid("unbalanced frame epilogue")
            return (-8 if pushed else 0, registers, slots, saved)
        if args != ("%rsi",) or not saved or rsp != -8:
            _invalid("unbalanced saved-register epilogue")
        registers.pop("rsi", None)
        return (0, registers, slots, False)
    if op in _PASS_THROUGH:
        if op in ("ret", "retq") and (rsp != 0 or saved):
            _invalid("unbalanced helper return")
        return state
    if rsp != -frame:
        _invalid("helper operation has an unstable frame")
    if op in ("call", "callq"):
        target, symbol = _target(item, "call")
        if item.address == binding:
            if symbol != REQUIRE_BINDING.lower() or registers.get("rcx") != "scope" or registers.get("rdx") != "lease":
                _invalid("binding call lost entry Scope or lease identity")
            return state
        if symbol != FAILURE:
            _invalid("unsupported call precedes binding")
        for register in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
            registers.pop(register, None)
        for slot in list(slots):
            if -frame <= slot < -frame + 0x20:
                del slots[slot]
        return state
    if op == "movq":
        if len(args) != 2:
            _invalid("malformed pointer copy")
        value = _source(args[0], state, 8, frame)
        _write(args[1], state, value, 8, frame, pushed)
        return state
    if op == "movl":
        if len(args) != 2:
            _invalid("malformed integer copy")
        _source(args[0], state, 4, frame)
        _write(args[1], state, None, 4, frame, pushed)
        return state
    if op in _INTEGER:
        if len(args) not in (2, 3) or _register(args[-1]) is None:
            _invalid("unmodelled integer operation")
        for operand in args[:-1]:
            _source(operand, state, 4, frame)
        _write(args[-1], state, None, 4, frame, pushed)
        return state
    if op in ("cmpl", "cmpq"):
        if len(args) != 2:
            _invalid("malformed comparison")
        for operand in args:
            _source(operand, state, 4 if op == "cmpl" else 8, frame)
        return state
    _invalid(f"unsupported pre-binding instruction {op}")


def _initial(name):
    return (0, {"rcx": "lease" if name == OWNED else "scope"},
            {0x40: "scope" if name == OWNED else "lease"}, False)


def _normal_entry(instructions, frame, pushed, binding):
    first_branch = next((item for item in instructions if item.opcode in ("jmp", "jmpq")), None)
    if first_branch is None or first_branch.address >= binding[1]:
        _invalid("entry lacks a direct pre-binding dispatcher jump")
    prefix = instructions[:instructions.index(first_branch)]
    if (not prefix or any(item.opcode in _BRANCH or
                          item.opcode in ("call", "callq", "ret", "retq", "int3")
                          for item in prefix)):
        _invalid("entry prefix has an earlier control transfer")
    preceding = prefix[-1]
    initializers = [item for item in instructions if item.address < first_branch.address and
                    item.opcode == "movl" and len(item.operands) == 2 and
                    item.operands[0].startswith("$") and STACK.fullmatch(item.operands[1])]
    if (len(initializers) != 1 or initializers[0] != preceding or
            preceding.address + len(preceding.raw) != first_branch.address):
        _invalid("entry state initializer is not unique and adjacent to dispatcher jump")
    state_slot = _stack(preceding.operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0))
    if (state_slot is None or state_slot < -frame + 0x20 or
            state_slot + 4 > (-8 if pushed else 0)):
        _invalid("entry state leaves its fixed non-shadow frame")
    observed = _decoded_immediate(preceding)
    entry = instructions[0].address
    current = _initial(binding[0])
    for item in (*prefix, first_branch):
        current = _step(item, current, frame, pushed, entry, binding[1])
    if (current[0] != -frame or
            any(_overlap(state_slot, 4, slot, 8) for slot in current[2])):
        _invalid("entry state aliases a captured argument")
    root, _ = _target(first_branch, "branch")
    try:
        leaf, _ = _dispatcher(instructions, root, state_slot, frame, current[2], observed)
    except ValueError as error:
        raise ValueError(f"helper arguments: entry dispatcher differs: {error}") from error
    by_address = {item.address: item for item in instructions}
    cursor = leaf
    for _ in range(64):
        if cursor == binding[1]:
            return observed, leaf
        item = by_address.get(cursor)
        if (item is None or item.opcode in _BRANCH or
                item.opcode in ("call", "callq", "ret", "retq", "int3")):
            _invalid("normal entry state does not reach the binding body")
        cursor += len(item.raw)
    _invalid("normal binding body exceeds its bounded instruction budget")


def _route(instructions, frame, pushed, binding):
    by_address = {item.address: item for item in instructions}
    if len(by_address) != len(instructions):
        _invalid("duplicate instruction address")
    entry = instructions[0].address
    initial = _initial(binding[0])
    pending = deque(((entry, initial),))
    seen = {}
    reached = False
    while pending:
        address, state = pending.popleft()
        if address not in by_address:
            _invalid("pre-binding route leaves exact unwind interval")
        if address in seen:
            previous = seen[address]
            if previous[0] != state[0] or previous[3] != state[3]:
                _invalid("ambiguous pre-binding frame merge")
            state = (state[0],
                     {key: value for key, value in previous[1].items()
                      if state[1].get(key) == value},
                     {key: value for key, value in previous[2].items()
                      if state[2].get(key) == value}, state[3])
            if state == previous:
                continue
        if len(seen) >= 4096:
            _invalid("pre-binding route exceeds bounded instruction budget")
        seen[address] = state
        item = by_address[address]
        next_state = _step(item, state, frame, pushed, entry, binding[1])
        if address == binding[1]:
            reached = True
            continue
        if item.opcode in ("ret", "retq", "int3"):
            continue
        following = address + len(item.raw)
        targets = [following]
        if item.opcode in _BRANCH:
            target, _ = _target(item, "branch")
            targets = [target] if item.opcode in ("jmp", "jmpq") else [target, following]
        for target in targets:
            if target not in by_address:
                _invalid("pre-binding branch enters unknown instruction")
            pending.append((target, next_state))
    if not reached:
        _invalid("entry cannot reach the exact binding call")
    return len(seen)


def verify_builder_helper_arguments(object_bytes: bytes, image_bytes: bytes,
                                    mixed_helpers: dict[str, str],
                                    local_callee_proof: dict) -> dict:
    """Prove only the first acquisition call's two argument identities."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(mixed_helpers) is not dict or set(mixed_helpers) != {OWNED, MEASURED} or
            any(type(code) is not str or not code for code in mixed_helpers.values())):
        _invalid("exact object, image and two helper disassemblies are required")
    image = parse_image(image_bytes)
    local = {}
    for index, name in enumerate(_LOCAL):
        subject = function_subject(object_bytes, image_bytes, image, 0xb600 + index, name)
        if subject.kind != "function-contribution" or len(subject.ranges) != 1:
            _invalid("local binding has an unsupported subject")
        local[name] = subject.ranges[0]
    expected_local = [{"symbol": name, "rva": local[name].rva, "size": local[name].size}
                      for name in _LOCAL]
    if (type(local_callee_proof) is not dict or local_callee_proof.get("verified") is not True or
            local_callee_proof.get("scope") != "mixed-post-local-binding-route-v1" or
            local_callee_proof.get("local_status_route_verified") is not True or
            local_callee_proof.get("subjects") != expected_local):
        _invalid("local callee proof does not bind this exact object and image")
    subjects = []
    for index, name in enumerate((OWNED, MEASURED)):
        subject = function_subject(object_bytes, image_bytes, image, 0xb610 + index, name)
        if subject.kind != "function-contribution" or len(subject.ranges) != 1:
            _invalid("helper has an unsupported COFF/PE subject")
        span = subject.ranges[0]
        instructions = _instructions(mixed_helpers[name], image_bytes, name)
        if (instructions[0].address != image.preferred_base + span.rva or
                instructions[-1].address + len(instructions[-1].raw) >
                image.preferred_base + span.rva + span.size):
            _invalid("helper disassembly leaves exact COFF/PE subject")
        calls = [item for item in instructions if item.opcode in ("call", "callq") and
                 len(item.operands) == 1 and
                 (match := DIRECT.fullmatch(item.operands[0])) is not None and
                 match[2] == REQUIRE_BINDING.lower()]
        if len(calls) != 1 or _target(calls[0], "call")[0] != image.preferred_base + local[REQUIRE_BINDING].rva:
            _invalid("helper misses the exact local binding call")
        frame, pushed = _frame(instructions, image_bytes)
        entry_state, normal_leaf = _normal_entry(instructions, frame, pushed,
                                                 (name, calls[0].address))
        visited = _route(instructions, frame, pushed, (name, calls[0].address))
        subjects.append({"symbol": name, "rva": span.rva, "size": span.size,
                         "binding_call_rva": calls[0].address - image.preferred_base,
                         "entry_state": entry_state,
                         "normal_binding_leaf_rva": normal_leaf - image.preferred_base,
                         "pre_binding_instructions": visited})
    return {"verified": True, "scope": "mixed-post-observed-entry-binding-arguments-v1",
            "subjects": subjects, "observed_entry_binding_arguments_verified": True}
