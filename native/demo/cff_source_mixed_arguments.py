"""Check schema4 helper identity arguments against a fixed private policy."""

from collections import deque
from dataclasses import dataclass

from cff_joint_machine_evidence import (ALIASES, DIRECT, MEASURED, OWNED, REGISTERS,
                                        STACK, _graph, _instructions)


MASK = 0xffffffff
WORD_ALIASES = {name for name in ALIASES if name not in REGISTERS and
                (name.startswith("e") or name.endswith("d"))}
EXPECTED_REGISTERS = (("rdx", "routing_tag"), ("r8", "domain"),
                      ("r9", "owner_id"))


def _fail(reason):
    raise ValueError(f"source-mixed private arguments: {reason}")


@dataclass
class Constants:
    registers: dict[str, int]
    stack: dict[int, int]

    def copy(self):
        return Constants(self.registers.copy(), self.stack.copy())


def _register(operand, width):
    if not operand.startswith("%"):
        return None
    alias = operand[1:]
    if alias not in ALIASES or alias not in (WORD_ALIASES if width == 4 else REGISTERS):
        _fail(f"unsupported {width * 8}-bit register alias {operand}")
    return ALIASES[alias]


def _slot(operand):
    match = STACK.fullmatch(operand)
    if match is None:
        return None
    return int(match[1], 0) if match[1] else 0


def _read(operand, state):
    if operand.startswith("$"):
        return int(operand[1:], 0) & MASK
    register = _register(operand, 4)
    if register is not None:
        return state.registers.get(register)
    slot = _slot(operand)
    return state.stack.get(slot) if slot is not None else None


def _write(operand, state, width, value=None):
    register = _register(operand, width)
    if register is not None:
        state.registers.pop(register, None)
        if width == 4 and value is not None:
            state.registers[register] = value & MASK
        return
    slot = _slot(operand)
    if slot is None:
        # A write through an unknown pointer may alias any tracked stack slot.
        state.stack.clear()
        return
    for old in list(state.stack):
        if slot < old + 4 and old < slot + width:
            del state.stack[old]
    if width == 4 and value is not None:
        state.stack[slot] = value & MASK


def _arithmetic(opcode, operands, state):
    destination = operands[-1]
    left = _read(operands[1] if opcode == "imull" and len(operands) == 3 else
                 destination, state)
    right = _read(operands[0], state)
    value = None
    if opcode in ("xorl", "subl") and operands[0] == destination:
        value = 0
    elif opcode == "orl" and right == MASK:
        value = MASK
    elif opcode == "imull" and right == 0:
        value = 0
    elif left is not None and right is not None:
        if opcode == "addl": value = left + right
        elif opcode == "subl": value = left - right
        elif opcode == "xorl": value = left ^ right
        elif opcode == "orl": value = left | right
        elif opcode == "imull": value = left * right
        elif opcode == "shll": value = left << (right & 31)
        elif opcode == "shrl": value = left >> (right & 31)
    _write(destination, state, 4, value)


def _transfer(item, incoming):
    state = incoming.copy()
    opcode, operands = item.opcode, item.operands
    if opcode in ("call", "callq"):
        # Do not borrow any value across an unproved helper or other call.
        state.registers.clear()
        state.stack.clear()
    elif opcode == "movl":
        _write(operands[1], state, 4, _read(operands[0], state))
    elif opcode in ("movq", "leaq"):
        _write(operands[1], state, 8)
    elif opcode in ("addl", "subl", "xorl", "orl", "imull", "shll", "shrl"):
        _arithmetic(opcode, operands, state)
    elif opcode in ("cmovel", "cmovll", "cmovnel"):
        # A conditional value without proved flags cannot establish a constant.
        _write(operands[1], state, 4)
    elif opcode in ("subq", "addq"):
        if operands[-1] == "%rsp":
            state.stack.clear()
        else:
            _write(operands[-1], state, 8)
    elif opcode in ("pushq", "popq"):
        # Exact prologue/epilogue and PE unwind are checked by the site map.
        state.stack.clear()
        if opcode == "popq": _write(operands[0], state, 8)
    elif opcode not in ("cmpl", "cmpq", "jae", "jmp", "jmpq", "ret", "retq",
                        "nop", "nopl", "nopw"):
        _fail(f"unsupported machine instruction {opcode}")
    return state


def _join(before, incoming):
    return Constants({key: value for key, value in before.registers.items()
                      if incoming.registers.get(key) == value},
                     {key: value for key, value in before.stack.items()
                      if incoming.stack.get(key) == value})


def _states(instructions, graph):
    by_address = {item.address: item for item in instructions}
    states = {instructions[0].address: Constants({}, {})}
    pending = deque((instructions[0].address,))
    while pending:
        address = pending.popleft()
        outgoing = _transfer(by_address[address], states[address])
        for successor in graph[address]:
            before = states.get(successor)
            merged = outgoing if before is None else _join(before, outgoing)
            if before != merged:
                states[successor] = merged
                pending.append(successor)
    return states


def check_private_arguments(image_bytes, code, row, identity):
    if row.get("function") != identity.owner:
        _fail("selected owner differs from fixed private policy")
    instructions = _instructions(code, image_bytes, identity.owner)
    _, graph, callers = _graph(instructions, allow_indirect=True)
    states = _states(instructions, graph)
    helpers = [item for item in callers if DIRECT.fullmatch(item.operands[0])[2]
               in (OWNED, MEASURED)]
    if len(helpers) != row["runtime_contribution"].get("query_count"):
        _fail("helper count differs from fixed private policy")
    for item in helpers:
        state = states.get(item.address)
        if state is None:
            _fail(f"unreachable helper call at {item.address:x}")
        for register, field in EXPECTED_REGISTERS:
            if state.registers.get(register) != getattr(identity, field):
                _fail(f"helper {field} at {item.address:x} is missing, ambiguous or differs from private policy")
