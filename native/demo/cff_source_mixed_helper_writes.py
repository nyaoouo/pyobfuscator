"""Bounded direct stack-write proof for two linked schema4 query helpers."""

from collections import deque
import re

from cff_joint_machine_evidence import (CALLER_SAVED, DIRECT, MEASURED, OWNED,
                                        _instructions, _register)


MEMORY = re.compile(r"^(-?0x[0-9a-f]+|-?\d+)?\(%([a-z][a-z0-9]*)\)$")
IMMEDIATE = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
WRITES = {"movq": 8, "movl": 4, "addq": 8, "addl": 4,
          "subq": 8, "subl": 4, "xorl": 4, "orl": 4}
ORDINARY = {"movq", "movl", "leaq", "addq", "subq", "shrq",
            "testl", "cmpl", "nopl", "nop", "int3", "callq", "call",
            "pushq", "popq", "retq", "ret", "jne", "je", "jae", "jmp", "jmpq",
            "addl", "subl", "xorl", "orl", "imull", "shll", "shrl",
            "cmovel", "cmovnel", "cmovll", "cmpq", "testb", "movabsq",
            "andq", "setne", "sete", "orb"}


def _address(operand, rsp, aliases):
    match = MEMORY.fullmatch(operand)
    if match is None:
        return None
    base = match[2]
    origin = rsp if base == "rsp" else aliases.get(base)
    return None if origin is None else origin + (int(match[1], 0) if match[1] else 0)


def _immediate(operand):
    match = IMMEDIATE.fullmatch(operand)
    if match is None:
        raise ValueError("helper has an unknown stack adjustment")
    value = int(match[1], 0)
    if not 0 <= value <= 8192:
        raise ValueError("helper stack adjustment exceeds bounded scope")
    return value


def _check_instructions(instructions):
    by_address = {item.address: item for item in instructions}
    if len(by_address) != len(instructions) or not instructions:
        raise ValueError("helper instruction inventory is ambiguous")
    pending = deque(((instructions[0].address, 0, ()),))
    visited = {}
    returns = 0
    while pending:
        address, rsp, saved_aliases = pending.popleft()
        state = (rsp, saved_aliases)
        previous = visited.get(address)
        if previous is not None:
            if previous != state:
                raise ValueError("helper stack state has an ambiguous CFG merge")
            continue
        if len(visited) >= 256:
            raise ValueError("helper CFG exceeds bounded scope")
        visited[address] = state
        item = by_address.get(address)
        if item is None or item.opcode not in ORDINARY:
            raise ValueError("helper has an unsupported instruction or branch")
        opcode, operands = item.opcode, item.operands
        aliases = dict(saved_aliases)
        next_address = address + len(item.raw)
        if opcode == "pushq":
            if len(operands) != 1 or _register(operands[0]) in (None, "rsp"):
                raise ValueError("helper has an unsupported push")
            rsp -= 8
        elif opcode == "popq":
            if len(operands) != 1 or (destination := _register(operands[0])) in (None, "rsp"):
                raise ValueError("helper has an unsupported pop")
            aliases.pop(destination, None)
            rsp += 8
        elif opcode in ("subq", "addq") and len(operands) == 2 and operands[1] == "%rsp":
            amount = _immediate(operands[0])
            rsp += amount if opcode == "addq" else -amount
        elif opcode in WRITES:
            if len(operands) != 2:
                raise ValueError("helper has an unsupported direct write")
            destination = operands[1]
            if "(" in destination:
                location = _address(destination, rsp, aliases)
                if location is None:
                    raise ValueError("helper has an unproved direct memory write")
                if location + WRITES[opcode] > 0:
                    raise ValueError("helper directly writes caller or return stack")
                if location < rsp:
                    raise ValueError("helper writes below its reserved stack frame")
            elif (register := _register(destination)):
                if register == "rsp":
                    raise ValueError("helper has an unknown stack adjustment")
                if opcode == "movq":
                    source = _register(operands[0])
                    if source == "rsp":
                        aliases[register] = rsp
                    elif source in aliases:
                        aliases[register] = aliases[source]
                    else:
                        aliases.pop(register, None)
                elif opcode in ("addq", "subq") and register in aliases:
                    amount = _immediate(operands[0])
                    aliases[register] += amount if opcode == "addq" else -amount
                else:
                    aliases.pop(register, None)
            else:
                raise ValueError("helper has an unsupported direct write")
        elif opcode == "leaq":
            if len(operands) != 2 or (register := _register(operands[1])) is None:
                raise ValueError("helper has an unsupported address lowering")
            if register == "rsp":
                raise ValueError("helper has an unknown stack adjustment")
            origin = _address(operands[0], rsp, aliases)
            if origin is None:
                aliases.pop(register, None)
            else:
                aliases[register] = origin
        elif opcode == "shrq":
            if len(operands) != 2 or (register := _register(operands[1])) in (None, "rsp"):
                raise ValueError("helper has an unsupported shift")
            aliases.pop(register, None)
        elif opcode in ("imull", "shll", "shrl", "cmovel", "cmovnel", "cmovll",
                        "movabsq", "andq", "orb", "setne", "sete"):
            widths = (2, 3) if opcode == "imull" else (1,) if opcode in ("setne", "sete") else (2,)
            if (len(operands) not in widths or
                    (register := _register(operands[-1])) in (None, "rsp")):
                raise ValueError("helper has an unsupported register operation")
            aliases.pop(register, None)
        elif opcode in ("call", "callq"):
            if len(operands) != 1 or DIRECT.fullmatch(operands[0]) is None or rsp >= 0:
                raise ValueError("helper has an unsupported call or stack state")
            # Callee writes through passed pointers remain outside this direct-write proof.
            for register in CALLER_SAVED:
                aliases.pop(register, None)
        elif opcode in ("testl", "cmpl", "cmpq", "testb"):
            if len(operands) != 2:
                raise ValueError("helper has an unsupported comparison")
        elif opcode in ("ret", "retq"):
            if operands or rsp != 0:
                raise ValueError("helper returns with an unbalanced stack")
            returns += 1
            continue
        elif opcode == "int3":
            if operands:
                raise ValueError("helper has an unsupported trap")
            continue
        elif opcode in ("nop", "nopl"):
            pass
        elif opcode in ("jne", "je", "jae", "jmp", "jmpq"):
            if len(operands) != 1 or (match := DIRECT.fullmatch(operands[0])) is None:
                raise ValueError("helper has an indirect or malformed branch")
            branch = int(match[1], 16)
            if branch not in by_address:
                raise ValueError("helper branch leaves its unwind interval")
            pending.append((branch, rsp, tuple(sorted(aliases.items()))))
            if opcode in ("jmp", "jmpq"):
                continue
        if not -8192 <= rsp <= 0:
            raise ValueError("helper stack depth exceeds bounded scope")
        if next_address not in by_address:
            raise ValueError("helper falls outside its unwind interval")
        pending.append((next_address, rsp, tuple(sorted(aliases.items()))))
    if not returns:
        raise ValueError("helper has no balanced return")
    if any(item.address not in visited and item.opcode not in
           ("int3", "nop", "nopl", "nopw") for item in instructions):
        raise ValueError("helper contains unvisited executable instructions")


def check_helper_direct_writes(image_bytes, helper_codes):
    if not isinstance(helper_codes, dict) or set(helper_codes) != {OWNED, MEASURED}:
        raise ValueError("two helper disassemblies are required")
    for name in (OWNED, MEASURED):
        instructions = _instructions(helper_codes[name], image_bytes, name)
        _check_instructions(instructions)
