"""Bounded Windows x64 caller-side provenance for one schema4 joint site."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from code_subject import unwind_interval
from pe_layout import data_directory, parse_image, read_rva


OWNED = "pyobf_native_mixed_owned_contribution_word_v1"
MEASURED = "pyobf_native_mixed_measured_contribution_word_v1"
LINE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?: [0-9a-f]{2})*)\s*\t([a-z][a-z0-9]*)\t?(.*)$")
HEADER = re.compile(r"^\s*([0-9a-f]+) <([^>]+)>:$")
STACK = re.compile(r"^(0x[0-9a-f]+|-?\d+)?\(%rsp\)$")
REGISTER = re.compile(r"^%([a-z][a-z0-9]*)$")
DIRECT = re.compile(r"^(0x[0-9a-f]+)(?: <([^>]+)>)?$")
REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
ALIASES = {name: name for name in REGISTERS}
ALIASES.update({"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"})
for number in range(8, 16): ALIASES[f"r{number}d"] = f"r{number}"
for low, full in (("al", "rax"), ("ax", "rax"), ("cl", "rcx"), ("cx", "rcx"),
                  ("dl", "rdx"), ("dx", "rdx"), ("bl", "rbx"), ("bx", "rbx")):
    ALIASES[low] = full
for number in range(8, 16):
    ALIASES[f"r{number}b"] = ALIASES[f"r{number}w"] = f"r{number}"
CALLER_SAVED = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
ALLOWED = {"retq", "ret", "jmp", "jmpq", "jae", "nop", "nopl", "nopw",
           "call", "callq", "pushq", "popq", "subq", "addq", "movq", "leaq", "movl", "addl",
           "subl", "xorl", "orl", "imull", "shll", "shrl", "cmovel",
           "cmovll", "cmovnel", "cmpl", "cmpq"}


@dataclass(frozen=True)
class Instruction:
    address: int
    raw: bytes
    opcode: str
    operands: tuple[str, ...]


@dataclass
class State:
    rsp: int
    registers: dict[str, str]
    slots: dict[int, str]
    words: dict[str, int]
    word_slots: dict[int, int]
    origins: dict[str, int]
    origin_slots: dict[int, int]
    spills: int
    saved_rsi: bool = False

    def copy(self):
        return State(self.rsp, self.registers.copy(), self.slots.copy(),
                     self.words.copy(), self.word_slots.copy(),
                     self.origins.copy(), self.origin_slots.copy(), self.spills, self.saved_rsi)


@dataclass(frozen=True)
class ReturnValue:
    identity: int
    dependencies: int
    constant: int | None


class ReturnExpressions:
    """Exact copy/constant identities along the branch-free joint return span."""

    def __init__(self):
        self.registers = {}
        self.slots = {}
        self.values = {}
        self.identities = {}
        self.keys = {}

    def intern(self, key, dependencies=0, constant=None):
        if key not in self.values:
            value = ReturnValue(len(self.values) + 1, dependencies, constant)
            self.values[key] = value
            self.identities[value.identity] = value
            self.keys[value.identity] = key
        return self.values[key]

    def read(self, operand, state):
        register = _register(operand)
        if register:
            return self.registers.get(register) or self.intern(("unknown-register", register))
        slot = _stack(operand, state)
        if slot is not None:
            return self.slots.get(slot) or self.intern(("unknown-slot", slot))
        if operand.startswith("$"):
            number = int(operand[1:], 0) & 0xffffffff
            return self.intern(("constant", number), constant=number)
        _fail(f"unsupported return expression operand {operand}")

    def write(self, operand, state, value, width):
        register = _register(operand)
        if register:
            self.registers.pop(register, None)
            if width == 4: self.registers[register] = value
            return
        slot = _stack(operand, state)
        if slot is None: _fail("return expression has an unmodelled write")
        for key in list(self.slots):
            if slot < key + 4 and key < slot + width: del self.slots[key]
        if width == 4: self.slots[slot] = value

    def binary(self, opcode, left, right):
        zero = self.intern(("constant", 0), constant=0)
        if opcode in ("xorl", "subl") and left.identity == right.identity:
            return zero
        if opcode == "subl":
            previous = self.keys[left.identity]
            if previous[0] == "addl":
                if previous[1] == right.identity: return self.identities[previous[2]]
                if previous[2] == right.identity: return self.identities[previous[1]]
        if opcode == "imull" and (left.constant == 0 or right.constant == 0):
            return zero
        if opcode == "orl" and (left.constant == 0xffffffff or right.constant == 0xffffffff):
            return self.intern(("constant", 0xffffffff), constant=0xffffffff)
        if right.constant == 0 and opcode in ("addl", "subl", "xorl", "orl"):
            return left
        if left.constant == 0 and opcode in ("addl", "xorl", "orl"):
            return right
        if opcode == "imull":
            if left.constant == 1: return right
            if right.constant == 1: return left
        if left.constant is not None and right.constant is not None:
            a, b = left.constant, right.constant
            result = {"addl": lambda: a + b, "subl": lambda: a - b,
                      "xorl": lambda: a ^ b, "orl": lambda: a | b,
                      "imull": lambda: a * b}[opcode]() & 0xffffffff
            return self.intern(("constant", result), constant=result)
        if opcode == "xorl":
            def atoms(value):
                if value.constant == 0: return set()
                key = self.keys[value.identity]
                return set(key[1]) if key[0] == "xor-terms" else {value.identity}
            terms = atoms(left) ^ atoms(right)
            if not terms: return zero
            if len(terms) == 1: return self.identities[next(iter(terms))]
            ordered = tuple(sorted(terms))
            bits = 0
            for term in ordered: bits |= self.identities[term].dependencies
            return self.intern(("xor-terms", ordered), bits)
        return self.intern((opcode, left.identity, right.identity),
                           left.dependencies | right.dependencies)

    def transfer(self, item, state):
        op, args = item.opcode, item.operands
        if op in ("call", "callq"):
            target = DIRECT.fullmatch(args[0])[2]
            for register in CALLER_SAVED: self.registers.pop(register, None)
            for slot in list(self.slots):
                if state.rsp <= slot < state.rsp + 0x40: del self.slots[slot]
            if target in (OWNED, MEASURED):
                bit = 1 if target == OWNED else 2
                self.registers["rax"] = self.intern(("helper-return", bit, item.address), bit)
        elif op == "movl":
            self.write(args[1], state, self.read(args[0], state), 4)
        elif op == "movq":
            self.write(args[1], state, None, 8)
        elif op in ("addl", "subl", "xorl", "orl", "imull"):
            if op == "imull":
                if (len(args) != 3 or not args[0].startswith("$") or
                        int(args[0][1:], 0) & 1 != 1):
                    _fail("joint return path needs an odd immediate multiplier")
                source = self.read(args[1], state)
                multiplier = self.read(args[0], state)
                result = self.binary(op, source, multiplier)
            else:
                result = self.binary(op, self.read(args[-1], state), self.read(args[0], state))
            self.write(args[-1], state, result, 4)
        elif op in ("shll", "shrl"):
            source, count = self.read(args[1], state), self.read(args[0], state)
            if count.constant is None: _fail("variable return-expression shift")
            shift = count.constant & 31
            if source.constant is not None:
                value = ((source.constant << shift) if op == "shll" else
                         (source.constant >> shift)) & 0xffffffff
                result = self.intern(("constant", value), constant=value)
            elif shift == 0:
                result = source
            else:
                result = self.intern((op, source.identity, shift), source.dependencies)
            self.write(args[1], state, result, 4)
        elif op in ("cmovel", "cmovll"):
            before, alternate = self.read(args[1], state), self.read(args[0], state)
            result = before if before.identity == alternate.identity else self.intern(
                (op, before.identity, alternate.identity),
                before.dependencies & alternate.dependencies)
            self.write(args[1], state, result, 4)
        elif op == "leaq":
            self.write(args[1], state, None, 8)
        elif op in ("cmpl", "nop", "nopl", "nopw"):
            return
        else:
            _fail(f"unsupported return-expression instruction {op}")


def _fail(message):
    raise ValueError(f"joint machine binding: {message}")


def _register(operand):
    match = REGISTER.fullmatch(operand)
    return ALIASES.get(match[1]) if match else None


def _stack(operand, state):
    match = STACK.fullmatch(operand)
    if match is None: return None
    offset = int(match[1], 0) if match[1] else 0
    return state.rsp + offset


def _source(operand, state, width):
    register = _register(operand)
    if register:
        return state.registers.get(register) if width == 8 and operand[1:] == register else None
    slot = _stack(operand, state)
    if slot is not None: return state.slots.get(slot) if width == 8 else None
    if operand.startswith("$"): return None
    if "(" in operand and operand.endswith(")"): return None
    _fail(f"unsupported source operand {operand}")


def _word(operand, state):
    register = _register(operand)
    if register: return state.words.get(register, 0)
    slot = _stack(operand, state)
    if slot is not None: return state.word_slots.get(slot, 0)
    if operand.startswith("$"): return 0
    if "(" in operand and operand.endswith(")"): return 0
    _fail(f"unsupported integer operand {operand}")


def _origin(operand, state):
    register = _register(operand)
    if register: return state.origins.get(register)
    slot = _stack(operand, state)
    if slot is not None: return state.origin_slots.get(slot, slot)
    if operand.startswith("$"): return None
    if "(" in operand and operand.endswith(")"): return None
    _fail(f"unsupported origin operand {operand}")


def _write(operand, state, value, width, protected, word=0, origin=None):
    register = _register(operand)
    if register:
        if register == "rsp": _fail("unmodelled stack-pointer write")
        if operand[1:] not in ALIASES: _fail("unknown register alias")
        if width == 8 and operand[1:] == register and value:
            state.registers[register] = value
        else:
            state.registers.pop(register, None)
        if width == 4 and word: state.words[register] = word
        else: state.words.pop(register, None)
        if width == 4 and origin is not None: state.origins[register] = origin
        else: state.origins.pop(register, None)
        return
    slot = _stack(operand, state)
    if slot is None: _fail(f"unmodelled memory write {operand}")
    if any(slot < start + 8 and start < slot + width for start in protected):
        _fail("immutable entry reference spill overwritten")
    for key in list(state.slots):
        if slot < key + 8 and key < slot + width: del state.slots[key]
    for key in list(state.word_slots):
        if slot < key + 4 and key < slot + width: del state.word_slots[key]
    for key in list(state.origin_slots):
        if slot < key + 4 and key < slot + width: del state.origin_slots[key]
    if width == 8 and value: state.slots[slot] = value
    if width == 4 and word: state.word_slots[slot] = word
    if width == 4: state.origin_slots[slot] = origin if origin is not None else slot


def _instructions(code, image_bytes, name):
    image = parse_image(image_bytes)
    headers = [(int(match[1], 16), match[2]) for line in code.splitlines()
               if (match := HEADER.match(line))]
    if len(headers) != 1 or headers[0][1] != name: _fail("exact selected symbol is absent")
    entry = headers[0][0]
    subject = unwind_interval(image_bytes, image, 1, entry - image.preferred_base)
    span = subject.ranges[0]
    directory, size = data_directory(image, 3)
    runtime_functions = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    unwind = next(item[2] for item in runtime_functions if item[0] == span.rva)
    if read_rva(image_bytes, image, unwind, 1)[0] >> 3:
        _fail("exception and chained unwind handlers are outside bounded scope")
    if not 0 < span.size <= 16384: _fail("unwind interval exceeds bounded single-body scope")
    expected = read_rva(image_bytes, image, span.rva, span.size)
    instructions = []
    for line in code.splitlines():
        match = LINE.match(line)
        if match is None: continue
        address = int(match[1], 16)
        if not entry <= address < entry + span.size: continue
        raw = bytes.fromhex(match[2])
        if not raw: _fail("empty decoded instruction")
        operands = match[4].split("#", 1)[0].strip()
        instructions.append(Instruction(address, raw, match[3],
            tuple(part.strip() for part in operands.split(",")) if operands else ()))
    cursor = entry
    for instruction in instructions:
        if instruction.address != cursor: _fail("disassembly has a gap or overlapping instruction")
        offset = cursor - entry
        if expected[offset:offset + len(instruction.raw)] != instruction.raw:
            _fail("disassembly bytes differ from actual PE image")
        cursor += len(instruction.raw)
    if cursor != entry + span.size: _fail("disassembly does not cover the exact PE unwind interval")
    return instructions


def _graph(instructions, allow_indirect=False):
    by_address = {item.address: item for item in instructions}
    if len(by_address) != len(instructions): _fail("duplicate instruction address")
    successors = {}
    callers = []
    for index, item in enumerate(instructions):
        next_address = item.address + len(item.raw)
        opcode = item.opcode
        if opcode not in ALLOWED:
            _fail(f"unsupported instruction {opcode} at {item.address:x}")
        if opcode == "pushq" and (index != 0 or item.operands != ("%rsi",)):
            _fail(f"unsupported instruction pushq at {item.address:x}")
        if opcode == "popq" and (item.operands != ("%rsi",) or
                index + 1 == len(instructions) or instructions[index + 1].opcode not in ("ret", "retq")):
            _fail(f"unsupported instruction popq at {item.address:x}")
        if opcode in ("retq", "ret"):
            if item.operands: _fail("unsupported return operand")
            successors[item.address] = ()
        elif opcode in ("jmp", "jmpq", "jae"):
            if len(item.operands) != 1 or not (target := DIRECT.fullmatch(item.operands[0])):
                _fail("indirect or malformed branch")
            branch = int(target[1], 16)
            if branch not in by_address: _fail("branch crosses interval or enters instruction middle")
            successors[item.address] = (branch,) if opcode.startswith("jmp") else (branch, next_address)
        else:
            if next_address not in by_address: _fail("non-return falls outside unwind interval")
            successors[item.address] = (next_address,)
            if opcode in ("call", "callq"):
                if len(item.operands) != 1 or not (DIRECT.fullmatch(item.operands[0]) or
                                                    (allow_indirect and item.operands == ("*%rax",) and
                                                     item.raw == b"\xff\xd0")):
                    _fail("indirect or malformed call")
                if DIRECT.fullmatch(item.operands[0]): callers.append(item)
    return by_address, successors, callers


def _check_rsi_unwind(instructions, image_bytes, allocation):
    image = parse_image(image_bytes)
    entry = instructions[0].address
    begin = entry - image.preferred_base
    directory, size = data_directory(image, 3)
    runtime_functions = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    unwind = next((item[2] for item in runtime_functions if item[0] == begin), None)
    if unwind is None: _fail("saved-register prologue has no exact PE unwind entry")
    header = read_rva(image_bytes, image, unwind, 4)
    end = instructions[1].address + len(instructions[1].raw) - entry
    if header[0] != 1 or header[1] != end or header[3] != 0:
        _fail("saved-register prologue differs from PE unwind header")
    if allocation <= 128:
        expected = bytes((end, 2 | ((allocation // 8 - 1) << 4)))
    else:
        expected = bytes((end, 1)) + struct.pack("<H", allocation // 8)
    expected += bytes((len(instructions[0].raw), 0x60))
    if header[2] * 2 != len(expected) or read_rva(image_bytes, image, unwind + 4, len(expected)) != expected:
        _fail("saved-register push or allocation differs from PE unwind codes")


def _entry_spills(instructions, image_bytes=None):
    # This bounded lowering has one prologue and stores the two entry references
    # before any branch. Their physical stack addresses remain immutable.
    pushed = instructions[0].opcode == "pushq"
    first = instructions[1] if pushed else instructions[0]
    if first.opcode != "subq" or len(first.operands) != 2 or first.operands[1] != "%rsp":
        _fail("expected a single fixed-frame prologue")
    allocation = int(first.operands[0][1:], 0) if first.operands[0].startswith("$") else 0
    frame = allocation + (8 if pushed else 0)
    if not 0 < allocation <= 4096 or allocation % 8 or frame > 4096:
        _fail("invalid fixed frame")
    if pushed:
        if instructions[0].operands != ("%rsi",) or image_bytes is None:
            _fail("saved-register prologue needs exact RSI and PE unwind bytes")
        _check_rsi_unwind(instructions, image_bytes, allocation)
    spills = {}
    for item in instructions[2 if pushed else 1:]:
        if item.opcode.startswith("j") or item.opcode in ("call", "callq", "ret", "retq"):
            break
        if item.opcode == "movq" and len(item.operands) == 2 and item.operands[0] in ("%rcx", "%rdx"):
            pseudo = State(-frame, {}, {}, {}, {}, {}, {}, 0)
            key = _stack(item.operands[1], pseudo)
            if key is not None:
                symbol = "lease" if item.operands[0] == "%rcx" else "scope"
                if symbol in spills: _fail("ambiguous entry spill")
                spills[symbol] = (item.address, key)
    if set(spills) != {"lease", "scope"} or abs(spills["lease"][1] - spills["scope"][1]) < 8:
        _fail("entry references lack separate fixed spills")
    return frame, spills


def _dispatcher_state(instructions, graph, frame):
    first_branch = next((item for item in instructions if item.opcode in ("jmp", "jmpq", "jae")), None)
    if first_branch is None or first_branch.opcode not in ("jmp", "jmpq"):
        _fail("entry lacks a direct dispatcher branch")
    initializers = [item for item in instructions if item.address < first_branch.address and
                    item.opcode == "movl" and len(item.operands) == 2 and
                    item.operands[0].startswith("$") and STACK.fullmatch(item.operands[1])]
    if len(initializers) != 1: _fail("entry lacks one state initializer")
    init_slot = _stack(initializers[0].operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0))
    destination = graph[first_branch.address]
    root = next((item for item in instructions if item.address == destination[0]), None)
    if (len(destination) != 1 or root is None or root.opcode != "movl" or
            len(root.operands) != 2 or not STACK.fullmatch(root.operands[0])):
        _fail("entry branch does not enter a stack-state dispatcher")
    root_slot = _stack(root.operands[0], State(-frame, {}, {}, {}, {}, {}, {}, 0))
    if root_slot != init_slot: _fail("dispatcher reads a different state slot from entry")
    return root_slot


def _transfer(item, state, frame, spills):
    state = state.copy()
    op, args = item.opcode, item.operands
    protected = tuple(value[1] for value in spills.values() if state.spills & (1 if value == spills["lease"] else 2))
    if state.saved_rsi: protected += (-8,)
    if op == "pushq" and args == ("%rsi",):
        if item.address != _transfer.entry or state.rsp != 0 or state.saved_rsi:
            _fail("non-prologue saved-register push")
        state.rsp = -8
        state.saved_rsi = True
        return state
    if op == "popq" and args == ("%rsi",):
        if state.rsp != -8 or not state.saved_rsi:
            _fail("non-epilogue saved-register pop")
        state.rsp = 0
        state.saved_rsi = False
        state.registers.pop("rsi", None)
        state.words.pop("rsi", None)
        state.origins.pop("rsi", None)
        return state
    if op in ("subq", "addq") and len(args) == 2 and args[1] == "%rsp":
        amount = int(args[0][1:], 0) if args[0].startswith("$") else -1
        allocation = frame - (8 if state.saved_rsi else 0)
        if op == "subq":
            if (item.address != _transfer.entry + (1 if state.saved_rsi else 0) or
                    state.rsp != (-8 if state.saved_rsi else 0) or amount != allocation):
                _fail("non-entry stack-pointer shift")
            state.rsp -= amount
        else:
            if state.rsp != -frame or amount != allocation:
                _fail("non-epilogue stack-pointer shift")
            state.rsp += amount
        return state
    if op in ("retq", "ret"):
        if state.rsp != 0 or state.saved_rsi: _fail("return has an unbalanced stack")
        return state
    if op in ("jmp", "jmpq", "jae", "nop", "nopl", "nopw"):
        return state
    if op in ("call", "callq"):
        if state.rsp != -frame or state.spills != 3:
            _fail("call lacks stable frame and both entry spills")
        match = DIRECT.fullmatch(args[0])
        target = match[2] if match else None
        if target in (OWNED, MEASURED):
            expected = ("lease", "scope") if target == OWNED else ("scope", "lease")
            if state.registers.get("rcx") != expected[0] or state.slots.get(state.rsp + 0x38) != expected[1]:
                _fail(f"{target} lost first/eighth argument provenance")
        elif target is None and args != ("*%rax",):
            _fail("unresolved direct call")
        for register in CALLER_SAVED: state.registers.pop(register, None)
        for register in CALLER_SAVED: state.words.pop(register, None)
        for register in CALLER_SAVED: state.origins.pop(register, None)
        if target in (OWNED, MEASURED):
            state.words["rax"] = 1 if target == OWNED else 2
        # Win64 callees own the 32-byte shadow area and outgoing argument slots.
        for slot in list(state.slots):
            if state.rsp <= slot < state.rsp + 0x40: del state.slots[slot]
        for slot in list(state.word_slots):
            if state.rsp <= slot < state.rsp + 0x40: del state.word_slots[slot]
        for slot in list(state.origin_slots):
            if state.rsp <= slot < state.rsp + 0x40: del state.origin_slots[slot]
        return state
    if op == "movq" and len(args) == 2:
        value = _source(args[0], state, 8)
        for symbol, (address, key) in spills.items():
            if item.address == address:
                if value != symbol or _stack(args[1], state) != key or state.spills & (1 if symbol == "lease" else 2):
                    _fail("entry spill changed before immutable capture")
                state.slots[key] = symbol
                state.spills |= 1 if symbol == "lease" else 2
                return state
        _write(args[1], state, value, 8, protected)
        return state
    if op == "leaq" and len(args) == 2:
        stack_key = _stack(args[0], state)
        if stack_key is not None and any(stack_key <= key < stack_key + 8 for key in protected):
            _fail("entry spill address escapes")
        if stack_key is None and not args[0].endswith("(%rip)"):
            _fail("unsupported address calculation")
        _write(args[1], state, None, 8, protected)
        return state
    if op in ("movl", "addl", "subl", "xorl", "orl", "imull", "shll", "shrl", "cmovel", "cmovll", "cmovnel"):
        if len(args) < 2 or len(args) > 3: _fail(f"unsupported {op} operands")
        width = 4
        destination = args[-1]
        if op != "movl" and _register(destination) is None:
            _fail(f"unsupported {op} memory destination")
        if op == "movl":
            _source(args[0], state, width)
            word = _word(args[0], state)
            origin = _origin(args[0], state)
        elif op in ("cmovel", "cmovll", "cmovnel") and _register(args[0]) is None:
            _fail("unsupported conditional move source")
        elif op == "imull" and len(args) == 3:
            _source(args[1], state, width)
        elif op in ("addl", "subl", "xorl", "orl", "imull"):
            _source(args[0], state, width)
        if op != "movl":
            word = _word(destination, state)
            origin = None
            if op in ("addl", "subl", "xorl", "orl", "imull"):
                operand = args[1] if op == "imull" and len(args) == 3 else args[0]
                word = (0 if op == "imull" and len(args) == 3 else word) | _word(operand, state)
            if op in ("xorl", "subl") and args[0] == destination:
                word = 0
            if op == "imull" and args[0] in ("$0", "$0x0"):
                word = 0
            if op == "orl" and args[0] in ("$-1", "$0xffffffff"):
                word = 0
            if op in ("cmovel", "cmovll", "cmovnel"):
                word &= _word(args[0], state)
        _write(destination, state, None, width, protected, word, origin)
        return state
    if op == "cmpl" and len(args) == 2:
        _source(args[0], state, 4)
        _source(args[1], state, 4)
        return state
    if op == "cmpq" and len(args) == 2:
        _source(args[0], state, 8)
        _source(args[1], state, 8)
        return state
    _fail(f"unsupported instruction {op} at {item.address:x}")


def _join(before, incoming):
    if (before.rsp != incoming.rsp or before.spills != incoming.spills or
            before.saved_rsi != incoming.saved_rsi):
        _fail("non-joinable stack or entry-spill state")
    registers = {key: value for key, value in before.registers.items()
                 if incoming.registers.get(key) == value}
    slots = {key: value for key, value in before.slots.items()
             if incoming.slots.get(key) == value}
    words = {key: before.words[key] & incoming.words.get(key, 0) for key in before.words}
    word_slots = {key: before.word_slots[key] & incoming.word_slots.get(key, 0)
                  for key in before.word_slots}
    origins = {key: value for key, value in before.origins.items()
               if incoming.origins.get(key) == value}
    origin_slots = {key: value for key, value in before.origin_slots.items()
                    if incoming.origin_slots.get(key) == value}
    return State(before.rsp, registers, slots, {key: value for key, value in words.items() if value},
                 {key: value for key, value in word_slots.items() if value},
                 origins, origin_slots, before.spills, before.saved_rsi)


def _return_update(instructions, graph, first, second, state, frame, spills, dispatcher_state):
    by_address = {item.address: item for item in instructions}
    predecessors = {item.address: set() for item in instructions}
    for address, successors in graph.items():
        for successor in successors: predecessors[successor].add(address)
    cursor = first.address
    state = state.copy()
    expressions = ReturnExpressions()
    writes = set()
    expression_writes = []
    saw_second = False
    previous = None
    state_origin = state.origin_slots.get(state.rsp + 0x30)
    if state_origin != dispatcher_state:
        _fail("owned helper state origin differs from dispatcher state")
    while True:
        item = by_address[cursor]
        if previous is not None and predecessors[cursor] != {previous}:
            _fail("joint return path has a bypassing CFG predecessor")
        if item.opcode in ("jmp", "jmpq", "jae", "ret", "retq"):
            if item.opcode not in ("jmp", "jmpq") or not saw_second:
                _fail("joint return path branches before the state update")
            break
        if item.opcode in ("call", "callq") and item.address not in (first.address, second.address):
            _fail("unknown call intervenes in joint return flow")
        if item.address == second.address:
            if state.origin_slots.get(state.rsp + 0x30) != state_origin:
                _fail("joint helpers receive different state origins")
            saw_second = True
        if (saw_second and item.opcode == "movl" and len(item.operands) == 2 and
                _stack(item.operands[1], state) is not None and
                _word(item.operands[0], state) == 3):
            writes.add(_stack(item.operands[1], state))
        if (saw_second and item.opcode == "movl" and len(item.operands) == 2 and
                _stack(item.operands[1], state) == dispatcher_state):
            expression_writes.append(expressions.read(item.operands[0], state))
        expressions.transfer(item, state)
        state = _transfer(item, state, frame, spills)
        previous = cursor
        cursor += len(item.raw)
        if cursor not in by_address: _fail("joint return path leaves its interval")
    if writes != {state_origin} or state.word_slots.get(state_origin) != 3:
        _fail("both joint return words do not reach one state update")
    if len(expression_writes) != 1 or expression_writes[0].dependencies != 3:
        _fail("joint return expressions detach or cancel before the dispatcher state update")


def verify_joint_machine(image_bytes, code, report, row):
    proof = row.get("runtime_contribution", {})
    if (proof.get("scheme_version") != 4 or proof.get("joint_helper_contract") != "source-mixed-context-v1" or
            proof.get("cross_provider_owner_binding_verified") is not False or
            len(proof.get("sites", ())) != 1 or proof.get("query_count") != 2):
        _fail("one unproven explicit schema4 joint site is required")
    if len([item for item in report["functions"] if item.get("selected") and
            not item.get("generated") and item.get("runtime_contribution", {}).get(
                "joint_helper_contract") == "source-mixed-context-v1"]) != 1:
        _fail("multi-owner joint evidence is outside bounded scope")
    if row.get("hybrid_eh") or row.get("region_flow_contract_verified"):
        _fail("EH and region fragments are outside bounded scope")
    name = row["function"]
    instructions = _instructions(code, image_bytes, name)
    by_address, graph, callers = _graph(instructions)
    joint = [item for item in callers if DIRECT.fullmatch(item.operands[0])[2] in (OWNED, MEASURED)]
    if [DIRECT.fullmatch(item.operands[0])[2] for item in joint] != [OWNED, MEASURED]:
        _fail("joint helper order or count differs from schema4 contract")
    predecessors = {address: set() for address in by_address}
    for address, successors in graph.items():
        for successor in successors: predecessors[successor].add(address)
    can_reach_joint = {item.address for item in joint}
    pending_reach = deque(can_reach_joint)
    while pending_reach:
        for predecessor in predecessors[pending_reach.popleft()] - can_reach_joint:
            can_reach_joint.add(predecessor)
            pending_reach.append(predecessor)
    if any(item.opcode == "leaq" and item.operands and STACK.fullmatch(item.operands[0]) and
           item.address in can_reach_joint for item in instructions):
        _fail("stack address can escape before a joint helper")
    if any(item.address in can_reach_joint and item not in joint for item in callers):
        _fail("unmodelled call may alter entry spills before a joint helper")
    frame, spills = _entry_spills(instructions, image_bytes)
    dispatcher_state = _dispatcher_state(instructions, graph, frame)
    _transfer.entry = instructions[0].address
    entry = State(0, {"rcx": "lease", "rdx": "scope"}, {}, {}, {}, {}, {}, 0)
    states = {instructions[0].address: entry}
    pending = deque((instructions[0].address,))
    seen_calls = set()
    while pending:
        address = pending.popleft()
        item = by_address[address]
        state = _transfer(item, states[address], frame, spills)
        if item in joint: seen_calls.add(address)
        for successor in graph[address]:
            old = states.get(successor)
            merged = state if old is None else _join(old, state)
            if old != merged:
                states[successor] = merged
                pending.append(successor)
    if seen_calls != {item.address for item in joint}:
        _fail("a joint helper is unreachable in the actual CFG")
    _return_update(instructions, graph, joint[0], joint[1], states[joint[0].address],
                   frame, spills, dispatcher_state)
    # The caller's setup is visible, but either helper can modify its caller's
    # prepared stack slots before the next call. The helper bodies are not proved.
    return {"cross_provider_owner_binding_verified": False,
            "joint_caller_pointer_provenance_verified": False,
            "joint_machine_scope": "windows-x64-single-unwind-interval-caller-setup; helper-write-effects-unverified",
            "joint_return_routing_scope": "bounded-syntactic-def-use; numerical-influence-unverified"}
