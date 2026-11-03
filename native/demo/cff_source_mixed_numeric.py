"""Local numeric sensitivity of exact-PE two-site helper return routes."""

from collections import deque
from types import SimpleNamespace

from cff_joint_machine_evidence import (ALIASES, CALLER_SAVED, DIRECT, REGISTERS,
                                        _register, _stack)


MASK = 0xffffffff
WORD_REGISTERS = {name for name in ALIASES if name not in REGISTERS and
                  (name.startswith("e") or name.endswith("d"))}
PROBES = (1, 2, 3, 0x10203, 0x13579bdf, 0x2468ace1, 0x7fffffff,
          0x80000000, 0xfffffffe, 0xffffffff)


def _fail(reason):
    raise ValueError(f"numeric sensitivity: {reason}")


def _seed(key):
    value = (key * 0x9e3779b9 + 0x85ebca6b) & MASK
    return value or 1


def _constant_states(instructions, graph, frame):
    """Keep only 32-bit constants common to every decoded predecessor."""
    context = SimpleNamespace(rsp=-frame)

    def location(operand):
        register = _register(operand)
        if register is not None and operand[1:] in WORD_REGISTERS:
            return ("register", register)
        slot = _stack(operand, context)
        return ("slot", slot) if slot is not None else None

    def read(values, operand):
        if operand.startswith("$"): return int(operand[1:], 0) & MASK
        return values.get(location(operand))

    def clear(values, operand, width):
        key = location(operand)
        if key is not None:
            if key[0] == "register": values.pop(key, None)
            else:
                for old in list(values):
                    if old[0] == "slot" and key[1] < old[1] + 4 and old[1] < key[1] + width:
                        del values[old]
            return key
        register = _register(operand)
        if register is not None:
            values.pop(("register", register), None)
            return None
        slot = _stack(operand, context)
        if slot is not None:
            for old in list(values):
                if old[0] == "slot" and slot < old[1] + 4 and old[1] < slot + width:
                    del values[old]
        return None

    def transfer(item, incoming):
        values = incoming.copy()
        op, args = item.opcode, item.operands
        if op in ("call", "callq"):
            for name in CALLER_SAVED: values.pop(("register", name), None)
            for key in list(values):
                if key[0] == "slot" and context.rsp <= key[1] < context.rsp + 0x40:
                    del values[key]
        elif op == "movl":
            value = read(values, args[0])
            key = clear(values, args[1], 4)
            if key is not None and value is not None: values[key] = value
        elif op in ("movq", "leaq"):
            clear(values, args[1], 8)
        elif op in ("addl", "subl", "xorl", "orl", "imull", "shll", "shrl"):
            destination = args[-1]
            first = read(values, args[1] if op == "imull" and len(args) == 3 else destination)
            second = read(values, args[0])
            result = None
            if op in ("xorl", "subl") and args[0] == destination:
                result = 0
            elif op == "orl" and second == MASK:
                result = MASK
            elif op == "imull" and second == 0:
                result = 0
            elif first is not None and second is not None:
                if op == "addl": result = (first + second) & MASK
                elif op == "subl": result = (first - second) & MASK
                elif op == "xorl": result = first ^ second
                elif op == "orl": result = first | second
                elif op == "imull": result = (first * second) & MASK
                elif op == "shll": result = (first << (second & 31)) & MASK
                elif op == "shrl": result = first >> (second & 31)
            key = clear(values, destination, 4)
            if key is not None and result is not None: values[key] = result
        elif op in ("cmovel", "cmovll"):
            source, previous = read(values, args[0]), read(values, args[1])
            key = clear(values, args[1], 4)
            if key is not None and source is not None and source == previous:
                values[key] = source
        return values

    by_address = {item.address: item for item in instructions}
    incoming = {instructions[0].address: {}}
    pending = deque((instructions[0].address,))
    while pending:
        address = pending.popleft()
        outgoing = transfer(by_address[address], incoming[address])
        for successor in graph[address]:
            before = incoming.get(successor)
            merged = outgoing if before is None else {
                key: value for key, value in before.items() if outgoing.get(key) == value}
            if before != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming


def _prelude_tokens(instructions, graph, first_call, frame):
    """Distinguish current copies from physical origin slots reused earlier."""
    context = SimpleNamespace(rsp=-frame)
    by_address = {item.address: item for item in instructions}
    predecessors = {item.address: set() for item in instructions}
    for address, successors in graph.items():
        for successor in successors: predecessors[successor].add(address)
    index = next(index for index, item in enumerate(instructions)
                 if item.address == first_call.address)
    begin = index
    while begin and instructions[begin - 1].opcode not in (
            "jmp", "jmpq", "jae", "ret", "retq"):
        begin -= 1
    tokens = {}

    def location(operand):
        register = _register(operand)
        if register is not None:
            return ("register", register)
        slot = _stack(operand, context)
        return ("slot", slot) if slot is not None else None

    def read(operand):
        if operand.startswith("$"): return ("constant", int(operand[1:], 0) & MASK)
        key = location(operand)
        if key is None: _fail("unknown pre-call numeric copy source")
        return tokens.get(key, ("live-in", key))

    def invalidate(destination, width):
        key = location(destination)
        if key is None: _fail("unknown pre-call numeric write")
        if key[0] == "register": tokens.pop(key, None)
        else:
            for old in list(tokens):
                if old[0] == "slot" and key[1] < old[1] + 4 and old[1] < key[1] + width:
                    del tokens[old]
        return key

    for position in range(begin, index):
        item = instructions[position]
        if (position > begin and predecessors[item.address] != {
                instructions[position - 1].address}):
            _fail("pre-call copy interval has a bypassing predecessor")
        op, args = item.opcode, item.operands
        if op in ("call", "callq", "jae", "jmp", "jmpq", "ret", "retq"):
            _fail("pre-call copy interval is not straight-line")
        if op == "movl":
            value = read(args[0])
            tokens[invalidate(args[1], 4)] = value
        elif op in ("movq", "leaq"):
            invalidate(args[1], 8)
        elif op in ("addl", "subl", "xorl", "orl", "imull", "shll", "shrl",
                    "cmovel", "cmovll"):
            tokens[invalidate(args[-1], 4)] = ("computed", item.address)
        elif op not in ("nop", "nopl", "nopw", "cmpl", "subq", "addq"):
            _fail(f"unknown pre-call instruction {op}")
    if index > begin and predecessors[first_call.address] != {
            instructions[index - 1].address}:
        _fail("first helper call bypasses its pre-call copy interval")
    return tokens


def _token_seed(token):
    value = 2166136261
    for byte in repr(token).encode("ascii"):
        value = ((value ^ byte) * 16777619) & MASK
    return value or 1


class Machine:
    def __init__(self, state, constants=None, tokens=None):
        self.rsp = state.rsp
        # The provenance model preserves copy origins. Reuse each origin's value;
        # independently seeding physical copies can fabricate a CMOV outcome.
        tokens = tokens or {}
        self.registers = {name: _token_seed(tokens.get(("register", name),
            ("live-in", ("register", name)))) for name in state.origins}
        self.qregisters = {name: ("entry-pointer", symbol) for name, symbol in
                           state.registers.items()}
        self.memory = {}
        for slot in set(state.word_slots) | set(state.origin_slots):
            origin = state.origin_slots.get(slot)
            if origin is None:
                _fail(f"unknown initial word origin at {slot:x}")
            self.memory[slot] = (4, _token_seed(tokens.get(("slot", slot),
                ("live-in", ("slot", slot)))))
        for slot, symbol in state.slots.items():
            self._write_memory(slot, 8, ("entry-pointer", symbol))
        self.initial_origins = {}
        for name, origin in state.origins.items():
            self.initial_origins[("register", name)] = origin
        for slot, origin in state.origin_slots.items():
            self.initial_origins[("slot", slot)] = origin
        self.initial_tokens = {key: tokens.get(key, ("live-in", key))
                               for key in self.initial_origins}
        for (kind, key), value in (constants or {}).items():
            if kind == "register" and key in self.registers:
                self.registers[key] = value
                self.qregisters[key] = value
                self.initial_origins.pop((kind, key), None)
            elif kind == "slot" and self.memory.get(key, (None,))[0] == 4:
                self.memory[key] = (4, value)
                self.initial_origins.pop((kind, key), None)
        self.observed_origins = {}
        self.flags = None
        self.state_write = None

    def _write_memory(self, slot, width, value):
        for current, (size, _) in list(self.memory.items()):
            if slot < current + size and current < slot + width:
                del self.memory[current]
                if hasattr(self, "initial_origins"):
                    self.initial_origins.pop(("slot", current), None)
        self.memory[slot] = (width, value)

    def _observe(self, key):
        origin = self.initial_origins.get(key)
        if origin is None: return
        previous = self.observed_origins.setdefault(origin, key)
        if previous != key and self.initial_tokens[previous] != self.initial_tokens[key]:
            _fail(f"ambiguous reused initial word origin {origin:x}: {previous} and {key} at {self.current_item:x}")

    def read(self, operand, width=4):
        if operand.startswith("$"):
            return int(operand[1:], 0) & (MASK if width == 4 else 0xffffffffffffffff)
        register = _register(operand)
        if register is not None:
            if (width == 4 and operand[1:] not in WORD_REGISTERS or
                    width == 8 and operand[1:] not in REGISTERS):
                _fail(f"unknown register alias {operand}")
            values = self.registers if width == 4 else self.qregisters
            if register not in values:
                _fail(f"unknown {width * 8}-bit register read {operand}")
            if width == 4: self._observe(("register", register))
            return values[register]
        slot = _stack(operand, self)
        if slot is None or self.memory.get(slot, (None,))[0] != width:
            _fail(f"unknown or aliased {width * 8}-bit memory read {operand}")
        if width == 4: self._observe(("slot", slot))
        return self.memory[slot][1]

    def write(self, operand, width, value):
        register = _register(operand)
        if register is not None:
            if register == "rsp":
                _fail("stack pointer changed within return span")
            if (width == 4 and operand[1:] not in WORD_REGISTERS or
                    width == 8 and operand[1:] not in REGISTERS):
                _fail(f"unknown register alias {operand}")
            self.registers.pop(register, None)
            self.qregisters.pop(register, None)
            self.initial_origins.pop(("register", register), None)
            if width == 4:
                self.registers[register] = value & MASK
                self.qregisters[register] = value & MASK
            else:
                self.qregisters[register] = value
                if isinstance(value, int): self.registers[register] = value & MASK
            return
        slot = _stack(operand, self)
        if slot is None:
            _fail(f"unknown memory write {operand}")
        self._write_memory(slot, width, value)

    def _integer(self, value):
        if not isinstance(value, int):
            _fail("pointer value entered numeric expression")
        return value

    def _arithmetic(self, opcode, left, right):
        left, right = self._integer(left), self._integer(right)
        if opcode == "addl":
            result = (left + right) & MASK
            overflow = bool((~(left ^ right) & (left ^ result) & 0x80000000))
        elif opcode in ("subl", "cmpl"):
            result = (left - right) & MASK
            overflow = bool(((left ^ right) & (left ^ result) & 0x80000000))
        elif opcode == "xorl":
            result, overflow = left ^ right, False
        elif opcode == "orl":
            result, overflow = left | right, False
        elif opcode == "imull":
            product = (left if left < 0x80000000 else left - 0x100000000) * (
                right if right < 0x80000000 else right - 0x100000000)
            result = product & MASK
            self.flags = None  # x86 leaves ZF and SF undefined after IMUL.
            return result
        else:
            _fail(f"unknown arithmetic instruction {opcode}")
        self.flags = (result == 0, bool(result & 0x80000000), overflow)
        return result

    def step(self, item, calls, values, dispatcher_slot):
        self.current_item = item.address
        op, args = item.opcode, item.operands
        if op in ("call", "callq"):
            if item.address not in calls or DIRECT.fullmatch(args[0]) is None:
                _fail("unknown call in numeric return span")
            for register in CALLER_SAVED:
                self.registers.pop(register, None)
                self.qregisters.pop(register, None)
                self.initial_origins.pop(("register", register), None)
            for slot, (width, _) in list(self.memory.items()):
                if self.rsp <= slot < self.rsp + 0x40 or (
                        slot < self.rsp + 0x40 and self.rsp < slot + width):
                    del self.memory[slot]
                    self.initial_origins.pop(("slot", slot), None)
            self.flags = None
            self.write("%eax", 4, values[item.address])
            return
        if op == "movl":
            value = self._integer(self.read(args[0]))
            self.write(args[1], 4, value)
            if _stack(args[1], self) == dispatcher_slot:
                if self.state_write is not None: _fail("multiple state writes")
                self.state_write = value
            return
        if op == "movq":
            self.write(args[1], 8, self.read(args[0], 8))
            return
        if op == "leaq":
            slot = _stack(args[0], self)
            if slot is None: _fail("unknown address formation")
            self.write(args[1], 8, ("stack-address", slot))
            return
        if op in ("addl", "subl", "xorl", "orl", "cmpl"):
            result = self._arithmetic(op, self.read(args[-1]), self.read(args[0]))
            if op != "cmpl": self.write(args[-1], 4, result)
            return
        if op == "imull":
            if len(args) != 3: _fail("unknown IMUL form")
            result = self._arithmetic(op, self.read(args[1]), self.read(args[0]))
            self.write(args[2], 4, result)
            return
        if op in ("shll", "shrl"):
            count = self._integer(self.read(args[0])) & 31
            before = self._integer(self.read(args[1]))
            if count:
                result = ((before << count) if op == "shll" else (before >> count)) & MASK
                # OF is defined only for one-bit shifts. CFF spans compare afresh
                # before any CMOV that consumes this flag.
                overflow = ((bool(result & 0x80000000) ^ bool(before & 0x80000000))
                            if op == "shll" else bool(before & 0x80000000)) if count == 1 else None
                self.flags = (result == 0, bool(result & 0x80000000), overflow)
                self.write(args[1], 4, result)
            return
        if op in ("cmovel", "cmovll"):
            if self.flags is None or (op == "cmovll" and self.flags[2] is None):
                _fail("unknown condition flags at CMOV")
            zero, sign, overflow = self.flags
            take = zero if op == "cmovel" else sign != overflow
            source = self._integer(self.read(args[0]))
            self._integer(self.read(args[1]))
            if take: self.write(args[1], 4, source)
            return
        if op in ("nop", "nopl", "nopw"):
            return
        _fail(f"unknown return-span instruction {op}")


def _route(instructions, graph, calls, dispatcher):
    by_address = {item.address: item for item in instructions}
    cursor = calls[0].address
    route = []
    while True:
        # One physical gateway may end immediately before the shared
        # dispatcher. Accept only its decoded linear successor, while the
        # caller's group/return proof checks the complete helper set.
        if cursor == dispatcher and route:
            previous = route[-1]
            if (previous.address + len(previous.raw) != cursor or
                    graph[previous.address] != (cursor,)):
                _fail("return span does not fall through to dispatcher")
            return route
        item = by_address.get(cursor)
        if item is None: _fail("return span left exact PE interval")
        if item.opcode in ("jmp", "jmpq"):
            if int(DIRECT.fullmatch(item.operands[0])[1], 16) != dispatcher:
                _fail("return span left dispatcher")
            return route
        if item.opcode in ("jae", "ret", "retq"):
            _fail("return span has an unexpected branch")
        route.append(item)
        cursor += len(item.raw)


def check_numeric_sensitivity(instructions, graph, calls, state, frame,
                              dispatcher, dispatcher_slot):
    route = _route(instructions, graph, calls, dispatcher)
    constants = _constant_states(instructions, graph, frame).get(calls[0].address)
    if constants is None: _fail("helper call has no decoded constant state")
    tokens = _prelude_tokens(instructions, graph, calls[0], frame)
    addresses = {call.address for call in calls}
    for selected in calls:
        baseline = {address: _seed(address & MASK) for address in addresses}
        results = set()
        for probe in PROBES:
            values = baseline.copy()
            values[selected.address] = probe
            machine = Machine(state, constants, tokens)
            for item in route:
                machine.step(item, addresses, values, dispatcher_slot)
            if machine.state_write is None:
                _fail("missing dispatcher state write")
            results.add(machine.state_write)
            if len(results) > 1: break
        if len(results) < 2:
            _fail(f"helper return at {selected.address:x} has no exhibited numeric effect")
