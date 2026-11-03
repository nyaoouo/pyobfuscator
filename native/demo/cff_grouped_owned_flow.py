"""Bounded structural routing checks for linked grouped owned CFF queries."""

from dataclasses import dataclass
import re


HELPER = "<pyobf_native_contribution_word_v1>"
REGISTER = re.compile(r"^%[a-z][a-z0-9]*$")
STACK = re.compile(r"^(?:(0x[0-9a-f]+|-?\d+))?\(%rsp\)$")
PC_RELATIVE = re.compile(r"^(?:(?:0x[0-9a-f]+|-?\d+))?\(%rip\)$")
ALIASES = {"%rax": "%eax", "%rcx": "%ecx", "%rdx": "%edx",
           "%r8": "%r8d", "%r9": "%r9d", "%r10": "%r10d", "%r11": "%r11d"}
CALLER_SAVED = {"%eax", "%ecx", "%edx", "%r8d", "%r9d", "%r10d", "%r11d"}
STACK_POINTERS = {"%rsp", "%esp", "%sp", "%spl"}


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    op: str
    args: tuple[str, ...]
    operand_text: str


def parse(code):
    instructions = []
    for line in code.splitlines():
        columns = line.strip().split("\t")
        if len(columns) < 2:
            continue
        match = re.match(r"^([0-9a-f]{8,16}):", columns[0])
        if match is None:
            continue
        operand_text = columns[2].split("#", 1)[0].strip() if len(columns) > 2 else ""
        encoded = columns[0][match.end():].strip().split()
        if not encoded or any(re.fullmatch(r"[0-9a-f]{2}", byte) is None for byte in encoded):
            raise SystemExit("unsupported grouped owned instruction bytes")
        instructions.append(Instruction(int(match[1], 16), len(encoded), columns[1].strip(),
                                        tuple(part.strip() for part in operand_text.split(",")) if operand_text else (),
                                        operand_text))
    return instructions


def stack_range(operand, width=4):
    match = STACK.fullmatch(operand)
    if match is None:
        return None
    offset = int(match[1], 16 if match[1].startswith("0x") else 10) if match[1] else 0
    return offset, offset + width


def stack_write_range(instruction):
    if instruction.op in ("movl", "movq") and len(instruction.args) == 2:
        return stack_range(instruction.args[1], 8 if instruction.op == "movq" else 4)
    return None


def overlaps(left, right):
    return left is not None and right is not None and left[0] < right[1] and right[0] < left[1]


def immediate(operand):
    try:
        return int(operand[1:], 0) & 0xffffffff if operand.startswith("$") else None
    except ValueError:
        return None


def checked_stack_effect(instruction, owner):
    """Admit only machine forms whose stack and memory writes are bounded here."""
    op, args = instruction.op, instruction.args
    register = lambda item: REGISTER.fullmatch(item) is not None
    readable = lambda item: (register(item) or immediate(item) is not None or
                             stack_range(item) is not None or PC_RELATIVE.fullmatch(item) is not None)
    writable = lambda item: register(item) or stack_range(item) is not None
    if op in ("pushq", "popq") and len(args) == 1 and register(args[0]):
        if op == "popq" and args[0] in STACK_POINTERS:
            raise SystemExit(f"unsupported grouped owned stack adjustment: {owner}")
        return -8 if op == "pushq" else 8
    if args and args[-1] in STACK_POINTERS:
        if op in ("subq", "addq") and args[-1] == "%rsp" and len(args) == 2 and immediate(args[0]) is not None:
            amount = int(args[0][1:], 0)
            return -amount if op == "subq" else amount
        raise SystemExit(f"unsupported grouped owned stack adjustment: {owner}")
    if op in ("movl", "movq") and len(args) == 2 and readable(args[0]) and writable(args[1]):
        return 0
    if op in ("shll", "shrl", "roll", "rorl") and len(args) == 1 and register(args[0]):
        return 0
    if op in ("addl", "subl", "xorl", "andl", "orl", "imull", "shll", "shrl", "roll", "rorl",
              "addq", "subq") and len(args) in (2, 3) and all(readable(item) for item in args[:-1]) and register(args[-1]):
        return 0
    if re.fullmatch(r"cmov[a-z]+[lq]", op) and len(args) == 2 and readable(args[0]) and register(args[1]):
        return 0
    if op in ("cmpl", "cmpq", "testl", "testq") and len(args) == 2 and all(readable(item) for item in args):
        return 0
    if op in ("call", "callq", "jmp", "jmpq", "jae", "ja", "jb", "jbe") and len(args) == 1 and re.match(r"^0x[0-9a-f]+\b", args[0]):
        return 0
    if op.startswith(("ret", "nop")) or op in ("ud2", "int3", "hlt"):
        return 0
    raise SystemExit(f"unsupported grouped owned machine transfer: {owner}: {op} {instruction.operand_text}")


def reachable_stack_depths(segments, owner):
    blocks = {segment[0].address: segment for segment in segments}
    order = list(blocks)
    depths = {order[0]: 0}
    pending = [order[0]]
    while pending:
        address = pending.pop()
        segment = blocks[address]
        depth = depths[address]
        last = segment[-1]
        tail_target = re.match(r"^0x([0-9a-f]+)\b", last.operand_text) if last.op in ("jmp", "jmpq") else None
        terminal = last.op.startswith("ret") or (tail_target is not None and int(tail_target[1], 16) not in blocks)
        for index, instruction in enumerate(segment):
            effect = checked_stack_effect(instruction, owner)
            if effect and address != order[0] and not (
                    instruction.op == "addq" and terminal and
                    all(item.op.startswith(("ret", "nop")) or item.op in ("jmp", "jmpq")
                        for item in segment[index + 1:])):
                raise SystemExit(f"unsupported grouped owned transient stack adjustment: {owner}")
            depth += effect
        next_address = order[order.index(address) + 1] if order.index(address) + 1 < len(order) else None
        successors = []
        if last.op.startswith("j"):
            target = re.match(r"^0x([0-9a-f]+)\b", last.operand_text)
            if target is None:
                raise SystemExit(f"unsupported grouped owned indirect branch: {owner}")
            successors.append(int(target[1], 16))
            if last.op not in ("jmp", "jmpq") and next_address is not None:
                successors.append(next_address)
        elif not last.op.startswith("ret") and last.op not in ("ud2", "int3", "hlt") and next_address is not None:
            successors.append(next_address)
        for successor in successors:
            if successor not in blocks:
                if blocks[order[0]][0].address <= successor <= blocks[order[-1]][-1].address:
                    raise SystemExit(f"unsupported grouped owned branch into instruction: {owner}")
                continue
            if successor in depths:
                if depths[successor] != depth:
                    raise SystemExit(f"unsupported grouped owned stack join: {owner}")
            else:
                depths[successor] = depth
                pending.append(successor)
    return depths


def dispatcher_state_slot(segments, owner):
    entry = segments[0]
    if entry[-1].op not in ("jmp", "jmpq"):
        raise SystemExit(f"unsupported grouped owned entry route: {owner}")
    target = re.match(r"^0x([0-9a-f]+)\b", entry[-1].operand_text)
    if target is None:
        raise SystemExit(f"unsupported grouped owned entry route: {owner}")
    dispatcher = next((segment for segment in segments if segment[0].address == int(target[1], 16)), None)
    if dispatcher is None or dispatcher[-1].op not in ("jae", "ja", "jb", "jbe"):
        raise SystemExit(f"unsupported grouped owned dispatcher: {owner}")
    initial = [(index, item.args[1], immediate(item.args[0])) for index, item in enumerate(entry)
               if item.op == "movl" and len(item.args) == 2 and
               stack_range(item.args[1]) is not None and immediate(item.args[0]) is not None]
    if len(initial) != 1:
        raise SystemExit(f"unsupported grouped owned entry state: {owner}")
    index, state, _ = initial[0]
    state_span = stack_range(state)
    for item in entry[index + 1:]:
        if checked_stack_effect(item, owner) or overlaps(stack_write_range(item), state_span):
            raise SystemExit(f"linked image lost grouped owned entry state frame: {owner}")
    origins = {}
    compared = False
    for item in dispatcher:
        if checked_stack_effect(item, owner) or overlaps(stack_write_range(item), state_span):
            raise SystemExit(f"linked image lost grouped owned dispatcher state frame: {owner}")
        if item.op == "movl" and len(item.args) == 2:
            source, target = item.args
            origins[target] = origins.get(source, source if stack_range(source) is not None else None)
        elif item.op == "cmpl" and len(item.args) == 2:
            if immediate(item.args[0]) is None:
                raise SystemExit(f"unsupported grouped owned dispatcher pivot: {owner}")
            if origins.get(item.args[1]) != state:
                raise SystemExit(f"linked image lost grouped owned dispatcher state: {owner}")
            compared = True
        elif item.op.startswith("j"):
            break
        else:
            raise SystemExit(f"unsupported grouped owned dispatcher lowering: {owner}")
    if not compared:
        raise SystemExit(f"linked image lost grouped owned dispatcher state: {owner}")
    return state, dispatcher[0].address


def check_grouped_owned_query_flow(code, proof, owner):
    instructions = parse(code)
    if not instructions:
        raise SystemExit(f"linked image lost grouped owned query return flow: {owner}: empty function")
    sites = proof["sites"]
    expected = {site["label"]: tuple(source["word_label"] for source in site["sources"])
                for site in sites}
    if len(expected) != len(sites) or any(not words for words in expected.values()):
        raise SystemExit(f"linked image lost grouped owned query return flow: {owner}: site inventory")
    starts = {instructions[0].address}
    addresses = {instruction.address for instruction in instructions}
    for index, instruction in enumerate(instructions):
        if instruction.op.startswith("j"):
            target = re.match(r"^0x([0-9a-f]+)\b", instruction.operand_text)
            if target is None:
                raise SystemExit(f"unsupported grouped owned indirect branch: {owner}")
            address = int(target[1], 16)
            if instructions[0].address <= address <= instructions[-1].address and address not in addresses:
                raise SystemExit(f"unsupported grouped owned branch into instruction: {owner}")
            if address in addresses:
                starts.add(address)
        if (instruction.op.startswith(("j", "ret")) or instruction.op in ("ud2", "int3", "hlt")) and index + 1 < len(instructions):
            starts.add(instructions[index + 1].address)
    segments = []
    start = 0
    for index in range(1, len(instructions)):
        if instructions[index].address in starts:
            segments.append(instructions[start:index])
            start = index
    segments.append(instructions[start:])
    groups = [segment for segment in segments if any(HELPER in item.operand_text and item.op in ("call", "callq")
                                                   for item in segment)]
    if len(groups) != len(sites) or sum(sum(HELPER in item.operand_text and item.op in ("call", "callq")
                                        for item in group) for group in groups) != proof["query_count"]:
        raise SystemExit(f"linked image lost grouped owned query return flow: {owner}: group inventory")
    depths = reachable_stack_depths(segments, owner)
    state_slot, dispatcher = dispatcher_state_slot(segments, owner)
    if any(group[0].address not in depths for group in groups) or len({depths[group[0].address] for group in groups}) != 1:
        raise SystemExit(f"linked image lost grouped owned reachable query groups: {owner}")
    if depths.get(dispatcher) != depths[groups[0][0].address]:
        raise SystemExit(f"linked image lost grouped owned query stack frame: {owner}")
    for group in groups:
        if any(left.address + left.size != right.address for left, right in zip(group, group[1:])):
            raise SystemExit(f"unsupported grouped owned instruction gap: {owner}")
        if any(item.op in ("pushq", "popq") or item.args and item.args[-1] in STACK_POINTERS for item in group):
            raise SystemExit(f"unsupported grouped owned stack change within query group: {owner}")
    seen = set()
    state_slots = set()
    for group in groups:
        label, slot = check_group(group, expected, owner, dispatcher, state_slot)
        if label in seen:
            raise SystemExit(f"linked image lost grouped owned query return flow: {owner}: duplicate site {label}")
        seen.add(label)
        state_slots.add(slot)
    if seen != set(expected) or state_slots != {state_slot}:
        raise SystemExit(f"linked image lost grouped owned query return flow: {owner}: site/state mismatch")


def check_group(group, expected, owner, dispatcher, anchored_state):
    origins = {}
    constants = {}
    taints = {}
    identities = {}
    history = {}
    site = None
    words = []
    state = anchored_state
    returned = 0
    state_writes = []
    next_identity = 1

    def register_name(value):
        return ALIASES.get(value, value) if REGISTER.fullmatch(value) else value

    def value(table, operand):
        key = register_name(operand)
        if key in table:
            return table[key]
        return 0 if table is taints else immediate(operand) if table is constants else None

    def set_value(table, target, entry):
        table[register_name(target)] = entry

    def erase_callers():
        for register in CALLER_SAVED:
            origins.pop(register, None)
            constants.pop(register, None)
            taints.pop(register, None)
            identities.pop(register, None)
        for argument in ("0x20(%rsp)", "0x28(%rsp)", "0x30(%rsp)"):
            origins.pop(argument, None)
            constants.pop(argument, None)
            taints.pop(argument, None)
            identities.pop(argument, None)

    for instruction in group:
        op, args = instruction.op, instruction.args
        if op in ("call", "callq"):
            if HELPER not in instruction.operand_text or len(args) != 1:
                raise SystemExit(f"unsupported grouped owned intervening call: {owner}")
            label = value(constants, "0x20(%rsp)")
            word = value(constants, "0x28(%rsp)")
            current_state = value(origins, "0x30(%rsp)")
            if (label not in expected or word is None or current_state != anchored_state or
                    stack_range(current_state) is None or current_state in
                    ("0x20(%rsp)", "0x28(%rsp)", "0x30(%rsp)") or
                    (site is not None and site != label) or
                    (state is not None and state != current_state)):
                raise SystemExit(f"linked image lost grouped owned query state origin: {owner}")
            site, state = label, current_state
            words.append(word)
            erase_callers()
            returned += 1
            set_value(taints, "%eax", 1 << (returned - 1))
            set_value(identities, "%eax", next_identity)
            next_identity += 1
            continue
        if op.startswith(("j", "ret")) or op in ("ud2", "int3", "hlt"):
            if op not in ("jmp", "jmpq") or instruction is not group[-1]:
                raise SystemExit(f"unsupported grouped owned query terminator: {owner}")
            continue
        if op in ("nop", "nopl", "nopw", "nopq"):
            continue
        if op in ("cmpl", "cmpq", "testl", "testq"):
            continue
        if op in ("movl", "movq") and len(args) == 2:
            source, target = args
            width = 8 if op == "movq" else 4
            target_range = stack_range(target, width)
            if target_range is not None:
                state_store = (op == "movl" and target == anchored_state and site is not None and
                               returned == len(expected[site]))
                if overlaps(target_range, stack_range(anchored_state)) and not state_store:
                    raise SystemExit(f"linked image lost grouped owned state slot lifecycle: {owner}")
                arguments = ("0x20(%rsp)", "0x28(%rsp)", "0x30(%rsp)")
                if any(overlaps(target_range, stack_range(argument)) for argument in arguments) and not (
                        op == "movl" and target in arguments):
                    raise SystemExit(f"linked image lost grouped owned query argument bytes: {owner}")
            if returned and target_range is not None:
                protected = [stack_range(state)] if state else []
                protected.extend(stack_range(name) for name, mask in taints.items()
                                 if mask and stack_range(name) is not None and name != target)
                if any(target_range[0] < span[1] and span[0] < target_range[1]
                       for span in protected if span is not None) and (op != "movl" or target != state):
                    raise SystemExit(f"unsupported grouped owned overlapping stack write: {owner}")
            if op == "movq" and value(taints, source):
                raise SystemExit(f"unsupported grouped owned wide return move: {owner}")
            if op == "movl":
                origin = value(origins, source)
                if origin is None and STACK.fullmatch(source):
                    origin = source
                set_value(origins, target, origin)
                set_value(constants, target, value(constants, source))
                set_value(taints, target, value(taints, source))
                set_value(identities, target, value(identities, source))
                if returned and target == state:
                    state_writes.append(value(taints, source))
            else:
                set_value(origins, target, None)
                set_value(constants, target, None)
                set_value(taints, target, 0)
                set_value(identities, target, None)
            continue
        if op == "imull" and len(args) == 3 and REGISTER.fullmatch(args[-1]):
            factor, source, target = args
            zero = immediate(factor) == 0 or value(constants, source) == 0
            mask = 0 if zero else value(taints, source)
            set_value(taints, target, mask)
            set_value(constants, target, 0 if zero else None)
            set_value(origins, target, None)
            set_value(identities, target, next_identity if mask else None)
            next_identity += 1
            continue
        if len(args) == 2 and REGISTER.fullmatch(args[-1]):
            source, target = args
            source_identity = None
            restored = None
            known = None
            if op in ("shrl", "shll", "roll", "rorl"):
                shift = immediate(source)
                if shift is None or shift >= 32:
                    raise SystemExit(f"unsupported grouped owned shift: {owner}")
                mask = value(taints, target)
            elif op in ("xorl", "addl", "subl", "orl", "andl", "imull"):
                source_mask, target_mask = value(taints, source), value(taints, target)
                source_identity, target_identity = value(identities, source), value(identities, target)
                same = (source == target or value(identities, source) is not None and
                        value(identities, source) == value(identities, target))
                if ((op in ("xorl", "subl") and same) or
                        (op in ("andl", "imull") and (immediate(source) == 0 or value(constants, source) == 0 or value(constants, target) == 0)) or
                        (op == "orl" and (immediate(source) == 0xffffffff or value(constants, target) == 0xffffffff))):
                    mask = 0
                    known = 0 if op != "orl" else 0xffffffff
                else:
                    mask = source_mask | target_mask
                    known = None
                inverse = {"xorl": "xorl", "addl": "subl", "subl": "addl"}.get(op)
                previous = history.get(target_identity)
                restored = (previous if inverse and source_identity is not None and previous is not None and
                            previous[0] == inverse and previous[1] == source_identity else None)
                if restored is not None:
                    mask = restored[2]
                    known = None
            else:
                raise SystemExit(f"unsupported grouped owned query lowering: {owner} {op} {instruction.operand_text}")
            prior_mask, prior_identity = value(taints, target), value(identities, target)
            set_value(taints, target, mask)
            set_value(constants, target, known)
            set_value(origins, target, None)
            set_value(identities, target, (restored[3] if restored is not None else
                                         next_identity if mask else None))
            if mask and restored is None and op in ("xorl", "addl", "subl"):
                history[next_identity] = (op, source_identity, prior_mask, prior_identity)
            next_identity += 1
            continue
        raise SystemExit(f"unsupported grouped owned query lowering: {owner} {op} {instruction.operand_text}")
    if (site is None or tuple(words) != expected[site] or returned != len(expected[site]) or
            len(state_writes) != 1 or state_writes[0] != (1 << returned) - 1):
        raise SystemExit(f"linked image lost grouped owned query return flow: {owner} site{site}")
    last = group[-1]
    if last.op in ("jmp", "jmpq"):
        target = re.match(r"^0x([0-9a-f]+)\b", last.operand_text)
        delivered = target is not None and int(target[1], 16) == dispatcher
    else:
        delivered = last.address + last.size == dispatcher
    if not delivered:
        raise SystemExit(f"linked image lost grouped owned dispatcher route: {owner} site{site}")
    return site, state
