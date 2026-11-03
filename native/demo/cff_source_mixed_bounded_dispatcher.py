"""Bounded unsigned dispatcher-tree proof for three to eight schema4 sites."""

from cff_joint_machine_evidence import STACK, State, _stack


WORD_LIMIT = 1 << 32


def _slot(operand, frame):
    if not STACK.fullmatch(operand):
        raise ValueError("dispatcher has an unsupported state copy")
    return _stack(operand, State(-frame, {}, {}, {}, {}, {}, {}, 0))


def _leaf_groups(target, dispatcher, by_address, graph, calls):
    found = set()
    seen = set()
    address = target
    while address != dispatcher:
        if address in seen:
            raise ValueError("dispatcher leaf route has a cycle")
        seen.add(address)
        if address >= dispatcher or address not in by_address:
            raise ValueError("dispatcher leaf enters an ambiguous route")
        if address in calls:
            found.add(calls[address])
        successors = graph[address]
        if len(successors) > 1:
            raise ValueError("dispatcher leaf route has a conditional branch")
        if not successors:
            break
        address = successors[0]
    return found


def check_dispatcher_intervals(instructions, by_address, graph, dispatcher,
                               dispatcher_slot, frame, groups):
    """Prove local tree intervals and distinct PE routes to the real helper groups.

    This intentionally starts with an arbitrary 32-bit dispatcher state.  Entry
    initialization and return-state generation remain separate proof obligations.
    """
    calls = {entry[0].address: index for index, group in enumerate(groups)
             for entry in group}
    seen, leaves = set(), []
    pending = [(dispatcher, 0, WORD_LIMIT, None, None, None)]
    while pending:
        address, lower, upper, eax, scratch, comparison = pending.pop()
        if address in seen:
            raise ValueError("dispatcher tree has a cycle or ambiguous merge")
        if len(seen) >= 128:
            raise ValueError("dispatcher tree exceeds bounded scope")
        seen.add(address)
        item = by_address[address]
        next_address = item.address + len(item.raw)
        if item.opcode == "movl" and len(item.operands) == 2 and comparison is None:
            source, destination = item.operands
            if destination == "%eax":
                slot = _slot(source, frame)
                if slot == dispatcher_slot:
                    eax = "state"
                elif slot == scratch and scratch is not None:
                    eax = "state"
                else:
                    raise ValueError("dispatcher reads an unknown state copy")
            elif source == "%eax" and eax == "state" and STACK.fullmatch(destination):
                slot = _slot(destination, frame)
                if slot < dispatcher_slot + 4 and dispatcher_slot < slot + 4:
                    raise ValueError("dispatcher overwrites its state slot")
                if scratch is not None and scratch != slot:
                    raise ValueError("dispatcher has ambiguous state copies")
                scratch = slot
            else:
                raise ValueError("dispatcher has an unsupported state copy")
            pending.append((next_address, lower, upper, eax, scratch, None))
        elif item.opcode == "cmpl" and len(item.operands) == 2:
            source, destination = item.operands
            if (eax != "state" or destination != "%eax" or not source.startswith("$") or
                    item.raw[:1] != b"\x3d" or len(item.raw) != 5 or
                    by_address[next_address].opcode != "jae"):
                raise ValueError("dispatcher comparison does not read state imm32")
            try:
                pivot = int(source[1:], 0)
            except ValueError as error:
                raise ValueError("dispatcher comparison has invalid immediate") from error
            if not 0 <= pivot < WORD_LIMIT:
                raise ValueError("dispatcher comparison has invalid immediate")
            pending.append((next_address, lower, upper, eax, scratch, pivot))
        elif item.opcode == "jae" and comparison is not None:
            if len(graph[address]) != 2:
                raise ValueError("dispatcher has an ambiguous split")
            if not lower < comparison < upper:
                raise ValueError("dispatcher has an empty unsigned interval")
            branch, fallthrough = graph[address]
            pending.append((branch, comparison, upper, eax, scratch, None))
            pending.append((fallthrough, lower, comparison, eax, scratch, None))
        elif item.opcode in ("jmp", "jmpq") and comparison is None:
            if len(graph[address]) != 1 or graph[address][0] >= dispatcher:
                raise ValueError("dispatcher leaf has an unsupported target")
            leaves.append((lower, upper, graph[address][0]))
        else:
            raise ValueError("dispatcher has an unsupported instruction or branch")
    if len(leaves) < 2 or len({target for _, _, target in leaves}) != len(leaves):
        raise ValueError("dispatcher has duplicate or missing leaves")
    end = max(item.address for item in instructions if item.address >= dispatcher and
              item.opcode in ("jmp", "jmpq"))
    if any(item.address not in seen for item in instructions
           if dispatcher <= item.address <= end):
        raise ValueError("dispatcher contains an unvisited comparison or leaf")
    memberships = [_leaf_groups(target, dispatcher, by_address, graph, calls)
                   for _, _, target in leaves]
    if any(len(members) > 1 for members in memberships):
        raise ValueError("dispatcher leaf crosses helper groups")
    if sorted(next(iter(members)) for members in memberships if members) != list(range(len(groups))):
        raise ValueError("dispatcher helper groups lack distinct nonempty leaf intervals")
    return [(lower, upper, next(iter(members)) if members else None)
            for (lower, upper, _), members in zip(leaves, memberships)]
