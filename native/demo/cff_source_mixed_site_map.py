"""Bounded linked Windows x64 mapping for two explicit schema4 source sites."""

from collections import deque

from cff_joint_machine_evidence import (DIRECT, MEASURED, OWNED, STACK, _instructions,
    ReturnExpressions, State, _dispatcher_state, _entry_spills, _graph, _join,
    _stack, _transfer)
from cff_source_mixed_numeric import check_numeric_sensitivity
from cff_source_mixed_dispatcher import check_dispatcher_intervals
from cff_source_mixed_helper_writes import check_helper_direct_writes
from cff_source_mixed_helper_routes import check_helper_routes


def _fail(reason, owner):
    raise SystemExit(f"source-mixed linked site map {reason}: {owner}")


def _argument_states(instructions, graph):
    """Keep only values shared by every reachable predecessor of each call."""
    by_address = {item.address: item for item in instructions}
    incoming = {instructions[0].address: {}}
    pending = deque((instructions[0].address,))
    while pending:
        address = pending.popleft()
        item = by_address[address]
        values = incoming[address].copy()
        if item.opcode in ("call", "callq"):
            values.clear()
        elif (item.opcode not in ("cmpl", "jae", "jmp", "jmpq", "ret", "retq") and
                item.operands and (match := STACK.fullmatch(item.operands[-1]))):
            offset = int(match[1], 0) if match[1] else 0
            width = {"b": 1, "w": 2, "l": 4, "q": 8}.get(item.opcode[-1:], 8)
            for key in (0x20, 0x28):
                if offset < key + 4 and key < offset + width:
                    values.pop(key, None)
            if (item.opcode == "movl" and len(item.operands) == 2 and
                    offset in (0x20, 0x28) and item.operands[0].startswith("$")):
                values[offset] = int(item.operands[0][1:], 0) & 0xffffffff
        for successor in graph[address]:
            old = incoming.get(successor)
            merged = values if old is None else {
                key: value for key, value in old.items() if values.get(key) == value}
            if old != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming


def _return_route(instructions, graph, calls, state, frame, spills, dispatcher,
                  dispatcher_slot, owner):
    by_address = {item.address: item for item in instructions}
    predecessors = {item.address: set() for item in instructions}
    for address, successors in graph.items():
        for successor in successors: predecessors[successor].add(address)
    expressions = ReturnExpressions()
    bits = {item.address: 1 << index for index, item in enumerate(calls)}
    seen, writes = set(), []
    cursor, previous = calls[0].address, None
    state = state.copy()
    while True:
        # The final generated gateway can be laid out immediately before the
        # shared dispatcher. Its final state write then falls through rather
        # than encoding a jump; the dispatcher necessarily has other callers.
        if cursor == dispatcher and previous is not None:
            if (graph[previous] != (cursor,) or
                    previous + len(by_address[previous].raw) != cursor or
                    seen != set(bits) or
                    len(writes) != 1 or
                    writes[0].dependencies != (1 << len(calls)) - 1):
                _fail("has a detached or bypassed fallthrough to dispatcher", owner)
            return
        item = by_address[cursor]
        if previous is not None and predecessors[cursor] != {previous}:
            _fail("has a bypassing query-return predecessor", owner)
        if item.opcode in ("jmp", "jmpq"):
            if (len(item.operands) != 1 or
                    int(DIRECT.fullmatch(item.operands[0])[1], 16) != dispatcher or
                    seen != set(bits) or len(writes) != 1 or
                    writes[0].dependencies != (1 << len(calls)) - 1):
                _fail("has a detached or misrouted return-to-dispatcher path", owner)
            return
        if item.opcode in ("jae", "ret", "retq"):
            _fail("branches before the query state update", owner)
        if item.opcode in ("call", "callq"):
            if item.address not in bits or item.address in seen:
                _fail("has an intervening or repeated helper call", owner)
            seen.add(item.address)
            if state.origin_slots.get(state.rsp + 0x30) != dispatcher_slot:
                _fail("passes a decoy state origin", owner)
        if (item.opcode not in ("cmpl", "jae") and len(item.operands) >= 2 and
                (target := _stack(item.operands[-1], state)) is not None):
            width = {"b": 1, "w": 2, "l": 4, "q": 8}.get(item.opcode[-1:], 8)
            if target < dispatcher_slot + 4 and dispatcher_slot < target + width:
                if (item.opcode != "movl" or len(item.operands) != 2 or
                        target != dispatcher_slot):
                    _fail("overwrites or aliases the dispatcher state slot", owner)
                writes.append(expressions.read(item.operands[0], state))
        expressions.transfer(item, state)
        if item.address in bits:
            expressions.registers["rax"] = expressions.intern(
                ("site-helper-return", item.address), bits[item.address])
        state = _transfer(item, state, frame, spills)
        previous = cursor
        cursor += len(item.raw)
        if cursor not in by_address:
            _fail("leaves the selected instruction interval", owner)


def check_two_site_map(code, proof, owner, image_bytes, helper_codes=None):
    sites = proof.get("sites", ())
    if (proof.get("scheme_version") != 4 or proof.get("provider") != "source-mixed-v1" or
            proof.get("joint_helper_contract") != "source-mixed-context-v1" or
            len(sites) != 2 or [site.get("label") for site in sites] !=
            sorted(site.get("label") for site in sites)):
        _fail("requires two canonical explicit schema4 sites", owner)
    try:
        instructions = _instructions(code, image_bytes, owner)
        by_address, graph, callers = _graph(instructions, allow_indirect=True)
        frame, spills = _entry_spills(instructions, image_bytes)
        dispatcher_slot = _dispatcher_state(instructions, graph, frame)
    except ValueError as error:
        _fail(str(error), owner)
    first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq", "jae"))
    dispatcher = graph[first_branch.address][0]
    helpers = {OWNED: "owned-context-v1", MEASURED: "measured-scope-v1"}
    arguments = _argument_states(instructions, graph)
    observed = []
    for item in callers:
        target = DIRECT.fullmatch(item.operands[0])[2]
        if target not in helpers: continue
        values = arguments.get(item.address, {})
        if 0x20 not in values or 0x28 not in values:
            _fail("has missing, bypassed or ambiguous site/source arguments", owner)
        observed.append((item, values[0x20], values[0x28], helpers[target]))
    if len(observed) != proof.get("query_count"):
        _fail("helper count differs from the compiler report", owner)
    groups = []
    for entry in observed:
        if not groups or groups[-1][0][1] != entry[1]: groups.append([])
        groups[-1].append(entry)
    if len(groups) != 2 or len({group[0][1] for group in groups}) != 2:
        _fail("has missing, duplicate or ambiguous site groups", owner)
    expected = {site["label"]: [(source["word_label"], source["provider"])
                                   for source in site["sources"]] for site in sites}
    for group in groups:
        label = group[0][1]
        if label not in expected:
            _fail("contains an unknown site label", owner)
        actual = [(entry[2], entry[3]) for entry in group]
        if actual != expected[label]:
            _fail(f"site {label} has wrong ordered source providers", owner)
    try:
        _transfer.entry = instructions[0].address
        states = {instructions[0].address: State(0, {"rcx": "lease", "rdx": "scope"},
            {}, {}, {}, {}, {}, 0)}
        pending = deque((instructions[0].address,))
        while pending:
            address = pending.popleft()
            state = _transfer(by_address[address], states[address], frame, spills)
            for successor in graph[address]:
                old = states.get(successor)
                merged = state if old is None else _join(old, state)
                if old != merged:
                    states[successor] = merged
                    pending.append(successor)
        if any(item.address not in states for group in groups for item, *_ in group):
            _fail("contains an unreachable or decoy helper group", owner)
        for group in groups:
            calls = [entry[0] for entry in group]
            _return_route(instructions, graph, calls, states[calls[0].address], frame,
                          spills, dispatcher, dispatcher_slot, owner)
            check_numeric_sensitivity(instructions, graph, calls, states[calls[0].address],
                                      frame, dispatcher, dispatcher_slot)
        intervals = check_dispatcher_intervals(instructions, by_address, graph, dispatcher,
                                               dispatcher_slot, frame, groups)
        if helper_codes is not None:
            check_helper_direct_writes(image_bytes, helper_codes)
            check_helper_routes(image_bytes, helper_codes)
        return [(lower, upper, groups[index][0][1] if index is not None else None)
                for lower, upper, index in intervals]
    except ValueError as error:
        _fail(str(error), owner)
