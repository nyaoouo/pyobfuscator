"""Bounded linked call-route proof for the two schema4 query helpers."""

from collections import deque
import struct

from cff_joint_machine_evidence import DIRECT, MEASURED, OWNED, _instructions


BINDING = ("_ZN12pyobfuscator6native12contribution6scoped12_GLOBAL__N_1"
           "15require_bindingERKNS2_5ScopeERKNS0_21BootstrapContextLeaseE").lower()
OWNED_QUERY = ("_ZN12pyobfuscator6native12contribution7requestERKNS0_"
               "21BootstrapContextLeaseEjRKNS1_4SiteE").lower()
MEASURED_QUERY = ("_ZN12pyobfuscator6native12contribution6scoped5Scope5query"
                  "EjRKNS1_4SiteE").lower()
FAILURE = "_ZN12pyobfuscator6native8platform18protection_failureEj".lower()


def _target(item, kind):
    if len(item.operands) != 1 or (match := DIRECT.fullmatch(item.operands[0])) is None:
        raise ValueError(f"helper {kind} lacks a direct resolved target")
    if kind == "call":
        if len(item.raw) != 5 or item.raw[0] != 0xe8:
            raise ValueError("helper call has unsupported rel32 lowering")
        displacement = struct.unpack("<i", item.raw[1:])[0]
    elif (len(item.raw) == 2 and item.raw[0] ==
          {"je": 0x74, "jne": 0x75, "jae": 0x73, "jmp": 0xeb, "jmpq": 0xeb}.get(item.opcode)):
        displacement = struct.unpack("<b", item.raw[1:])[0]
    elif len(item.raw) == 5 and item.raw[0] == 0xe9 and item.opcode in ("jmp", "jmpq"):
        displacement = struct.unpack("<i", item.raw[1:])[0]
    elif (len(item.raw) == 6 and item.raw[:2] ==
          {"je": b"\x0f\x84", "jne": b"\x0f\x85", "jae": b"\x0f\x83"}.get(item.opcode)):
        displacement = struct.unpack("<i", item.raw[2:])[0]
    else:
        raise ValueError("helper branch has unsupported relative lowering")
    target = item.address + len(item.raw) + displacement
    if target != int(match[1], 16):
        raise ValueError(f"helper {kind} target differs from its PE bytes")
    return target, match[2]


def _check_cff_route(instructions, by_address, calls, targets):
    """Prove the binding dominates the query in a flattened helper body.

    Dispatcher states may enter the return or failure leaves on invalid input,
    so this proof deliberately concerns the acquisition call, not all exits.
    The live entry/return behavior is checked by the linked runtime fixture.
    """
    entry = instructions[0].address
    successors = {}
    for item in instructions:
        following = item.address + len(item.raw)
        if item.opcode in ("ret", "retq", "int3"):
            successors[item.address] = ()
            continue
        edges = []
        if item.opcode in ("je", "jne", "jae", "jmp", "jmpq"):
            branch, _ = _target(item, "branch")
            edges.append(branch)
        if item.opcode not in ("jmp", "jmpq"):
            edges.append(following)
        if any(edge not in by_address for edge in edges):
            raise ValueError("helper branch leaves its unwind interval")
        successors[item.address] = tuple(edges)

    binding = next(address for address, kind in calls.items() if kind == "binding")
    query = next(address for address, kind in calls.items() if kind == "query")
    if binding >= query:
        raise ValueError("helper binding call follows its query")
    # A path to the query with binding removed is a machine-level bypass,
    # regardless of the dispatcher's state encoding.
    pending, seen = [entry], set()
    while pending:
        address = pending.pop()
        if address in seen or address == binding:
            continue
        if address == query:
            raise ValueError("helper query bypasses binding call")
        seen.add(address)
        pending.extend(successors[address])
    pending, seen = [entry], set()
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        pending.extend(successors[address])
    if not {binding, query, next(address for address, kind in calls.items()
                                 if kind == "failure")}.issubset(seen):
        raise ValueError("helper lacks a reachable binding, query or failure route")
    if not any(by_address[address].opcode in ("ret", "retq") for address in seen):
        raise ValueError("helper has no reachable return")
    return targets


def _check_route(instructions, name):
    expected_query = {OWNED: OWNED_QUERY, MEASURED: MEASURED_QUERY}.get(name)
    if expected_query is None or not instructions:
        raise ValueError("helper route has an unsupported owner or empty body")
    by_address = {item.address: item for item in instructions}
    if len(by_address) != len(instructions):
        raise ValueError("helper route has duplicate instruction addresses")
    expected = {BINDING: "binding", expected_query: "query", FAILURE: "failure"}
    calls, targets = {}, {}
    for item in instructions:
        if item.opcode not in ("call", "callq"):
            continue
        target, symbol = _target(item, "call")
        if symbol not in expected:
            raise ValueError("helper call target differs from required route")
        kind = expected[symbol]
        if kind in targets:
            raise ValueError("helper has duplicate binding, query or failure calls")
        calls[item.address] = kind
        targets[kind] = target
    if set(targets) != {"binding", "query", "failure"}:
        raise ValueError("helper lacks a binding, query or failure call")
    if any(item.opcode == "jae" for item in instructions):
        return _check_cff_route(instructions, by_address, calls, targets)
    if [calls[address] for address in sorted(calls)] != ["binding", "query", "failure"]:
        raise ValueError("helper binding, query and failure calls have wrong order")

    pending = deque(((instructions[0].address, False, False, False),))
    seen = {}
    returns = traps = 0
    while pending:
        address, bound, queried, failed = pending.popleft()
        state = (bound, queried, failed)
        previous = seen.get(address)
        if previous is not None:
            if previous != state:
                raise ValueError("helper binding route has an ambiguous CFG merge")
            continue
        if len(seen) >= 256 or address not in by_address:
            raise ValueError("helper binding route exceeds its unwind interval")
        seen[address] = state
        item = by_address[address]
        if address in calls:
            kind = calls[address]
            if kind == "binding":
                if bound or queried or failed:
                    raise ValueError("helper binding call is repeated or late")
                bound = True
            elif kind == "query":
                if not bound:
                    raise ValueError("helper query bypasses binding call")
                if queried or failed:
                    raise ValueError("helper query call is repeated or late")
                queried = True
            else:
                if not queried or failed:
                    raise ValueError("helper failure call precedes query or repeats")
                failed = True
        if item.opcode in ("ret", "retq"):
            if not bound or not queried or failed:
                raise ValueError("helper returns without a bound query route")
            returns += 1
            continue
        if item.opcode == "int3":
            if not bound or not queried or not failed:
                raise ValueError("helper trap lacks its failure route")
            traps += 1
            continue
        next_address = address + len(item.raw)
        successors = []
        if item.opcode in ("je", "jne", "jmp", "jmpq"):
            branch, _ = _target(item, "branch")
            if branch <= address or branch not in by_address:
                raise ValueError("helper branch leaves or cycles within its unwind interval")
            successors.append(branch)
        if item.opcode not in ("jmp", "jmpq"):
            successors.append(next_address)
        for successor in successors:
            if successor not in by_address:
                raise ValueError("helper route falls outside its unwind interval")
            pending.append((successor, bound, queried, failed))
    if not returns or not traps or any(address not in seen for address in calls):
        raise ValueError("helper lacks a reachable bound query and failure route")
    return targets


def check_helper_routes(image_bytes, helper_codes):
    if not isinstance(helper_codes, dict) or set(helper_codes) != {OWNED, MEASURED}:
        raise ValueError("two helper disassemblies are required for route proof")
    routes = {name: _check_route(_instructions(helper_codes[name], image_bytes, name), name)
              for name in (OWNED, MEASURED)}
    if (routes[OWNED]["binding"] != routes[MEASURED]["binding"] or
            routes[OWNED]["failure"] != routes[MEASURED]["failure"]):
        raise ValueError("two helpers use different binding or failure targets")
