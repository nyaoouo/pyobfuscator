"""Check mixed POST entry states against independently derived CFF layout seeds."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_joint_machine_evidence import STACK, State, _dispatcher_state, _entry_spills, _graph, _instructions, _stack
from payload_binding import OWNER, WRAPPER
from post_mixed_binding import _plan


MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
OWNERS = (OWNER, WRAPPER)


def _next_random(state):
    state = (state + 0x9e3779b97f4a7c15) & MASK64
    value = state
    value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & MASK64
    return state, value ^ (value >> 31)


def _expected_state(owner, recipe):
    components = recipe.get("components")
    cfg = [item for item in components if type(item) is dict and
           item.get("component") == "cfg"] if type(components) is list else []
    if len(cfg) != 1 or type(cfg[0].get("seed")) is not int or not 0 <= cfg[0]["seed"] <= MASK32:
        raise ValueError(f"entry state lacks one unsigned CFG seed: {owner}")
    name_hash = 0xcbf29ce484222325
    for character in owner.encode("utf-8"):
        name_hash = ((name_hash ^ character) * 0x100000001b3) & MASK64
    random_state = ((cfg[0]["seed"] << 32) ^ name_hash) & MASK64
    random_state, _ = _next_random(random_state)  # transition salt precedes body states
    for _ in range(16):
        random_state, value = _next_random(random_state)
        candidate = value & MASK32
        if 4 <= candidate <= MASK32 - 4:
            return candidate
    raise ValueError(f"entry state generator exceeded its bounded candidate count: {owner}")


def _decoded_immediate(item):
    if (item.opcode != "movl" or len(item.operands) != 2 or
            not item.operands[0].startswith("$") or not STACK.fullmatch(item.operands[1])):
        raise ValueError("entry initializer is not an immediate stack write")
    raw = item.raw
    if (len(raw) < 7 or raw[0] != 0xc7 or (raw[1] & 0x38) or
            (raw[1] & 7) != 4 or raw[2] != 0x24):
        raise ValueError("entry initializer has unsupported C7 /0 stack encoding")
    mode = raw[1] >> 6
    if mode == 0 and len(raw) == 7:
        displacement = 0
    elif mode == 1 and len(raw) == 8:
        displacement = struct.unpack_from("<b", raw, 3)[0]
    elif mode == 2 and len(raw) == 11:
        displacement = struct.unpack_from("<i", raw, 3)[0]
    else:
        raise ValueError("entry initializer has unsupported C7 /0 displacement")
    match = STACK.fullmatch(item.operands[1])
    displayed_offset = int(match[1], 0) if match[1] else 0
    if displacement != displayed_offset:
        raise ValueError("entry initializer stack displacement differs from PE bytes")
    try:
        displayed = int(item.operands[0][1:], 0) & MASK32
    except ValueError as error:
        raise ValueError("entry initializer has invalid displayed immediate") from error
    observed = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    if displayed != observed:
        raise ValueError("entry initializer immediate differs from PE bytes")
    return observed


def _actual_state(image_bytes, code, owner):
    instructions = _instructions(code, image_bytes, owner)
    _, graph, _ = _graph(instructions, allow_indirect=True)
    frame, _ = _entry_spills(instructions, image_bytes)
    state_slot = _dispatcher_state(instructions, graph, frame)
    first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq", "jae"))
    initializers = [item for item in instructions if item.address < first_branch.address and
                    item.opcode == "movl" and len(item.operands) == 2 and
                    item.operands[0].startswith("$") and STACK.fullmatch(item.operands[1])]
    if len(initializers) != 1 or initializers[0].address + len(initializers[0].raw) != first_branch.address:
        raise ValueError(f"entry initializer is not unique and adjacent to dispatcher jump: {owner}")
    if _stack(initializers[0].operands[1], State(-frame, {}, {}, {}, {}, {}, {}, 0)) != state_slot:
        raise ValueError(f"entry initializer differs from dispatcher state slot: {owner}")
    return _decoded_immediate(initializers[0])


def verify_builder_entry_states(image_bytes: bytes, plan_bytes: bytes,
                                owner_codes: dict[str, str]) -> dict:
    """Match exact mixed owner PE entry values to their frozen recipe seeds."""
    if (type(image_bytes) is not bytes or not image_bytes or
            type(plan_bytes) is not bytes or not plan_bytes or
            type(owner_codes) is not dict or set(owner_codes) != set(OWNERS) or
            any(type(code) is not str or not code for code in owner_codes.values())):
        raise ValueError("entry state needs the actual PE, frozen plan and two owner disassemblies")
    plan = _plan(plan_bytes)
    owners = []
    for row in plan["owners"]:
        owner = row["owner"]
        expected = _expected_state(owner, row["recipe"])
        try:
            observed = _actual_state(image_bytes, owner_codes[owner], owner)
        except (StopIteration, ValueError) as error:
            raise ValueError(f"entry state machine shape differs for {owner}: {error}") from error
        if expected != observed:
            raise ValueError(f"entry state differs from frozen CFG seed: {owner}")
        owners.append({"owner": owner, "expected": expected, "observed": observed})
    return {"verified": True, "scope": "mixed-post-two-encoded-entry-states-v1",
            "owners": owners}
