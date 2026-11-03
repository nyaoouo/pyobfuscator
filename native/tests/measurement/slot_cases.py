"""Independent plan/layout/ciphertext/stale reference controls on actual linked PEs."""
import copy
import json
import struct

from pe_data_patch import Write, apply_writes
from pe_layout import parse_image
from reference_plan import parse_plan
from reference_slots import HEADER, MATERIAL_BYTES, locate, storage


def rejected(operation):
    try: operation()
    except ValueError: return
    raise AssertionError("invalid reference plan/finalization was accepted")


def check_cases(raw, filled, value, plan, words, targets, objects, finalize):
    count = 0
    for field, replacement in (("schema_version", True), ("build_seed", "00" * 16),
            ("container", "AB" * 16), ("records", [])):
        bad = copy.deepcopy(value); bad[field] = replacement
        rejected(lambda: parse_plan(json.dumps(bad).encode())); count += 1
    for field, replacement in (("owner", 0), ("subject", True), ("kind", 4), ("stage", 0),
            ("capacity", 247), ("capacity", 524289), ("image", "0" * 33), ("selector", {"section": ".data"})):
        bad = copy.deepcopy(value); bad["records"][0][field] = replacement
        rejected(lambda: parse_plan(json.dumps(bad).encode())); count += 1
    for bad in (b'{"schema_version":1,"schema_version":1}', b'[]', b'null', b'{}'):
        rejected(lambda: parse_plan(bad)); count += 1
    duplicate = copy.deepcopy(value); duplicate["records"].append(duplicate["records"][0])
    rejected(lambda: parse_plan(json.dumps(duplicate).encode())); count += 1
    _, section, slots = locate(raw, plan)
    pe = int.from_bytes(raw[60:64], "little")
    table = pe + 24 + int.from_bytes(raw[pe + 20:pe + 22], "little")
    index = parse_image(raw).layout.sections.index(section)
    header = table + index * 40
    def mutate(offset, blob, data=raw): return data[:offset] + blob + data[offset + len(blob):]
    for flag in (0x80000000, 0x20000000, 0x10000000, 0x02000000, 0x80):
        bad = mutate(header + 36, struct.pack("<I", section.flags | flag))
        rejected(lambda: locate(bad, plan)); count += 1
    for relative in (0, 16, 20, 24, 28, 32, HEADER.size, HEADER.size + 52, HEADER.size + 56):
        offset = section.raw_offset + relative
        bad = mutate(offset, bytes([raw[offset] ^ 1]))
        rejected(lambda: locate(bad, plan)); count += 1
    if section.raw_size > slots.size:
        bad = mutate(section.raw_offset + slots.size, b"\1")
        rejected(lambda: locate(bad, plan)); count += 1
    intervals = [(offset, record.identity.capacity) for offset, record in zip(slots.offsets, plan.records)]
    intervals.extend((offset, MATERIAL_BYTES) for offset in slots.material_offsets if offset)
    intervals.sort()
    for (left, capacity), (right, _) in zip(intervals, intervals[1:]):
        gap = left + capacity
        if gap < right:
            bad = mutate(section.raw_offset + gap, b"\1")
            rejected(lambda: locate(bad, plan)); count += 1
    # An OS relocation into the store would modify it after our file proof.
    bad = bytearray(raw)
    reloc = next(part for part in parse_image(raw).layout.sections if part.name == b".reloc")
    block_size = struct.unpack_from("<I", bad, reloc.raw_offset + 4)[0]
    struct.pack_into("<I", bad, reloc.raw_offset, section.rva)
    struct.pack_into("<H", bad, reloc.raw_offset + 8, 0xa000)
    if block_size < 12: raise AssertionError("fixture needs a real DIR64 block")
    rejected(lambda: locate(bytes(bad), plan)); count += 1
    # Loader-directory and writable/executable patch rejection are separate contracts.
    bad = mutate(pe + 24 + 112 + 10 * 8, struct.pack("<II", section.rva, 8))
    rejected(lambda: locate(bad, plan)); count += 1
    text = next(part for part in parse_image(raw).layout.sections if part.name == b".text")
    for writes in ((), (Write(text.raw_offset, b"x"),),
            (Write(section.raw_offset, b"xx"), Write(section.raw_offset + 1, b"x")),
            (Write(True, b"x"),), (Write(section.raw_offset, bytearray(1)),)):
        rejected(lambda: apply_writes(raw, writes)); count += 1
    for offset in (section.raw_offset + slots.offsets[0],
            section.raw_offset + slots.offsets[0] + 80, section.raw_offset + slots.offsets[0] + 150):
        bad = mutate(offset, bytes([filled[offset] ^ 1]), filled)
        rejected(lambda: finalize(bad, plan, words, targets=targets, objects=objects)); count += 1
    stale = mutate(text.raw_offset, bytes([filled[text.raw_offset] ^ 1]), filled)
    rejected(lambda: finalize(stale, plan, words, targets=targets, objects=objects)); count += 1
    changed = copy.deepcopy(value); changed["records"][0]["owner"] += 1
    changed_plan = parse_plan(json.dumps(changed).encode())
    if changed_plan.records[0].identity.build == plan.records[0].identity.build:
        raise AssertionError("selection not bound into pre-codegen identity")
    # Coordinated metadata replacement still cannot recalibrate filled ciphertext.
    alternate = storage(changed_plan)
    forged = mutate(section.raw_offset, alternate.prefix, filled)
    rejected(lambda: finalize(forged, changed_plan, words, targets=targets, objects=objects)); count += 1
    wrong_words = (words[0] ^ 1, *words[1:])
    rejected(lambda: finalize(filled, plan, wrong_words, targets=targets, objects=objects)); count += 1
    for binding, replacement in (("targets", {}), ("objects", {}),
            ("targets", {**targets, bytes(16): raw}), ("objects", {**objects, 99: b"x"})):
        arguments = {"targets": targets, "objects": objects}; arguments[binding] = replacement
        rejected(lambda: finalize(raw, plan, words, **arguments)); count += 1
    rejected(lambda: finalize(raw, plan, words, targets={next(iter(targets)): filled}, objects=objects)); count += 1
    print(f"{count} independent frozen-plan/store/authentication/stale/cycle/patch refusals pass")
