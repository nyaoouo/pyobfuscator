"""Versioned selection, authenticated material replay and CLI input controls."""
import copy
import hashlib
import json

from finalize_references import finalize
from reference_plan import parse_plan
from reference_slots import MATERIAL_BYTES, locate, render_header, render_source, storage
from slot_cases import check_cases as reference_cases, rejected


def check_cases(raw, filled, value, plan, words, targets, objects, materials,
        cli, options, output, report, paths, run):
    legacy = copy.deepcopy(value); legacy["schema_version"] = 1; del legacy["scope_materials"]
    for index, record in enumerate(legacy["records"]): record["stage"] = 1 + index % 2
    legacy = parse_plan(json.dumps(legacy).encode())
    # Frozen from ca8d654, before the v2 layout was introduced.
    for data, digest in ((storage(legacy).prefix, "86fdd90630a37dac983c7bcefb7ed8fc6fc8214a89426f45f5f04e7f47316cb7"),
            (render_header(legacy).encode(), "b3db3a67f6cfe6fb2e79f9d462978c8c9bbe0eca60e3812474413570f550c75e"),
            (render_source(legacy).encode(), "a8dad4e80992b42c0cc861d9a468d0c6927385eb426e183845b39ee77808416b")):
        if hashlib.sha256(data).hexdigest() != digest:
            raise AssertionError("schema1 directory or generated source/header bytes changed")
    def complete(image, selected, private, **arguments):
        return finalize(image, selected, private, materials=materials, **arguments)
    reference_cases(raw, filled, value, plan, words, targets, objects, complete)
    count = 0
    for indices in ([], None, True, "0", [True], [-1], [3], [0, 0], [2, 0], [1]):
        changed = copy.deepcopy(value); changed["scope_materials"] = indices
        rejected(lambda: parse_plan(json.dumps(changed).encode())); count += 1
    changed = copy.deepcopy(value); changed["schema_version"] = 1
    rejected(lambda: parse_plan(json.dumps(changed).encode())); count += 1
    _, section, slots = locate(filled, plan)
    packages = {index: filled[section.raw_offset + offset:section.raw_offset + offset + record.identity.capacity]
        for index, (record, offset) in enumerate(zip(plan.records, slots.offsets))}
    encrypted = {index: filled[section.raw_offset + slots.material_offsets[index]:
        section.raw_offset + slots.material_offsets[index] + MATERIAL_BYTES] for index in plan.scope_materials}
    options_host = {"targets": targets, "objects": objects, "materials": materials}
    exact, _ = finalize(raw, plan, words, **options_host, packages=packages, material_packages=encrypted)
    if exact != filled: raise AssertionError("presealed material replay changed exact final bytes")
    for bad in ({}, {False: materials[0], 2: materials[2]}, {**materials, 1: bytes(32)},
            {**materials, 0: bytes(31)}, {**materials, 0: bytearray(32)}, []):
        rejected(lambda: finalize(raw, plan, words, targets=targets, objects=objects, materials=bad)); count += 1
    for bad in ({}, {False: encrypted[0], 2: encrypted[2]}, {**encrypted, 1: bytes(MATERIAL_BYTES)},
            {**encrypted, 0: encrypted[0][:-1]}, {**encrypted, 0: bytearray(encrypted[0])}):
        rejected(lambda: finalize(raw, plan, words, **options_host, material_packages=bad)); count += 1
    for position in (0, 12, 40, 80, MATERIAL_BYTES - 1):
        altered = bytearray(encrypted[0]); altered[position] ^= 1
        rejected(lambda: finalize(raw, plan, words, **options_host,
            material_packages={**encrypted, 0: bytes(altered)})); count += 1
    other_material = bytes([materials[0][0] ^ 1]) + materials[0][1:]
    rejected(lambda: finalize(filled, plan, words, targets=targets, objects=objects,
        materials={**materials, 0: other_material})); count += 1
    alternative = finalize(raw, plan, words, **options_host)[0]
    replacement = alternative[section.raw_offset + slots.material_offsets[0]:
        section.raw_offset + slots.material_offsets[0] + MATERIAL_BYTES]
    rejected(lambda: finalize(filled, plan, words, **options_host,
        material_packages={**encrypted, 0: replacement})); count += 1
    rejected(lambda: finalize(raw, plan, words, **options_host,
        material_packages={0: encrypted[2], 2: encrypted[0]})); count += 1
    for path in paths.values():
        before = path.read_bytes()
        run([*cli, path, "--report", report, *options], succeeds=False)
        if path.read_bytes() != before: raise AssertionError("refused output alias overwrote early material")
        count += 1
    before = output.read_bytes()
    run([*cli, output, "--report", output, *options], succeeds=False)
    for binding in (f"00={paths[0]}", f"True={paths[0]}", f"3={paths[0]}", f"0={paths[0]}"):
        run([*cli, output, "--report", report, *options, "--scope-material", binding], succeeds=False); count += 1
    if output.read_bytes() != before: raise AssertionError("refused material CLI input changed final artifact")
    print(f"{count} scoped plan/material/ciphertext/replay/owner/alias/CLI refusals pass")
