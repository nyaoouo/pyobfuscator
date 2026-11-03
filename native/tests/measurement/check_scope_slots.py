"""Actual v2 reserved material slots with the existing native Scope and finalizer."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from check_capture import ROOT
from check_functions import prepare_fixture
from finalize_references import finalize
from reference_plan import parse_plan
from reference_slots import MATERIAL_BYTES, locate, render_header, render_source
from release_material import create_material, material_fold
from scope_slot_inputs import write_inputs
from scope_slot_cases import check_cases

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "runtime_directory", "build_dir"): parser.add_argument(name, type=Path)
    for name in ("native", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--cmake", type=Path); parser.add_argument("--ninja", type=Path)
    args = parser.parse_args()
    if bool(args.cmake) != bool(args.ninja): parser.error("dependency checks require CMake and Ninja")
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="scope-slots-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        _, fragments, dll = prepare_fixture(args.compiler, directory)
        container, external = "11" * 16, "22" * 16
        value = {"schema_version": 2, "build_seed": "33" * 16, "container": container,
            "scope_materials": [0, 2], "records": []}
        selectors = ({"section": ".text"}, {"symbol": "extent_eh"},
            {"symbol": "extent_split", "aliases": ["extent_alias"], "fragments": ["extent_cold"]})
        for index, selector in enumerate(selectors):
            value["records"].append({"image": container if index == 0 else external, "owner": 7 + index,
                "subject": 0x701 + index, "kind": index + 1, "stage": 1 if index == 1 else 2,
                "capacity": 4096 + index * 8, "selector": selector})
        plan_path, header, source = (directory / name for name in ("plan.json", "reference_slots.hpp", "slots.cpp"))
        plan_path.write_text(json.dumps(value)); plan = parse_plan(plan_path.read_bytes())
        run([sys.executable, ROOT / "tools/prepare_references.py", plan_path, header, source])
        if header.read_text() != render_header(plan) or source.read_text() != render_source(plan):
            raise AssertionError("v2 preparation CLI differs from the frozen layout")
        includes = ["-I", ROOT / "src", "-I", ROOT / "include", "-I", directory]
        store, raw_path = directory / "slots.obj", directory / "raw.exe"
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *includes, "-c", source, "-o", store])
        run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else []), *includes,
            ROOT / "tests/measurement/scope_slot_probe.cpp", store, *args.native, *args.backend, "-lbcrypt", "-o", raw_path])
        material = create_material(); words = material_fold(material)
        materials = {index: bytes((byte + index) % 256 for byte in range(32)) for index in plan.scope_materials}
        paths = {index: directory / f"material-{index}.bin" for index in materials}
        for index, path in paths.items(): path.write_bytes(materials[index])
        material_path, inputs = directory / "release.json", directory / "inputs.bin"
        material_path.write_text(json.dumps(material)); write_inputs(inputs, plan_path, material_path, paths)
        raw = raw_path.read_bytes(); targets = {bytes.fromhex(external): dll.read_bytes()}; objects = {2: fragments.read_bytes()}
        filled, proof = finalize(raw, plan, words, targets=targets, objects=objects, materials=materials)
        again, repeated = finalize(filled, plan, words, targets=targets, objects=objects, materials=materials)
        if again != filled or not repeated["idempotent"] or proof["schema_version"] != 2:
            raise AssertionError("v2 material fill is not authenticated and idempotent")
        _, section, slots = locate(raw, plan)
        allowed = {(section.raw_offset + offset + byte) for record, offset in zip(plan.records, slots.offsets)
            for byte in range(record.identity.capacity)}
        allowed.update(section.raw_offset + offset + byte for offset in slots.material_offsets if offset
            for byte in range(MATERIAL_BYTES))
        if any(a != b and index not in allowed for index, (a, b) in enumerate(zip(raw, filled))) or len(raw) != len(filled):
            raise AssertionError("material fill changed bytes outside frozen slots")
        output, report = directory / "final.exe", directory / "final.json"
        cli = [sys.executable, ROOT / "tools/finalize_references.py", raw_path, plan_path, material_path]
        options = ["--target", f"{external}={dll}", "--object", f"2={fragments}"]
        for index, path in paths.items(): options += ["--scope-material", f"{index}={path}"]
        run([*cli, output, "--report", report, *options]); run([output, inputs, dll, "1"])
        run([raw_path, inputs, dll, "1"], succeeds=False)
        final = output.read_bytes()
        for index in plan.scope_materials:
            changed = bytearray(final); position = section.raw_offset + slots.material_offsets[index]
            changed[position + MATERIAL_BYTES - 1] ^= 1
            corrupt = directory / f"corrupt-{index}.exe"; corrupt.write_bytes(changed)
            refused = run([corrupt, inputs, dll, "1"], succeeds=False)
            if f"material failure at {index}" not in refused.stderr or "word0" not in refused.stderr:
                raise AssertionError("ciphertext corruption did not reach the actual scoped no-word failure")
        first, second = (section.raw_offset + slots.material_offsets[index] for index in plan.scope_materials)
        changed = bytearray(final); changed[first:first + MATERIAL_BYTES] = final[second:second + MATERIAL_BYTES]
        crossed = directory / "cross-owner.exe"; crossed.write_bytes(changed)
        refused = run([crossed, inputs, dll, "1"], succeeds=False)
        if "material failure at 0" not in refused.stderr or "word0" not in refused.stderr:
            raise AssertionError("another owner's ciphertext supplied the actual scoped word")
        check_cases(raw, filled, value, plan, words, targets, objects, materials, cli, options, output, report, paths, run)
        if args.cmake:
            from slot_pipeline import check_pipeline
            args.python = Path(sys.executable)
            check_pipeline(args, directory, plan_path, material_path, dll, fragments, inputs,
                args.native, run, scope_materials=paths)
        print("v2 selected self/external materials derive independent words from actual native observations; exact writes, stale/alias/negative and dependency controls pass")


if __name__ == "__main__": main()
