"""Actual reserved-store finalization and loaded CNG/canonical-code consumers."""
import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

from check_capture import ROOT
from check_functions import prepare_fixture
from coff_symbols import image_symbols
from finalize_references import finalize
from reference_plan import parse_plan
from reference_slots import locate, render_header, render_source
from reference_slots import storage
from pe_layout import parse_image
from release_material import create_material, material_fold
from slot_cases import check_cases

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run


def check(args, directory, native):
    _, fragments, dll = prepare_fixture(args.compiler, directory)
    container, external = "11" * 16, "22" * 16
    value = {"schema_version": 1, "build_seed": "33" * 16, "container": container, "records": []}
    for index, selector in enumerate(({"section": ".text"}, {"symbol": "extent_eh"},
            {"symbol": "extent_split", "aliases": ["extent_alias"], "fragments": ["extent_cold"]})):
        value["records"].append({"image": container if index == 0 else external, "owner": 7 + index,
            "subject": 0x701 + index, "kind": index + 1, "stage": 1 + index % 2,
            "capacity": 4096 + index * 8, "selector": selector})
    plan_path, header, source = (directory / name for name in ("plan.json", "reference_slots.hpp", "slots.cpp"))
    plan_path.write_text(json.dumps(value)); plan = parse_plan(plan_path.read_bytes())
    run([sys.executable, ROOT / "tools/prepare_references.py", plan_path, header, source])
    if header.read_text() != render_header(plan) or source.read_text() != render_source(plan):
        raise AssertionError("preparation CLI differs from frozen source contract")
    store, raw_path = directory / "slots.obj", directory / "raw.exe"
    includes = ["-I", ROOT / "include", "-I", ROOT / "src", "-I", directory]
    run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *includes, "-c", source, "-o", store])
    run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else []), *includes,
        ROOT / "tests/measurement/slot_probe.cpp", store, *native, *args.backend, "-lbcrypt", "-o", raw_path])
    raw = raw_path.read_bytes(); material = create_material(); words = material_fold(material)
    targets, objects = {bytes.fromhex(external): dll.read_bytes()}, {2: fragments.read_bytes()}
    filled, report = finalize(raw, plan, words, targets=targets, objects=objects)
    again, second = finalize(filled, plan, words, targets=targets, objects=objects)
    if again != filled or not second["idempotent"] or report["idempotent"]:
        raise AssertionError("finalization replaced an existing authenticated reference")
    # Independent byte-difference set proves that only declared slots changed.
    _, section, slots = locate(raw, plan)
    allowed = {position for record, offset in zip(plan.records, slots.offsets)
        for position in range(section.raw_offset + offset, section.raw_offset + offset + record.identity.capacity)}
    if len(raw) != len(filled) or any(a != b and index not in allowed for index, (a, b) in enumerate(zip(raw, filled))):
        raise AssertionError("finalization changed bytes outside authored ciphertext slots")
    material_path, words_path, output, report_path = (directory / name for name in
        ("material.json", "words.bin", "final.exe", "final.json"))
    material_path.write_text(json.dumps(material)); words_path.write_bytes(struct.pack("<8I", *words))
    cli = [sys.executable, ROOT / "tools/finalize_references.py", raw_path, plan_path, material_path]
    options = ["--target", f"{external}={dll}", "--object", f"2={fragments}"]
    run([*cli, output, "--report", report_path, *options])
    final_data = output.read_bytes()
    run([output, words_path, dll, "1"])
    run([raw_path, words_path, dll, "1"], succeeds=False)
    parsed = parse_image(final_data)
    anchor = next(symbol for symbol in image_symbols(final_data, parsed) if symbol.name == "slot_anchor")
    part = parsed.layout.sections[anchor.section - 1]
    position = part.raw_offset + anchor.value
    mutated = bytearray(final_data); mutated[position] ^= 1
    tampered = directory / "changed-code.exe"; tampered.write_bytes(mutated)
    failure = run([tampered, words_path, dll, "1"], succeeds=False)
    if "actual code mismatch at 0" not in failure.stderr:
        raise AssertionError("changed final code did not reach the actual code/reference mismatch")
    changed = json.loads(json.dumps(value)); changed["records"][0]["owner"] += 1
    other_plan = parse_plan(json.dumps(changed).encode())
    prefix = storage(other_plan).prefix
    redirected = raw[:section.raw_offset] + prefix + raw[section.raw_offset + len(prefix):]
    redirected, _ = finalize(redirected, other_plan, words, targets=targets, objects=objects)
    tampered.write_bytes(redirected)
    failure = run([tampered, words_path, dll, "1"], succeeds=False)
    if "reference authentication/descriptor failure at 0" not in failure.stderr:
        raise AssertionError("compiled independent identity accepted coordinated slot metadata/key substitution")
    for alias in (raw_path, plan_path, material_path, dll, fragments):
        before = alias.read_bytes()
        run([*cli, alias, "--report", report_path, *options], succeeds=False)
        if alias.read_bytes() != before: raise AssertionError("refused output alias changed an input")
    run([*cli, output, "--report", output, *options], succeeds=False)
    if output.read_bytes() != final_data: raise AssertionError("refused report alias changed final image")
    check_cases(raw, filled, value, plan, words, targets, objects, finalize)
    if getattr(args, "cmake", None):
        from slot_pipeline import check_pipeline
        args.python = Path(sys.executable)
        check_pipeline(args, directory, plan_path, material_path, dll, fragments, words_path, native, run)
    print("self .text, external unwind interval and closed function references execute from actual reserved PE storage")
    return output


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "runtime_directory", "build_dir"): parser.add_argument(name, type=Path)
    parser.add_argument("--native", nargs="+", type=Path, required=True)
    parser.add_argument("--backend", nargs="+", type=Path, required=True)
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--cmake", type=Path)
    parser.add_argument("--ninja", type=Path)
    args = parser.parse_args()
    if bool(args.cmake) != bool(args.ninja): parser.error("CMake dependency test needs both cmake and ninja")
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="reference-slots-", dir=args.build_dir) as temporary:
        check(args, Path(temporary), args.native)


if __name__ == "__main__": main()
