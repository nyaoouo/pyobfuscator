"""Actual bootstrap phase/key/code negatives and independent composed finalization."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools")); sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run, verify_image
from owner_reader_image import checker_arguments
from coff_symbols import image_symbols
from finalize_measured_release import finalize, verify
from finalize_references import finalize as references
from pe_layout import parse_image
from pe_release_record import locate_record
from reference_plan import parse_plan
from reference_slots import locate
from release_material import material_fold, parse_material
from measured_release_cases import completion_cases
from measured_dependency_cases import dependency_case
from post_subjects import artifact_arguments, read_artifacts


def rejects(function):
    try: function()
    except ValueError: return
    raise AssertionError("measured completion accepted malformed/stale data")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "objdump", "image", "raw_image", "plan", "material", "draft", "report",
            "reference_object", "record_object", "reference_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--coverage", type=Path); parser.add_argument("--object", type=Path)
    parser.add_argument("--sources", nargs="+", type=Path)
    parser.add_argument("--blocked", action="store_true")
    parser.add_argument("--cmake", type=Path)
    parser.add_argument("--dependency-target")
    parser.add_argument("--backend", nargs="+", type=Path, required=True)
    parser.add_argument("--post-input", nargs=5, type=Path, metavar=("PRIVATE", "ROOT", "CHILD", "REPORT", "PLAN"))
    artifact_arguments(parser)
    args = parser.parse_args()
    if bool(args.object) == bool(args.sources) or (args.coverage and not args.object): parser.error("choose actual object and optional CFF report or ordinary source inputs")
    if (args.post_subjects or args.post_object or args.post_ownership or args.post_ownership_report) and not args.post_input:
        parser.error("function subjects need explicit post inputs")
    if bool(args.cmake) != bool(args.dependency_target): parser.error("dependency check needs both CMake and its target")
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    raw, final = args.raw_image.read_bytes(), args.image.read_bytes()
    plan, material, draft = parse_plan(args.plan.read_bytes()), parse_material(args.material.read_bytes()), args.draft.read_bytes()
    finish, inspect = finalize, verify
    reference_options = {}
    if args.post_input:
        from finalize_post_release import finalize as finalize_post, verify as verify_post
        from prepare_scope_material import read_material
        from release_plan import parse_plan as release_plan
        from post_reference_plan import INNER_ROLE
        from bootstrap_reference_plan import create as bootstrap_plan
        private, root, child, child_report, child_plan = args.post_input
        post = (private.read_bytes(), read_material(root), child.read_bytes(), child_report.read_bytes(), release_plan(child_plan.read_bytes()),
            "pyobf_native_demo_outer_unfinalized")
        material_bytes = args.material.read_bytes()
        post_options = read_artifacts(args, plan)
        def parameters(selection, early, record):
            return (selection, material_bytes if early == material else json.dumps(early).encode(), record, *post)
        def finish(image, selection, early, record): return finalize_post(image, *parameters(selection, early, record), pre_release=True, **post_options)
        def inspect(image, completed, selection, early, record): return verify_post(image, completed,
            *parameters(selection, early, record), pre_release=True, **post_options)
        reference_options = {"targets": {bootstrap_plan(material_bytes, INNER_ROLE).container: post[2]},
            "materials": {index: post[1] for index in plan.scope_materials}, "objects": post_options["objects"]}
        if "ownership" in post_options: reference_options["ownership"] = post_options["ownership"]
    report = inspect(raw, final, plan, material, draft)
    if report != json.loads(args.report.read_text()): raise AssertionError("composed proof does not name exact final bytes")
    completed, repeated = finish(final, plan, material, draft)
    if completed != final or not repeated["idempotent"]: raise AssertionError("measured finalization is not idempotent")
    _, section, slots = locate(final, plan); slot = section.raw_offset + slots.offsets[0]; capacity = plan.records[0].identity.capacity
    _, record = locate_record(final, version=2)
    packages = {0: final[slot:slot + capacity]}
    words = material_fold(material)
    for bad in ({}, {False: packages[0]}, {1: packages[0]}, {0: bytearray(packages[0])}, {0: packages[0][:-1]}):
        rejects(lambda bad=bad: references(raw, plan, words, packages=bad, **reference_options))
    bad = bytearray(packages[0]); bad[-1] ^= 1
    rejects(lambda: references(raw, plan, words, packages={0: bytes(bad)}, **reference_options))
    alternative = references(raw, plan, words, **reference_options)[0][slot:slot + capacity]
    rejects(lambda: references(final, plan, words, packages={0: alternative}, **reference_options))
    marker = next(symbol for symbol in image_symbols(final, parse_image(final)) if
        "reconstruct_payload_key" in symbol.name and symbol.type == 0x20 and symbol.section > 0)
    code_section = parse_image(final).layout.sections[marker.section - 1]
    offset = code_section.raw_offset + marker.value
    if not code_section.flags & 0x20000000: raise AssertionError("code negative is not executable")
    with tempfile.TemporaryDirectory(prefix="measured-bootstrap-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        if not args.post_input: completion_cases(args, directory, raw, final, plan, material, draft, run, rejects)
        probe = directory / "phase.raw.exe"
        hashes = [source for source in args.backend if source.name == "hash.cpp"]
        if len(hashes) != 1: raise AssertionError("measured phase fixture requires exact actual SHA backend")
        actual_hash = directory / "hash.actual.obj"
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-Dhash_sha256=hash_sha256_actual",
            "-I", ROOT / "include", "-c", hashes[0], "-o", actual_hash])
        post_definitions = ["-DPYOBF_DEMO_POST_CODE_HASH=1"] if args.post_input else []
        run([args.compiler, "-std=c++17", "-O2", "-DPYOBF_DEMO_PRE_CODE_HASH=1", *post_definitions, "-I", ROOT / "include",
            "-I", ROOT / "src", "-I", ROOT / "demo", "-I", args.build_dir, "-I", args.reference_directory,
            ROOT / "demo/measured_release_probe.cpp", ROOT / "src/path_fold/marker.cpp", *([args.object] if args.object else args.sources),
            args.reference_object, args.record_object, *[source for source in args.backend if source not in hashes],
            actual_hash, "-lbcrypt", "-o", probe])
        binary = directory / "phase.exe"; binary.write_bytes(finish(probe.read_bytes(), plan, material, draft)[0])
        if args.coverage:
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump,
                *checker_arguments(args.object, Path(str(args.object) + ".ownership.json"), args.plan)],
                binary, args.coverage, directory / "phase.final.json")
        for phase in (*range(7), 7, 0xffffffff): run([binary, "phase", phase])
        for mode in ("wrong-lease", "closed", "repeated", "reference-hash-failed", "code-hash-failed", "key-hash-failed"):
            run([binary, mode])
        run([binary, "dll", args.image, -2 if args.blocked else 16])
        cases = []
        for name, position, status in (("code", offset, -8), ("reference", slot + capacity - 1, -8), ("mask", record + 24, -4)):
            data = bytearray(final); data[position] ^= 1; cases.append((name, bytes(data), status))
        data = bytearray(final); data[slot:slot + capacity] = bytes(capacity); cases.append(("missing", bytes(data), -8))
        data = bytearray(final); data[record:record + 64] = draft; cases.append(("v1", bytes(data), -8))
        for name, data, status in cases:
            path = directory / (name + ".dll"); path.write_bytes(data)
            run([binary, "dll", path, -2 if args.blocked else status])
            rejects(lambda data=data: inspect(raw, data, plan, material, draft))
        wrong = copy.deepcopy(material); wrong["seed"] ^= 1
        rejects(lambda: finish(final, plan, wrong, draft))
    if report["image_after_sha256"] != hashlib.sha256(final).hexdigest(): raise AssertionError("final digest stale")
    if args.cmake: dependency_case(args, plan, material, draft, run, verifier=inspect)
    print("actual measured bootstrap: correct-fold7 phases+2unknown,typed origin errors,wrong lease/closed/repeat/retirement,code/reference/mask/missing/v1 denials and authenticated data-only/idempotent completion pass")


if __name__ == "__main__": main()
