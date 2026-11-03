"""Actual generated bodies, independent CNG reads and mixed-epoch/omission refusals."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools")); sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run, verify_image
from check_capture import check_native
from code_observation import reference_digest
from coff_layout import parse_object
from function_inventory import Ownership, create, helpers
from function_subject import function_subject
from generated_function_subject import generated_function_subject
from generated_ownership import closure, graph
from pe_layout import parse_image, rva_section
from generated_slots import check_slots
from generated_archive import check_archive, check_shared
from untransformed_cases import check_untransformed


def encoded(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def refuses(callback, message):
    try: callback()
    except ValueError as error:
        if message not in str(error): raise AssertionError(f"wrong generated subject refusal: {error}") from error
    else: raise AssertionError("unproven generated helper code was admitted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "opt", "plugin", "objdump", "probe", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--previous-plugin", type=Path)
    parser.add_argument("--cmake", required=True, type=Path)
    parser.add_argument("--ninja", required=True, type=Path)
    parser.add_argument("--llvm-link", required=True, type=Path)
    parser.add_argument("--archive-ir", type=Path)
    parser.add_argument("--archive-report", type=Path)
    args = parser.parse_args()
    if bool(args.archive_ir) != bool(args.archive_report): parser.error("archive ownership needs its actual IR and report")
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="generated-subject-", dir=args.build_dir) as temporary, \
            os.add_dll_directory(str(args.runtime_directory.resolve())):
        directory = Path(temporary)
        recipe = directory / "recipe.json"
        recipe.write_bytes(encoded({"schema_version": 1, "functions": {"owned_root": {
            "components": {"call-frames": "required", "external-calls": "required"}}}}))
        check_shared(args, directory)
        if args.archive_ir: check_archive(args, directory, args.archive_ir, args.archive_report)
        for profile in ("none", "O2"):
            work = directory / profile; work.mkdir()
            source = ROOT / "tests/measurement/generated_fixture.ll"
            requested, requests = work / "requested.ll", work / "requests.json"
            options = [f"-pyobf-cff-config={recipe}"]
            run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests", *options,
                f"-pyobf-cff-requests-output={requests}", "-S", source, "-o", requested])
            if profile == "O2":
                optimized = work / "optimized.ll"
                run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", optimized]); requested = optimized
            output, report = work / "protected.ll", work / "coverage.json"
            transform = ["-passes=pyobf-native-cff", *options, f"-pyobf-cff-requests-input={requests}", "-verify-each", "-S", requested]
            run([args.opt, f"-load-pass-plugin={args.plugin}", *transform, f"-pyobf-cff-report={report}", "-o", output])
            check_untransformed(args, work, requested, output)
            if args.previous_plugin:
                previous, previous_report = work / "previous.ll", work / "previous.json"
                run([args.opt, f"-load-pass-plugin={args.previous_plugin}", *transform,
                    f"-pyobf-cff-report={previous_report}", "-o", previous])
                if previous.read_bytes() != output.read_bytes(): raise AssertionError("ownership reporting changed final executable IR")
            native, binary = work / "protected.obj", work / "protected.dll"
            run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", output, "-o", native])
            run([args.compiler, "-shared", "-fno-lto", native, ROOT / "tests/measurement/generated_support.cpp", "-o", binary])
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump], binary, report, work / "final.json")
            original, final = native.read_bytes(), binary.read_bytes()
            proof = Ownership(create(original, output.read_bytes(), report.read_bytes()), report.read_bytes())
            names = helpers(original, proof, "owned_root")
            if len(names) != 2 or {edge[2] for edge in graph(proof.report)[1]} != {"call-frames", "external-calls"}:
                raise AssertionError("fixture lost actual internal/external generated helpers")
            subject = generated_function_subject(original, final, parse_image(final), 0x601, "owned_root", proof)
            if len(subject.ranges) != 3: raise AssertionError("generated subject silently covered only its root")
            ordinary = function_subject(original, final, parse_image(final), subject.tag, "ordinary_callee")
            if set(ordinary.ranges) & set(subject.ranges): raise AssertionError("ordinary callee was guessed into generated ownership")
            rows, edges = graph(proof.report)
            projected = (("owned_root", names[0], "call-frames", "first"), (names[0], names[1], "external-calls", "second"))
            if closure(rows, projected, "owned_root") != names: raise AssertionError("ownership traversal lost a transitive descendant")
            check_native(args.probe, args.runtime_directory, work, binary, final, parse_image(final), subject)
            execute(binary)
            root = function_subject(original, final, parse_image(final), subject.tag, "owned_root")
            initial = reference_digest(final, parse_image(final), subject, 7)
            for index, name in enumerate(names):
                helper = function_subject(original, final, parse_image(final), subject.tag, name)
                span = helper.ranges[0]; part = rva_section(parse_image(final), span.rva, span.size)
                changed = bytearray(final); changed[part.raw_offset + span.rva - part.rva + span.size - 1] ^= 1; changed = bytes(changed)
                if reference_digest(changed, parse_image(changed), root, 7) != reference_digest(final, parse_image(final), root, 7) or \
                        reference_digest(changed, parse_image(changed), subject, 7) == initial:
                    raise AssertionError("generated helper modification was lost or credited to the untouched root")
                damaged = work / f"changed-{index}.dll"; damaged.write_bytes(changed)
                check_native(args.probe, args.runtime_directory, work, damaged, changed, parse_image(changed), subject)
                refuses(lambda changed=changed: generated_function_subject(original, changed, parse_image(changed),
                    subject.tag, "owned_root", proof), "exact relocation evaluation")
            mutation_cases(original, output.read_bytes(), proof, final, subject)
            check_slots(args, work, native, output, report, refuses)
    print("actual none/O2 internal/external helpers: whole contributions, independent native CNG reads, execution and helper/epoch/inventory mutations pass")


def execute(binary):
    library = ctypes.WinDLL(str(binary.resolve()))
    try:
        function = library.owned_root; function.argtypes = [ctypes.c_uint]; function.restype = ctypes.c_uint
        for value in (0, 1, 7, 30, 31, 100, 0xffffffff):
            prior = ((((value * 3) & 0xffffffff) ^ 85) + 17) & 0xffffffff
            expected = (prior ^ 17) if value < 31 else (prior + value) & 0xffffffff
            if function(value) != expected: raise AssertionError("actual helper body changed source results")
    finally:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.FreeLibrary.argtypes = [ctypes.c_void_p]; kernel.FreeLibrary.restype = ctypes.c_int
        if not kernel.FreeLibrary(library._handle): raise OSError(ctypes.get_last_error(), "release generated fixture")


def mutation_cases(original, ir, proof, final, subject):
    data = json.loads(proof.report)
    changed = dict(data); changed.pop("generated_ownership")
    refuses(lambda: graph(encoded(changed)), "missing or unknown")
    changed = json.loads(proof.report); changed["generated_ownership"]["verified"] = False
    refuses(lambda: graph(encoded(changed)), "verified compiler")
    changed = json.loads(proof.report); changed["generated_ownership"]["edges"].pop()
    refuses(lambda: graph(encoded(changed)), "call obligations")
    changed = json.loads(proof.report); changed["functions"] = [row for row in changed["functions"] if not row.get("generated")]
    refuses(lambda: graph(encoded(changed)), "actual registered")
    changed = json.loads(proof.report); changed["generated_ownership"]["edges"][0]["component"] = "ordinary-call"
    refuses(lambda: graph(encoded(changed)), "registered")
    changed = json.loads(proof.report)
    declarations = [row for row in changed["functions"] if row.get("generated")]
    for row in changed["functions"]:
        for part in row.get("components", []):
            if part["component"] in ("call-frames", "external-calls"): part["applied"] = 0
    cycle = []
    for index, row in enumerate(declarations):
        owner = declarations[1 - index]
        row["generated_owner"] = owner["function"]
        kind = row["generation_component"]
        next(part for part in owner["components"] if part["component"] == kind)["applied"] = 1
        cycle.append({"owner": owner["function"], "helper": row["function"], "component": kind, "site": row["generated_site"]})
    changed["generated_ownership"]["edges"] = cycle
    refuses(lambda: graph(encoded(changed)), "dependency cycle")
    changed = json.loads(proof.manifest); changed["edges"].pop()
    refuses(lambda: helpers(original, Ownership(encoded(changed), proof.report), "owned_root"), "independent compiler report")
    refuses(lambda: helpers(original, Ownership(proof.manifest, proof.report + b" "), "owned_root"), "stale")
    refuses(lambda: helpers(original + b"x", proof, "owned_root"), "stale")
    obj = parse_object(original)
    name = helpers(original, proof, "owned_root")[0]
    helper = next(symbol for symbol in obj.symbols if symbol.name == name and symbol.type == 0x20)
    changed = bytearray(original); changed[obj.sections[helper.section - 1].offset] ^= 1; changed = bytes(changed)
    refreshed = Ownership(create(changed, ir, proof.report), proof.report)
    refuses(lambda: generated_function_subject(changed, final, parse_image(final), subject.tag, "owned_root", refreshed),
        "exact relocation evaluation")


if __name__ == "__main__": main()
