"""Actual two-module post-release operations, cleanup and authenticated composition."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools")); sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run, verify_image
from finalize_post_release import finalize, verify
from prepare_scope_material import read_material
from reference_plan import parse_plan
from release_plan import parse_plan as release_plan
from post_completion_cases import completion_cases
from post_subjects import artifact_arguments, read_artifacts
from owner_reader_image import checker_arguments


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "objdump", "image", "raw_image", "plan", "material", "draft", "private", "scoped",
            "child", "child_report", "release_plan", "reference_object", "record_object", "reference_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--role", required=True)
    parser.add_argument("--pre-release", action="store_true")
    parser.add_argument("--mixed-plan", type=Path)
    parser.add_argument("--blocked", action="store_true")
    parser.add_argument("--object", type=Path); parser.add_argument("--coverage", type=Path)
    parser.add_argument("--sources", type=Path, nargs="+")
    parser.add_argument("--backend", type=Path, nargs="+", required=True)
    parser.add_argument("--foreign-context", type=Path, nargs="+", required=True)
    artifact_arguments(parser)
    args = parser.parse_args()
    if bool(args.object) == bool(args.sources) or (args.coverage and not args.object):
        parser.error("choose actual protected object/report or ordinary sources")
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    inputs = (parse_plan(args.plan.read_bytes()), args.material.read_bytes(), args.draft.read_bytes(),
        args.private.read_bytes(), read_material(args.scoped), args.child.read_bytes(), args.child_report.read_bytes(),
        release_plan(args.release_plan.read_bytes()), args.role)
    options = {"pre_release": args.pre_release, **read_artifacts(args, inputs[0])}
    if args.mixed_plan:
        options["mixed_plan"] = args.mixed_plan.read_bytes()
    raw, final = args.raw_image.read_bytes(), args.image.read_bytes()
    proof = verify(raw, final, *inputs, **options)
    report = args.build_dir / "pyobf_native_demo_outer.release.json"
    if proof != json.loads(report.read_text()): raise AssertionError("post proof differs from exact final output")
    repeated, repeat_proof = finalize(final, *inputs, **options)
    if repeated != final or not repeat_proof["idempotent"]: raise AssertionError("post finalization is not idempotent")
    with tempfile.TemporaryDirectory(prefix="post-release-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        completion_cases(args, directory, raw, final, inputs, options, run)
        wrapped, actual = [], []
        for name, definitions in (("memory.cpp", ["-Dallocate=allocate_actual", "-Drelease=release_actual"]),
                ("hash.cpp", ["-Dhash_sha256=hash_sha256_actual"]), ("clock.cpp", ["-Dmeasurement_clock=measurement_clock_actual"])):
            sources = [source for source in args.backend if source.name == name]
            if len(sources) != 1: raise AssertionError("post fault probe needs the exact actual memory/hash/clock backends")
            wrapped += sources
            obj = directory / (name + ".actual.obj"); actual.append(obj)
            run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *definitions,
                "-I", ROOT / "include", "-I", ROOT / "src", "-c", sources[0], "-o", obj])
        probe = directory / "post.raw.exe"
        definitions = ["-DPYOBF_DEMO_POST_CODE_HASH=1"] + (["-DPYOBF_DEMO_PRE_CODE_HASH=1"] if args.pre_release else [])
        if args.blocked: definitions.append("-DPYOBF_POST_PROBE_ALLOW_UNAVAILABLE=1")
        run([args.compiler, "-std=c++17", "-O2", "-fno-lto", *definitions, "-I", ROOT / "include", "-I", ROOT / "src",
            "-I", ROOT / "demo", "-I", args.build_dir, "-I", args.reference_directory, ROOT / "demo/post_release_probe.cpp",
            ROOT / "src/path_fold/marker.cpp", *([args.object] if args.object else args.sources), args.reference_object,
            args.record_object, *[source for source in args.backend if source not in wrapped], *actual, "-lbcrypt", "-o", probe])
        binary = directory / "post.exe"
        completed, probe_proof = finalize(probe.read_bytes(), *inputs, **options)
        binary.write_bytes(completed)
        if args.coverage:
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump,
                *checker_arguments(args.object, Path(str(args.object) + ".ownership.json"), args.plan)],
                binary, args.coverage, directory / "post.final.json")
        if args.foreign_context:
            foreign = directory / "foreign.dll"
            operations = [source for source in args.backend if source.name in
                ("memory.cpp", "atomic.cpp", "code_lifetime.cpp", "archive_support.cpp")]
            if len(operations) != 4: raise AssertionError("foreign context needs its actual memory/atomic/code/failure operations")
            run([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-shared", "-I", ROOT / "include", "-I", ROOT / "src",
                ROOT / "demo/post_foreign_context.cpp", *args.foreign_context, *operations, "-o", foreign])
            for mode in (*(["foreign-key", "foreign-ready"] if args.pre_release else []), "foreign-generation"):
                result = run([binary, mode, foreign])
                if "foreign-origin-denied" not in result.stdout: raise AssertionError("foreign generation collision did not reach its boundary")
        for mode in ("normal", "unwind", "reentrant", "independent", "unprepared", "repeat", "admission", "missing",
                "hash-failed", "clock-failed", "reader-key", "reader-codec"):
            result = run([binary, mode])
            if mode.startswith("reader-") and "reader-domain-denied" not in result.stdout:
                raise AssertionError("reader failure missed actual per-owner typed source checks")
        for role, mode in enumerate(("parent-code", "inner-code")):
            index = inputs[0].scope_materials[role]
            for ordinal, span in enumerate(probe_proof["reference"]["records"][index]["ranges"]):
                if span["size"] == 0: raise AssertionError("actual function/fragment mutation lost its byte extent")
                result = run([binary, mode, ordinal])
                kind = inputs[0].records[index].identity.kind
                if f"range-denied:{kind}:{ordinal}:{span['rva']}:{span['size']}" not in result.stdout:
                    raise AssertionError("code mutation did not deny at its exact independent actual range")
        for mode in ("wrong-owner", "wrong-fold", "wrong-material", "inner-owner", "inner-material"):
            result = run([binary, mode], succeeds=False)
            inner = mode.startswith("inner-")
            if ((result.returncode & 0xffffffff) != 0xe04f0702 or "stage:5" not in result.stdout or
                    ("stage:7" in result.stdout) != inner or "post-verified" in result.stdout):
                raise AssertionError(f"{mode} failed outside actual measured query boundary: {result.stdout}, {result.stderr}")
        result = run([binary, "synthetic-observer", foreign], succeeds=False)
        if ((result.returncode & 0xffffffff) != 0xe04f0702 or "synthetic-same-generation-ready" not in result.stdout or
                "stage:7" in result.stdout or "synthetic-source-effect" in result.stdout):
            raise AssertionError(f"synthetic copied evidence reached an unexpected boundary: "
                f"status={result.returncode & 0xffffffff:#x}, stdout={result.stdout}, stderr={result.stderr}")
        for ordinal in range(1, 65):
            result = run([binary, "oom", ordinal])
            if "oom-denied" not in result.stdout:
                if "post-verified" not in result.stdout: raise AssertionError("OOM traversal missed its terminal success")
                break
        else: raise AssertionError("post preparation OOM traversal exceeded bounded allocations")
    print(f"post release: two actual CFF roles, normal/EH/reentry, cross-DLL equal-generation/phase/role/legacy denials, code/material/fold/owner failures and {ordinal - 1} partial OOM points pass")


if __name__ == "__main__": main()
