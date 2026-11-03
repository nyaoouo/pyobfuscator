"""CFF actual bootstrap/payload/context sources, then run the isolated cleanup protocol."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import tempfile
from session_fold_reference import verify_transcript, verify_coverage

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests/context"))
from cff_build import run, verify_image
from session_build import native_support, complete_binary, session_output
from release_plan import parse_plan
from release_flow_mutations import runtime_mutations


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "configuration", "build_dir", "release_plan", "record"):
        parser.add_argument(name, type=Path)
    parser.add_argument("profile", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", root / "include", "-I", root / "src", "-I", root / "demo", "-I", args.build_dir]
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        plan = parse_plan(args.release_plan.read_bytes())
        support_objects = native_support(args, directory, root)
        units = []
        for index, source in enumerate(args.sources):
            unit = directory / f"source-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
                 *includes, source, "-o", unit])
            units.append(unit)
        combined, requested = directory / "combined.ll", directory / "requested.ll"
        requests = directory / "requests.json"
        run([args.llvm_link, "-S", *units, "-o", combined])
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={args.configuration}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
             "-verify-each", "-S", combined, "-o", requested])
        source = requested
        if args.profile == "O2":
            source = directory / "optimized.ll"
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
        transformed, report = directory / "protected.ll", directory / "coverage.json"
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", transformed])
        rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
        expected = {"pyobf.native.cff": 2, "pyobf.native.sdk": 48,
                    "pyobf.native.bootstrap": 21, "pyobf.native.bootstrap.eh": 2}
        if (dict(Counter(row.get("marker") for row in rows)) != expected or
                any(row["status"] != "transformed" or not row["requested"] for row in rows)):
            raise AssertionError("actual session authored/source/CFF coverage changed")
        verify_coverage(rows)
        native_object = directory / "protected.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", transformed, "-o", native_object])
        host = [root / "demo" / name for name in
                ("session_smoke.cpp", "session_protocol.cpp", "session_backend.cpp", "session_fold.cpp",
                 "session_common.cpp", "session_crypto.cpp")]
        binary = directory / "session.exe"
        raw = directory / "session.raw.exe"
        run([args.compiler, "-std=c++17", "-O2", native_object, *support_objects, *host, *includes,
             *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", raw])
        complete_binary(raw, binary, args.record)
        actual = session_output(binary)
        verify_transcript(actual, plan)
        if "owned demo session cleanup verified" not in actual:
            raise AssertionError("protected actual session did not finish its failure/cleanup suite")
        checker = [sys.executable, root / "demo/check_linked_cff.py", args.objdump]
        verify_image(checker, binary, report, directory / "final.json")
        plain = directory / "plain.exe"
        raw_plain = directory / "plain.raw.exe"
        run([args.compiler, "-std=c++17", "-O0", combined, *support_objects, *host, root / "src/path_fold/marker.cpp",
             *includes, *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", raw_plain])
        complete_binary(raw_plain, plain, args.record)
        verify_transcript(session_output(plain), plan)
        absent = directory / "rejected.json"
        run([*checker, plain, report, "--output", absent], succeeds=False)
        if absent.exists(): raise AssertionError("plain session received final CFF evidence")
        # Compile LLVM-valid adversarial edits without re-running the build proof.
        # The same production CNG code must refuse based on missing/wrong material.
        fault_host = [root / "demo" / name for name in
            ("release_fault_smoke.cpp", "session_common.cpp", "session_backend.cpp", "session_crypto.cpp")]
        def fault_binary(ir, name):
            obj, raw_fault, fault = (directory / (name + suffix) for suffix in (".obj", ".raw.exe", ".exe"))
            run([args.compiler, "-O0", "-fno-lto", "-c", ir, "-o", obj])
            run([args.compiler, "-std=c++17", "-O2", obj, *support_objects, *fault_host, *includes,
                 *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", raw_fault])
            complete_binary(raw_fault, fault, args.record)
            return fault
        reference_fault = fault_binary(transformed, "fault-controls")
        for mode, status in (("reorder", -4), ("fold", -4), ("generation", -7), ("context", -7)):
            if "real CNG release fault refused" not in session_output(reference_fault, mode, status):
                raise AssertionError("release fault control did not execute")
        mutations = list(runtime_mutations(transformed.read_text()))
        if len(mutations) != 15: raise AssertionError("release IR fault inventory changed")
        for name, text, mode, status in mutations:
            mutant = directory / (name + ".ll")
            mutant.write_text(text)
            run([args.opt, "-passes=verify", "-disable-output", mutant])
            fault = fault_binary(mutant, name)
            if "real CNG release fault refused" not in session_output(fault, mode, status):
                raise AssertionError("altered valid IR did not refuse at the actual data/crypto boundary")
        print("19 runtime release faults: reordered/fold/context/generation, 15 LLVM-valid post-emission edits, actual CNG, zero loader/entry")
        print(f"73 authored session definitions and real CNG key refusal verified: source {args.profile}, parent IPO {args.ipo}")


if __name__ == "__main__":
    main()
