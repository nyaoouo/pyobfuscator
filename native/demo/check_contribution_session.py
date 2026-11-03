"""Protect actual bootstrap source dispatch and verify its authenticated snapshot."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/contribution"), str(ROOT / "tools")]
from cff_build import run, verify_image
from check_context import context_word
from release_plan import expected_fold, parse_plan
from session_build import native_support, complete_binary, session_output
from session_fold_reference import verify_coverage


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "configuration", "build_dir", "release_plan", "record"):
        parser.add_argument(name, type=Path)
    parser.add_argument("profile", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src", "-I", ROOT / "demo", "-I", args.build_dir]
    with tempfile.TemporaryDirectory(prefix="contribution-session-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        objects = native_support(args, directory, ROOT)
        units = []
        for index, source in enumerate(args.sources):
            unit = directory / f"source-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
                 *includes, source, "-o", unit]); units.append(unit)
        combined, requested, requests = (directory / name for name in ("combined.ll", "requested.ll", "requests.json"))
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
        if dict(Counter(row.get("marker") for row in rows)) != {
                "pyobf.native.bootstrap": 21, "pyobf.native.bootstrap.eh": 2, "pyobf.native.sdk": 49, "pyobf.native.cff": 2}:
            raise AssertionError("actual source-session authored scope changed")
        verify_coverage(rows)
        native = directory / "protected.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", transformed, "-o", native])
        host = [ROOT / "demo" / name for name in ("contribution_session.cpp", "session_common.cpp", "session_backend.cpp", "session_crypto.cpp")]
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        route = int(re.search(r"#define PYOBF_DEMO_ENV_OPERATION_ID (\d+)u", (args.build_dir / "demo_config.hpp").read_text())[1])
        point = (1, 2, 3, 4, 0x12345678)
        normal = context_word(expected_fold(parse_plan(args.release_plan.read_bytes())), route, point)
        zero = context_word((0,) * 8, route, point)
        if normal == zero: raise AssertionError("source test fixture truncated-word collision; choose a different site")
        for label, input_source in (("protected", native), ("plain", combined)):
            raw, binary = directory / (label + ".raw.exe"), directory / (label + ".exe")
            run([args.compiler, "-std=c++17", "-O2", input_source, *objects, *host,
                 *([ROOT / "src/path_fold/marker.cpp"] if label == "plain" else []), *includes,
                 *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", raw])
            complete_binary(raw, binary, args.record)
            output = session_output(binary)
            observed = {line.split()[1]: int(line.split()[2]) for line in output.splitlines() if line.startswith("bootstrap-fold ")}
            if observed != {"context-word": normal, "context-zero": zero}:
                raise AssertionError("actual bootstrap source differs from independent private-plan/canonical reference")
            final = directory / (label + ".final.json")
            if label == "protected": verify_image(checker, binary, report, final)
            else:
                run([*checker, binary, report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain actual source dispatch received CFF proof")
        print(f"74 actual bootstrap/source definitions: source{args.profile},IPO={args.ipo}; CNG authenticated snapshot, forged-state wrong word, protocol/lifetime/erasure and private reference verified")


if __name__ == "__main__":
    main()
