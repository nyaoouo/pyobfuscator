"""Observed actual-CNG real/decoy fault boundaries, separate from actual DLL smokes."""

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "demo/decoy"), str(ROOT / "tests/context"), str(ROOT / "tools")]
from cff_build import run, verify_image
from release_plan import expected_fold, parse_plan
from session_build import session_output
from runtime_build import fixture_directory, link, protect, support
from runtime_mutations import mutations


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "configuration", "build_dir", "record", "real_image", "decoy_image"):
        parser.add_argument(name, type=Path)
    parser.add_argument("profile", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src", "-I", ROOT / "demo", "-I", args.build_dir]
    with fixture_directory(args.build_dir) as directory:
        combined, transformed, report = protect(args, directory, ROOT, includes)
        objects = support(args, directory, ROOT, includes)
        binary = link(args, directory, transformed, "observed", objects, includes, ROOT)
        def execute(image, mode, expected):
            return session_output(image, args.real_image, args.decoy_image, mode, expected)
        def check_suite(image):
            output = execute(image, "suite", 0)
            lines = [line.split()[2:] for line in output.splitlines() if line.startswith("bootstrap-fold decoy-release ")]
            expected = expected_fold(parse_plan((args.build_dir / "decoy.private.json").read_bytes()))
            if len(lines) != 1 or tuple(map(int, lines[0])) != expected:
                raise AssertionError("actual decoy key-boundary fold differs from independent private input reference")
            if "observed decoy:" not in output: raise AssertionError("observed acceptance did not complete")
        check_suite(binary)
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        verify_image(checker, binary, report, directory / "final.json")
        plain = link(args, directory, combined, "plain", objects, includes, ROOT, plain=True)
        check_suite(plain)
        absent = directory / "rejected.json"
        run([*checker, plain, report, "--output", absent], succeeds=False)
        if absent.exists(): raise AssertionError("same-source unprotected session received final CFF evidence")
        cases = list(mutations(transformed.read_text()))
        if len(cases) != 33: raise AssertionError("real/decoy post-emission fault inventory changed")
        for name, text, mode, expected in cases:
            mutant = directory / (name + ".ll")
            mutant.write_text(text)
            run([args.opt, "-passes=verify", "-disable-output", mutant])
            image = link(args, directory, mutant, name, objects, includes, ROOT)
            try:
                execute(image, mode, expected)
            except AssertionError as error:
                raise AssertionError(f"decoy post-emission case {name}: {error}") from error
        print(f"observed81-definition decoy session: source{args.profile}/IPO{args.ipo};33 LLVM-valid faults,21 allocation failures, exact child classification, actual CNG and erased ownership passed")


if __name__ == "__main__":
    main()
