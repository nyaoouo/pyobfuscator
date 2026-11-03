"""Execute the production correction emitter and C++ model against Python vectors."""

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
from check_cff_path_fold import run
from contribution_cases import write_vectors


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "generator", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--ipo", action="store_true")
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="contribution-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, vectors = directory / "correction.ll", directory / "vectors.txt"
        counts = write_vectors(vectors)
        run([args.generator, source])
        rejected = directory / "invalid.ll"
        for mode in ("invalid-state", "invalid-observation", "null-observation"):
            result = run([args.generator, rejected, mode], succeeds=False)
            if rejected.exists() or "contribution correction needs i32 state and observation" not in result.stderr:
                raise AssertionError("malformed correction value was not refused before output")
        run([args.opt, "-passes=verify", "-disable-output", source])
        text = source.read_text()
        if re.search(r"\b(?:nsw|nuw|exact|icmp|switch|load)\b", text):
            raise AssertionError("correction added poison, fixed-value comparison or expected-value lookup")
        for profile in ("none", "O2"):
            actual = source
            if profile == "O2":
                actual = directory / "optimized.ll"
                run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", actual])
            binary = directory / (profile + ".exe")
            run([args.compiler, "-std=c++17", "-O2", "-I", ROOT / "src", actual,
                 ROOT / "tests/contribution_harness.cpp", *(["-flto=thin"] if args.ipo else []), "-o", binary])
            if "host/runtime/emitted correction verified" not in run([binary, vectors]).stdout:
                raise AssertionError("actual correction consumer was not executed")
        altered, count = re.subn(r"ret i32 %[-\w.$]+", "ret i32 0", text, count=1)
        if count != 1: raise AssertionError("missing emitted correction return")
        mutant, binary = directory / "altered.ll", directory / "altered.exe"
        mutant.write_text(altered)
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        run([args.compiler, "-std=c++17", "-O2", "-I", ROOT / "src", mutant, ROOT / "tests/contribution_harness.cpp", "-o", binary])
        run([binary, vectors], succeeds=False)
        print(f"contribution v1: {counts[0]} transcripts/{counts[1]} mutations/{counts[2]} corrections; none/O2,IPO={args.ipo}; provider integration not claimed")


if __name__ == "__main__":
    main()
