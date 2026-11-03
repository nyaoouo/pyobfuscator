"""Check decoy transitions are retained and alter execution if forced."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = """
define i32 @decoy_value(i32 %input) {
entry:
  %is_zero = icmp eq i32 %input, 0
  br i1 %is_zero, label %yes, label %no
yes:
  ret i32 101
no:
  ret i32 202
}
"""

HARNESS = """
extern "C" int decoy_value(int);
int main() {
    return decoy_value(0) == 101 && decoy_value(7) == 202 ? 0 : 1;
}
"""


def run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise AssertionError(f"command failed: {command}\n{result.stderr}")
    return result.stdout


def compile_executable(compiler: Path, ir: Path, harness: Path, binary: Path) -> None:
    run([str(compiler), str(ir), str(harness), "-o", str(binary)])


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        transformed = directory / "deep.ll"
        altered = directory / "forced.ll"
        report = directory / "coverage.json"
        harness = directory / "harness.cpp"
        baseline = directory / "baseline.exe"
        forced = directory / "forced.exe"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=decoy_value",
             "-pyobf-cff-deep-functions=decoy_value", f"-pyobf-cff-report={report}",
             "-verify-each", "-S", str(source), "-o", str(transformed)])
        row = json.loads(report.read_text(encoding="utf-8"))["functions"][0]
        if row["status"] != "transformed" or row["strategy"] != "relative-tree-deep":
            raise AssertionError("decoy fixture was not deep transformed")
        ir = transformed.read_text(encoding="utf-8")
        if ("pyobf.decoy.guard" not in ir or "pyobf.decoy.pick" not in ir or
                "icmp ult i32 %pyobf.decoy.state" not in ir):
            raise AssertionError("deep function lost its decoy state comparison")
        compile_executable(args.compiler, transformed, harness, baseline)
        run([str(baseline)])
        code = run([str(args.objdump), "-d", "--disassemble-symbols=decoy_value",
                    str(baseline)]).lower()
        if not re.search(r"\bcmovb[lq]?\b", code):
            raise AssertionError("linked function lost its decoy selection")

        changed, count = re.subn(r"select i1 %pyobf\.decoy\.guard(?:\d+)?",
                                 "select i1 true", ir, count=1)
        if count != 1:
            raise AssertionError("no decoy edge could be forced")
        altered.write_text(changed, encoding="utf-8")
        compile_executable(args.compiler, altered, harness, forced)
        try:
            result = subprocess.run([str(forced)], capture_output=True, text=True,
                                    timeout=2)
        except subprocess.TimeoutExpired:
            return
        if result.returncode == 0:
            raise AssertionError("forcing a decoy transition preserved normal results")


if __name__ == "__main__":
    main()
