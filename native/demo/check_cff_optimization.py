"""Prove marked code survives O2 before a late pass, and reject optimization after it."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE = """
#include "pyobfuscator_native/cff_marker.hpp"
extern "C" PYOBF_NATIVE_CFF int protected_value(int value) {
    return value * 3 + 5;
}
extern "C" int caller(int value) {
    return protected_value(value);
}
"""

HARNESS = """
extern "C" int caller(int);
int main() { return caller(7) == 26 ? 0 : 1; }
"""


def run(command: list[str], *, succeeds: bool = True) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result: {command}\n{result.stderr}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_check",
                 "include_dir", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.cpp"
        input_ir = directory / "optimized.ll"
        transformed = directory / "cff.ll"
        postoptimized = directory / "postoptimized.ll"
        report = directory / "coverage.json"
        harness = directory / "harness.cpp"
        baseline = directory / "protected.exe"
        erased = directory / "erased.exe"
        source.write_text(SOURCE, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.compiler), "-std=c++17", "-O2", "-S", "-emit-llvm",
             "-I", str(args.include_dir), str(source), "-o", str(input_ir)])
        ir = input_ir.read_text(encoding="utf-8")
        caller = ir[ir.index("@caller("):]
        if (not re.search(r"define .*@protected_value\(", ir) or
                "call" not in caller or "@protected_value" not in caller or
                "noinline" not in ir or "@llvm.used" not in ir):
            raise AssertionError("source marker did not preserve the O2 call boundary")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}",
             "-passes=pyobf-native-cff", f"-pyobf-cff-report={report}",
             "-verify-each", "-S", str(input_ir), "-o", str(transformed)])
        rows = {row["function"]: row for row in
                json.loads(report.read_text(encoding="utf-8"))["functions"]}
        if (rows["protected_value"]["status"] != "transformed" or
                rows["caller"]["selected"]):
            raise AssertionError("late CFF pass lost optimized marker coverage")
        run([str(args.compiler), str(transformed), str(harness), "-o", str(baseline)])
        run([str(baseline)])
        run([sys.executable, str(args.linked_check), str(args.objdump),
             str(baseline), str(report)])

        run([str(args.opt), "-passes=default<O2>", "-S", str(transformed),
             "-o", str(postoptimized)])
        run([str(args.compiler), str(postoptimized), str(harness), "-o", str(erased)])
        run([str(erased)])
        run([sys.executable, str(args.linked_check), str(args.objdump),
             str(erased), str(report)],
            succeeds=False)


if __name__ == "__main__":
    main()
