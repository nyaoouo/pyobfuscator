"""Check PHI and cross-block SSA lowering through executable results."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = """
define i32 @sum_to(i32 %n) {
entry:
  %stride = add i32 %n, 3
  br label %loop
loop:
  %index = phi i32 [0, %entry], [%next, %body]
  %total = phi i32 [0, %entry], [%updated, %body]
  %continue = icmp slt i32 %index, %n
  br i1 %continue, label %body, label %done
body:
  %updated = add i32 %total, %stride
  %next = add i32 %index, 1
  br label %loop
done:
  ret i32 %total
}

define i32 @phi_switch(i32 %value) {
entry:
  switch i32 %value, label %other [
    i32 0, label %zero
    i32 1, label %one
  ]
zero:
  br label %join
one:
  br label %join
other:
  br label %join
join:
  %result = phi i32 [10, %zero], [20, %one], [30, %other]
  ret i32 %result
}
"""

HARNESS = """
extern "C" int sum_to(int);
extern "C" int phi_switch(int);

int main() {
    for (int n = -3; n <= 20; ++n) {
        const int expected = n > 0 ? n * (n + 3) : 0;
        if (sum_to(n) != expected) {
            return 1;
        }
    }
    for (int value = -3; value <= 5; ++value) {
        const int expected = value == 0 ? 10 : value == 1 ? 20 : 30;
        if (phi_switch(value) != expected) {
            return 2;
        }
    }
    return 0;
}
"""


def run(command: list[str]) -> None:
    process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if process.returncode:
        raise AssertionError(f"command failed: {command}\n{process.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("compiler", type=Path)
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "ssa.ll"
        transformed = directory / "ssa.cff.ll"
        report = directory / "ssa.json"
        object_file = directory / "ssa.obj"
        harness = directory / "harness.cpp"
        executable = directory / "ssa.exe"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=sum_to,phi_switch",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source),
             "-o", str(transformed)])
        rows = {row["function"]: row for row in
                json.loads(report.read_text(encoding="utf-8"))["functions"]}
        if any(rows[name]["status"] != "transformed" for name in ("sum_to", "phi_switch")):
            raise AssertionError("PHI fixture was not reported transformed")
        ir = transformed.read_text(encoding="utf-8")
        for name in ("sum_to", "phi_switch"):
            start = ir.index(f"@{name}(")
            body = ir[start:ir.index("\n}", start)]
            if " phi i32 " in body or "pyobf.dispatch:" not in body:
                raise AssertionError(f"PHI lowering or CFF is absent from {name}")
        run([str(args.compiler), "-c", str(transformed), "-o", str(object_file)])
        run([str(args.compiler), str(harness), str(object_file), "-o", str(executable)])
        run([str(executable)])


if __name__ == "__main__":
    main()
