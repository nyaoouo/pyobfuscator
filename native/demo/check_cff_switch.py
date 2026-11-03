"""Run a transformed switch over its cases and default path."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


SWITCH_IR = """
define i64 @mapped(i64 %value) {
entry:
  switch i64 %value, label %other [
    i64 0, label %zero
    i64 -7, label %negative
    i64 42, label %same
    i64 43, label %same
  ]
zero:
  ret i64 100
negative:
  ret i64 -700
same:
  ret i64 4200
other:
  ret i64 9
}

define i64 @two_switches(i64 %first, i64 %second) {
entry:
  %second_slot = alloca i64
  %result_slot = alloca i64
  store i64 %second, ptr %second_slot
  switch i64 %first, label %first_default [
    i64 1, label %first_case
  ]
first_case:
  store i64 10, ptr %result_slot
  br label %join
first_default:
  store i64 20, ptr %result_slot
  br label %join
join:
  %second_value = load i64, ptr %second_slot
  switch i64 %second_value, label %second_default [
    i64 -5, label %second_case
  ]
second_case:
  %case_base = load i64, ptr %result_slot
  %case_result = add i64 %case_base, 100
  ret i64 %case_result
second_default:
  %default_base = load i64, ptr %result_slot
  %default_result = add i64 %default_base, 1
  ret i64 %default_result
}
"""

HARNESS = """
#include <initializer_list>

extern "C" long long mapped(long long);
extern "C" long long two_switches(long long, long long);

int main() {
    for (long long value = -64; value <= 64; ++value) {
        const long long expected = value == 0 ? 100 : value == -7 ? -700 :
            value == 42 || value == 43 ? 4200 : 9;
        if (mapped(value) != expected) {
            return 1;
        }
    }
    if (mapped(0x100000000LL) != 9) {
        return 2;
    }
    for (long long first : {1LL, 2LL}) {
        for (long long second : {-5LL, 0LL}) {
            const long long expected = (first == 1 ? 10 : 20) +
                (second == -5 ? 100 : 1);
            if (two_switches(first, second) != expected) {
                return 3;
            }
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
        source = directory / "switch.ll"
        transformed = directory / "switch.cff.ll"
        report = directory / "switch.json"
        object_file = directory / "switch.obj"
        harness = directory / "harness.cpp"
        executable = directory / "switch.exe"
        source.write_text(SWITCH_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=mapped,two_switches",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source),
             "-o", str(transformed)])
        rows = json.loads(report.read_text(encoding="utf-8"))["functions"]
        if any(not any(row["function"] == name and row["status"] == "transformed"
                       for row in rows) for name in ("mapped", "two_switches")):
            raise AssertionError("switch functions were not reported as transformed")
        ir = transformed.read_text(encoding="utf-8")
        for name, expected_checks in (("mapped", 4), ("two_switches", 2)):
            start = ir.index(f"@{name}(")
            body = ir[start:ir.index("\n}", start)]
            if "switch i64" in body or body.count("pyobf.switch.test") < expected_checks:
                raise AssertionError(f"switch checks were not lowered in {name}")
        run([str(args.compiler), "-c", str(transformed), "-o", str(object_file)])
        run([str(args.compiler), str(harness), str(object_file), "-o", str(executable)])
        run([str(executable)])


if __name__ == "__main__":
    main()
