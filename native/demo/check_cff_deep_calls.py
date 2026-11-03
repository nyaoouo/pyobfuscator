"""Execute a deep CFF call and inspect its linked indirect call site."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = """
define internal i32 @helper(i32 %input) {
entry:
  %result = add i32 %input, 9
  ret i32 %result
}

define i32 @deep_caller(i32 %input) {
entry:
  %value = call i32 @helper(i32 %input)
  %negative = icmp slt i32 %input, 0
  br i1 %negative, label %minus, label %plus
minus:
  %extra = add i32 %value, 5
  ret i32 %extra
plus:
  ret i32 %value
}

define i32 @deep_call_only(i32 %input) {
entry:
  %value = call i32 @helper(i32 %input)
  ret i32 %value
}
"""

HARNESS = """
extern "C" int deep_caller(int);
extern "C" int deep_call_only(int);
int main() {
    return deep_caller(-4) == 10 && deep_caller(8) == 17 &&
           deep_call_only(3) == 12 ? 0 : 1;
}
"""


def run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise AssertionError(f"command failed: {command}\n{result.stderr}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        transformed = directory / "deep.ll"
        report = directory / "coverage.json"
        harness = directory / "harness.cpp"
        binary = directory / "deep.exe"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=deep_caller,deep_call_only",
             "-pyobf-cff-deep-functions=deep_caller,deep_call_only",
             f"-pyobf-cff-report={report}",
             "-verify-each", "-S", str(source), "-o", str(transformed)])
        rows = {row["function"]: row for row in
                json.loads(report.read_text(encoding="utf-8"))["functions"]}
        if (rows["deep_caller"]["status"] != "transformed" or
                rows["deep_call_only"]["status"] != "transformed" or
                rows["helper"]["selected"]):
            raise AssertionError("deep caller or unselected helper coverage is wrong")
        ir = transformed.read_text(encoding="utf-8")
        for name in ("deep_caller", "deep_call_only"):
            start = ir.index(f"@{name}(")
            body = ir[start:ir.index("\n}", start)]
            if ("store volatile ptr @helper" not in body or
                    "load volatile ptr, ptr %pyobf.call.slot" not in body or
                    not re.search(r"call i32 %pyobf\.call\.target", body) or
                    "call i32 @helper" in body):
                raise AssertionError(f"internal call in {name} did not become indirect")
        run([str(args.compiler), str(transformed), str(harness), "-o", str(binary)])
        run([str(binary)])
        for name in ("deep_caller", "deep_call_only"):
            code = run([str(args.objdump), "-d", f"--disassemble-symbols={name}",
                        str(binary)]).lower()
            if (not re.search(rf"<{name}>:", code) or
                    not re.search(r"\bcallq?\s+\*", code) or
                    re.search(r"\bcallq?\s+[^\n]*<helper>", code)):
                raise AssertionError(f"linked {name} lost its indirect call route")


if __name__ == "__main__":
    main()
