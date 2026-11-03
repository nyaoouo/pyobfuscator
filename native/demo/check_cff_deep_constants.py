"""Execute state-dependent literal reconstruction and reject an altered state read."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = """
define i32 @deep_value(i32 %input) {
entry:
  %zero = icmp eq i32 %input, 0
  br i1 %zero, label %literal, label %added
literal:
  ret i32 305419896
added:
  %sum = add i32 %input, 21930
  ret i32 %sum
}
"""

HARNESS = """
extern "C" int deep_value(int);
int main() {
    return deep_value(0) == 305419896 && deep_value(7) == 21937 ? 0 : 1;
}
"""


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result for {command}: {result.stderr}")
    return result


def compile_and_run(compiler: Path, directory: Path, ir: Path, harness: Path,
                    name: str, *, succeeds: bool = True) -> None:
    binary = directory / f"{name}.exe"
    run([str(compiler), str(ir), str(harness), "-o", str(binary)])
    run([str(binary)], succeeds=succeeds)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        transformed = directory / "deep.ll"
        report = directory / "coverage.json"
        harness = directory / "harness.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=deep_value",
             "-pyobf-cff-deep-functions=deep_value", f"-pyobf-cff-report={report}",
             "-verify-each", "-S", str(source), "-o", str(transformed)])
        rows = json.loads(report.read_text(encoding="utf-8"))["functions"]
        if rows[0]["status"] != "transformed" or rows[0]["strategy"] != "relative-tree-deep":
            raise AssertionError("deep CFF coverage was not recorded")
        ir = transformed.read_text(encoding="utf-8")
        if (ir.count("pyobf.literal.decode") < 2 or "ret i32 305419896" in ir or
                "add i32 %input, 21930" in ir):
            raise AssertionError("literals remain plain or reconstruction was not inserted")
        compile_and_run(args.compiler, directory, transformed, harness, "normal")

        start = ir.index("literal:")
        end = ir.index("added:", start)
        literal = ir[start:end]
        pattern = (r"(%pyobf\.literal\.state(?:\.?\d+)? = )"
                   r"load i32, ptr %pyobf\.state(?:, align \d+)?")
        changed, count = re.subn(pattern, r"\1add i32 0, 0", literal, count=1)
        if count != 1:
            raise AssertionError("literal block has no state-dependent read")
        tampered = directory / "tampered.ll"
        tampered.write_text(ir[:start] + changed + ir[end:], encoding="utf-8")
        compile_and_run(args.compiler, directory, tampered, harness, "tampered",
                        succeeds=False)

        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=deep_value",
             "-pyobf-cff-deep-functions=missing", "-disable-output", str(source)],
            succeeds=False)

        no_literal = directory / "no_literal.ll"
        rejected_report = directory / "rejected.json"
        no_literal.write_text(
            "define i32 @no_literal(i32 %input) {\nentry:\n  ret i32 %input\n}\n",
            encoding="utf-8",
        )
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=no_literal",
             "-pyobf-cff-deep-functions=no_literal",
             f"-pyobf-cff-report={rejected_report}", "-disable-output", str(no_literal)],
            succeeds=False)
        rejected = json.loads(rejected_report.read_text(encoding="utf-8"))["functions"]
        if (rejected[0]["status"] != "unsupported" or
                "scalar integer literal or internal call" not in rejected[0]["reason"]):
            raise AssertionError("ineligible deep function was not reported")


if __name__ == "__main__":
    main()
