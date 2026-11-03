"""Verify single-block functions retain return and side-effect behavior after CFF."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = """
@counter = global i32 0

define i32 @tiny_value() {
entry:
  ret i32 41
}

define void @tiny_update() {
entry:
  %old = load i32, ptr @counter
  %new = add i32 %old, 1
  store i32 %new, ptr @counter
  ret void
}
"""

HARNESS = """
extern "C" int tiny_value();
extern "C" void tiny_update();
extern "C" int counter;

int main() {
    if (tiny_value() != 41 || counter != 0) {
        return 1;
    }
    tiny_update();
    tiny_update();
    return counter == 2 && tiny_value() == 41 ? 0 : 2;
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
        source = directory / "tiny.ll"
        transformed = directory / "tiny.cff.ll"
        report = directory / "tiny.json"
        object_file = directory / "tiny.obj"
        harness = directory / "harness.cpp"
        executable = directory / "tiny.exe"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=tiny_value,tiny_update",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source),
             "-o", str(transformed)])
        rows = {row["function"]: row for row in
                json.loads(report.read_text(encoding="utf-8"))["functions"]}
        ir = transformed.read_text(encoding="utf-8")
        for name in ("tiny_value", "tiny_update"):
            if rows[name]["status"] != "transformed":
                raise AssertionError(f"small function {name} was not transformed")
            if rows[name].get("coverage_kind") != "shape-only":
                raise AssertionError(f"small function {name} was counted as decision flow")
            start = ir.index(f"@{name}(")
            body = ir[start:ir.index("\n}", start)]
            if "pyobf.entry.pad" not in body or "pyobf.dispatch:" not in body:
                raise AssertionError(f"small function {name} lost its CFF entry")
        run([str(args.compiler), "-c", str(transformed), "-o", str(object_file)])
        run([str(args.compiler), str(harness), str(object_file), "-o", str(executable)])
        run([str(executable)])

        strict_report = directory / "strict.json"
        strict = subprocess.run(
            [str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=tiny_value,tiny_update",
             "-pyobf-cff-require-decision-flow=true",
             f"-pyobf-cff-report={strict_report}", "-disable-output", str(source)],
            capture_output=True, text=True, timeout=20,
        )
        if strict.returncode == 0 or not strict_report.exists():
            raise AssertionError("strict CFF accepted shape-only functions")
        strict_rows = json.loads(strict_report.read_text(encoding="utf-8"))["functions"]
        if any(row["status"] != "unsupported" or
               "no original decision flow" not in row.get("reason", "")
               for row in strict_rows):
            raise AssertionError("strict CFF did not report shape-only rejection")


if __name__ == "__main__":
    main()
