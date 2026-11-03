"""Verify source markers select linked payload/SDK functions without mangled-name lists."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


DECLARATION_IR = r"""
@.marker = private constant [17 x i8] c"pyobf.native.sdk\00"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr } { ptr @missing, ptr @.marker, ptr null, i32 1, ptr null }],
  section "llvm.metadata"
declare void @missing()
"""

ALIASED_IR = r"""
@.marker = private constant [17 x i8] c"pyobf.native.sdk\00"
@alias1 = alias i32 (i32), ptr @body
@alias2 = alias i32 (i32), ptr @alias1
@llvm.global.annotations = appending global [2 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr } { ptr @alias2, ptr @.marker, ptr null, i32 1, ptr null },
   { ptr, ptr, ptr, i32, ptr } { ptr @body, ptr @.marker, ptr null, i32 1, ptr null }],
  section "llvm.metadata"
define i32 @body(i32 %input) {
entry:
  %condition = icmp sgt i32 %input, 3
  br i1 %condition, label %yes, label %no
yes:
  ret i32 17
no:
  ret i32 23
}
"""


def run(opt: Path, plugin: Path, source: Path, report: Path,
        extra: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(opt), "-load-pass-plugin", str(plugin), "-passes=pyobf-native-cff",
         f"-pyobf-cff-report={report}", "-verify-each", "-disable-output", *extra,
         str(source)], capture_output=True, text=True, timeout=20,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("input_ir", type=Path)
    parser.add_argument("--asset", action="store_true")
    parser.add_argument("--strict-payload", action="store_true")
    parser.add_argument("--post-input", nargs=2, type=Path, metavar=("RECIPE", "PRIVATE"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.input_ir.parent) as temporary:
        directory = Path(temporary)
        report = directory / "marked.json"
        post_options = ([f"-pyobf-cff-config={args.post_input[0]}",
            f"-pyobf-cff-contribution-input={args.post_input[1]}"] if args.post_input else [])
        marked = run(args.opt, args.plugin, args.input_ir, report, post_options)
        if marked.returncode:
            raise AssertionError(f"marker-only CFF failed: {marked.stderr}")
        rows = json.loads(report.read_text(encoding="utf-8"))["functions"]
        expected = {"pyobf.native.cff": (5 if args.asset else 2) + int(args.strict_payload),
            "pyobf.native.sdk": 49 if args.strict_payload else 47}
        if args.post_input:
            expected = {"pyobf.native.cff": 7 if args.asset else 4, "pyobf.native.sdk": 129}
        for marker, count in expected.items():
            selected = [row for row in rows if row.get("marker") == marker]
            if len(selected) != count or any(row["status"] != "transformed" for row in selected):
                raise AssertionError(f"incomplete {marker} selection: " + str([(row["function"], row["status"]) for row in selected]))
        if args.strict_payload and not any(row["function"] == "pyobf_demo_bound_compute" and row["status"] == "transformed" for row in rows):
            raise AssertionError("strict private math helper escaped marker selection")

        explicit_report = directory / "explicit.json"
        explicit = run(args.opt, args.plugin, args.input_ir, explicit_report,
                       ["-pyobf-cff-markers=false",
                        "-pyobf-cff-functions=pyobf_demo_compute"])
        if explicit.returncode:
            raise AssertionError(f"explicit CFF selection failed: {explicit.stderr}")
        explicit_rows = json.loads(explicit_report.read_text(encoding="utf-8"))["functions"]
        selected_names = {row["function"] for row in explicit_rows if row["selected"]}
        if selected_names != {"pyobf_demo_compute"}:
            raise AssertionError(f"marker disable did not isolate explicit selection: {selected_names}")

        empty_report = directory / "empty.json"
        empty = run(args.opt, args.plugin, args.input_ir, empty_report,
                    ["-pyobf-cff-markers=false"])
        if empty.returncode == 0 or empty_report.exists() or "requires explicit functions" not in empty.stderr:
            raise AssertionError("empty CFF selection did not fail before reporting")

        declaration_ir = directory / "declaration.ll"
        declaration_ir.write_text(DECLARATION_IR, encoding="utf-8")
        declaration_report = directory / "declaration.json"
        declaration = run(args.opt, args.plugin, declaration_ir, declaration_report, [])
        if declaration.returncode == 0 or not declaration_report.exists():
            raise AssertionError("marked declaration did not fail with a coverage report")
        declaration_rows = json.loads(declaration_report.read_text(encoding="utf-8"))["functions"]
        if not any(row["function"] == "missing" and row["status"] == "unsupported"
                   for row in declaration_rows):
            raise AssertionError("marked declaration was not reported unsupported")

        alias_ir, alias_report = directory / "aliases.ll", directory / "aliases.json"
        alias_ir.write_text(ALIASED_IR, encoding="utf-8")
        alias = run(args.opt, args.plugin, alias_ir, alias_report, [])
        if alias.returncode:
            raise AssertionError(f"function-alias marker selection failed: {alias.stderr}")
        alias_rows = [row for row in json.loads(alias_report.read_text())["functions"] if row["selected"]]
        if len(alias_rows) != 1 or alias_rows[0]["function"] != "body" or alias_rows[0]["status"] != "transformed":
            raise AssertionError("alias chain and body did not resolve to one protected definition")
        object_ir, object_report = directory / "object.ll", directory / "object.json"
        object_ir.write_text(ALIASED_IR.replace("@body, ptr @.marker", "@object, ptr @.marker") +
                             "\n@object = global i32 0\n", encoding="utf-8")
        invalid = run(args.opt, args.plugin, object_ir, object_report, [])
        if invalid.returncode == 0 or object_report.exists() or "does not reference a function" not in invalid.stderr:
            raise AssertionError("non-function marker was accepted through alias handling")


if __name__ == "__main__":
    main()
