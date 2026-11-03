"""Preparation-specific bounds, empty fields, budgets and final-feature negatives."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run, invalid_execution


SOURCE = '''target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
define internal i32 @leaf(i32 %x) noinline { %r = add i32 %x, 9
ret i32 %r }
define internal void @nothing() noinline { ret void }
define internal {} @empty_echo({} %x) noinline { ret {} %x }
define internal i8 @byte_echo(i8 %x) noinline { ret i8 %x }
define i32 @f(i32 %x) noinline { %r = call i32 @leaf(i32 %x)
ret i32 %r }
define i32 @empty_fields() noinline { call void @nothing()
%r = call {} @empty_echo({} zeroinitializer)
%byte = call i8 @byte_echo(i8 3)
ret i32 42 }
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, recipe, report = (directory / name for name in ("source.ll", "output.ll", "recipe.json", "report.json"))
        source.write_text(SOURCE, encoding="utf-8")
        harness = directory / "harness.cpp"
        harness.write_text('''#include <cstdio>
extern "C" int f(int), empty_fields();
int main(){for(int i=-20;i<20;++i)if(f(i)!=i+9 || empty_fields()!=42)return 1;
std::puts("PREPARATION_OK");}
''', encoding="utf-8")
        binary, image = directory / "test.exe", directory / "test.dll"

        def transform(components: dict | None = None, budgets: dict | None = None, succeeds: bool = True):
            components = components or {"call-frames": "required", "call-preparation": "required"}
            recipe.write_text(json.dumps({"schema_version": 1, "functions": {
                name: {"components": components, "budgets": budgets or {}} for name in ("f", "empty_fields")}}), encoding="utf-8")
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={recipe}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)], succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("rejected preparation emitted output")
            return result

        transform()
        rows = json.loads(report.read_text())["functions"]
        row = next(row for row in rows if row["function"] == "empty_fields")
        component = next(item for item in row["components"] if item["component"] == "call-preparation")
        metrics = component["preparation"]
        if metrics["field_addresses"] != 5 or metrics["empty_fields"] != 2 or metrics["state_steps"] != 8:
            raise AssertionError("zero-byte fields received false protection or target-only frames lost their state dependency")
        ir = output.read_text()
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
        expected = run([str(binary)]).stdout
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])
        changed, count = re.subn(r"(%pyobf\.preparation\.state\d*) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
            lambda m: f"{m[1]}.wrong = {m[2]}\n  {m[1]} = xor i32 {m[1]}.wrong, 255", ir)
        if not count: raise AssertionError("no actual preparation state read to perturb")
        altered = directory / "altered.ll"
        altered.write_text(changed, encoding="utf-8")
        run([str(args.compiler), str(altered), str(harness), "-o", str(binary)])
        invalid_execution(binary, expected)
        if "668265261" not in ir: raise AssertionError("preparation coefficient is absent")
        altered.write_text(ir.replace("668265261", "668265263"), encoding="utf-8")
        run([str(args.compiler), "-shared", str(altered), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost state-dependent call preparation" not in result.stderr:
            raise AssertionError("final preparation erasure failed for an unrelated reason")

        for budgets, reason in (({"max_preparation_steps": 1}, "max_preparation_steps"),
                ({"max_frame_bytes": 16}, "max_frame_bytes"), ({"max_body_blocks": 6}, "max_body_blocks")):
            result = transform(budgets=budgets, succeeds=False)
            if reason not in result.stderr + (report.read_text() if report.exists() else ""):
                raise AssertionError(f"preparation budget did not fail at {reason}")
        transform({"call-frames": "required", "call-preparation": "optional"}, {"max_preparation_steps": 1})
        for row in json.loads(report.read_text())["functions"]:
            if row["function"] != "f": continue
            component = next(item for item in row["components"] if item["component"] == "call-preparation")
            if component["applied"] or component["unsupported"] != 1:
                raise AssertionError("optional unsupported preparation claimed coverage")
        result = transform({"call-preparation": "required"}, succeeds=False)
        if "requires source call-frames" not in result.stderr: raise AssertionError("missing frame prerequisite accepted")
        for text in (SOURCE + '\n!pyobf.prep.inventory = !{}\n',
                SOURCE.replace('ret i32 %r }', 'ret i32 %r, !pyobf.prep.bound !0 }') + '\n!0 = !{}\n'):
            source.write_text(text, encoding="utf-8")
            result = transform(succeeds=False)
            if "native preparation: private" not in result.stderr: raise AssertionError("private preparation source artifact accepted")


if __name__ == "__main__":
    main()
