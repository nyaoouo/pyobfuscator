"""Unsupported local objects, strict budgets, target layout and private-input failures."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from local_cases import SOURCE_IR, FUNCTIONS


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, config, report = (directory / name for name in ("source.ll", "output.ll", "recipe.json", "report.json"))

        def transform(text: str, name: str = "f", *, budgets: dict | None = None, mode: str = "required", succeeds: bool = False):
            source.write_text(text, encoding="utf-8")
            config.write_text(json.dumps({"schema_version": 1, "functions": {name: {
                "components": {"indexed-locals": mode}, "budgets": budgets or {}}}}), encoding="utf-8")
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)], succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("unsupported local object emitted output")
            return result.stderr + (report.read_text() if report.exists() else "")

        for name, budgets, reason in (("local_alias", {"max_local_slots": 2}, "max_local_slots"),
                ("local_volatile", {"max_local_routes": 1}, "max_local_routes"),
                ("local_volatile", {"max_local_bytes": 8}, "max_local_bytes"),
                ("local_volatile", {"max_local_slots": 3}, "max_local_slots must be a power of two")):
            if reason not in transform(SOURCE_IR, name, budgets=budgets): raise AssertionError(f"incorrect local budget rejection: {reason}")
        layout = 'target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'
        cases = (
            ("dynamic", '''define i32 @f(i32 %n) { %a = alloca i32, i32 %n
store i32 7, ptr %a
ret i32 7 }''', "dynamic, nonentry"),
            ("nonentry", '''define i32 @f(i32 %x) { entry: br label %body
body: %a = alloca i32
store i32 %x, ptr %a
br label %exit
exit: %r = load i32, ptr %a
ret i32 %r }''', "dynamic, nonentry"),
            ("empty", '''define void @f() { %a = alloca {}
store {} zeroinitializer, ptr %a
ret void }''', "unsupported or empty storage"),
            ("scalable", '''define void @f(<vscale x 2 x i32> %x) { %a = alloca <vscale x 2 x i32>
store <vscale x 2 x i32> %x, ptr %a
ret void }''', "unsupported or empty storage"),
            ("special", '''define void @f() { %a = alloca swifterror ptr
store ptr null, ptr %a
ret void }''', "special allocation ABI"),
            ("addressspace", '''define void @f() { %a = alloca i32, addrspace(1)
store i32 7, ptr addrspace(1) %a
ret void }''', "AS0 stack layout"),
            ("objectsize", '''declare i64 @llvm.objectsize.i64.p0(ptr, i1 immarg, i1 immarg, i1 immarg)
define i64 @f() { %a = alloca i32
%r = call i64 @llvm.objectsize.i64.p0(ptr %a, i1 false, i1 false, i1 false)
ret i64 %r }''', "intrinsic, bundle"),
            ("bundle", '''declare void @consume(ptr)
define void @f() { %a = alloca i32
call void @consume(ptr %a) ["deopt"(ptr %a)]
ret void }''', "intrinsic, bundle"),
            ("assembly", '''define void @f() { %a = alloca i32
call void asm sideeffect "", "r"(ptr %a)
ret void }''', "assembly and musttail"),
            ("unused", '''define i32 @f(i32 %x) { %a = alloca i32
ret i32 %x }''', "non-control address use"),
        )
        for label, text, reason in cases:
            if reason not in transform(layout + text): raise AssertionError(f"{label} failed for an unrelated reason")
            transform(layout + text, mode="optional", succeeds=True)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "f")
            component = next(item for item in row["components"] if item["component"] == "indexed-locals")
            if component["applied"] or component["unsupported"] != 1 or "pyobf.local.table" in output.read_text():
                raise AssertionError(f"unsupported optional object was rewritten or credited: {label}")
        text = 'define i32 @f(i32 %x) { %a = alloca i32\nstore i32 %x, ptr %a\n%r = load i32, ptr %a\nret i32 %r }'
        if "explicit 32/64-bit" not in transform(text): raise AssertionError("unknown stack layout accepted")
        for private in (layout + text.replace('ret i32 %r }', 'ret i32 %r, !pyobf.local.bound !0 }') + '\n!0 = !{}\n',
                layout + text + '\n!pyobf.local.inventory = !{}\n'):
            if "indexed locals: private" not in transform(private): raise AssertionError("private local input accepted")
        transform(SOURCE_IR, "local_values", mode="off", succeeds=True)
        if "pyobf.local.table" in output.read_text(): raise AssertionError("disabled locals emitted a table")
        target32 = SOURCE_IR.replace('e-p:64:64-i64:64-n8:16:32:64-S128', 'e-p:32:32-i64:64-n8:16:32-S128')
        for name in FUNCTIONS:
            transform(target32, name, succeeds=True)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            metrics = next(item["preparation"] for item in row["components"] if item["component"] == "indexed-locals")
            if metrics["per_invocation_bytes"] != metrics["table_slots"] * 4:
                raise AssertionError("local table storage uses host rather than target pointer size")


if __name__ == "__main__":
    main()
