"""Execute external-frame adapters against a separately linked provider DLL."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from external_cases import FUNCTIONS, SOURCE_IR, PROVIDER_IR, HARNESS, HELPER, CPP_USER, CPP_PROVIDER


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, provider, output, config, report = (directory / name for name in
            ("source.ll", "provider.ll", "output.ll", "recipe.json", "report.json"))
        harness, helper = directory / "harness.cpp", directory / "helper.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8"); provider.write_text(PROVIDER_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8"); helper.write_text(HELPER, encoding="utf-8")
        library, imports = directory / "provider.dll", directory / "provider.a"
        run([str(args.compiler), "-shared", str(provider), str(helper), "-o", str(library), f"-Wl,--out-implib,{imports}"])
        baseline, binary, image = directory / "plain.exe", directory / "protected.exe", directory / "protected.dll"
        run([str(args.compiler), str(source), str(harness), str(imports), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def transform(functions: dict, seed: int = 1, *, input_ir: Path = source, succeeds: bool = True, extra: tuple[str, ...] = ()):
            config.write_text(json.dumps({"schema_version": 1, "functions": functions}), encoding="utf-8")
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", f"-pyobf-cff-seed={seed}", *extra,
                "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("rejected external pipeline emitted output")
            return result

        layouts = []
        for seed, mixed in ((1, False), (17, False), (1, False), (17, True)):
            selection = {name: {"components": {"external-calls": "required"}} for name in FUNCTIONS}
            if mixed:
                for override in selection.values(): override["components"].update({name: "optional" for name in
                    ("call-frames", "call-preparation", "reference-routes", "indexed-locals", "common-exit", "split-blocks",
                     "deduplicate-blocks", "integer-literals", "comparison-constants", "opaque-choices", "reachable-junk",
                     "bogus-clones", "bogus-synthesis")})
            transform(selection, seed)
            rows = json.loads(report.read_text())["functions"]
            generated = [row for row in rows if row.get("generation_component") == "external-calls"]
            for name in FUNCTIONS:
                row = next(row for row in rows if row["function"] == name)
                component = next(item for item in row["components"] if item["component"] == "external-calls")
                helpers = [item for item in generated if item["generated_owner"] == name]
                if (not component["applied"] or component["applied"] != len(helpers) or component["relocated"] != len(helpers) or
                        component["preparation"]["frames"] != len(helpers) or any(item["requested"] or
                        item["status"] != "transformed" for item in helpers)):
                    raise AssertionError(f"external source/helper ownership or coverage differs: {row}")
            text = output.read_text()
            if "!pyobf.frame." in text or "!pyobf.prep." in text: raise AssertionError("private adapter descriptors leaked")
            if not mixed: layouts.append((sorted(row["function"] for row in generated),
                re.findall(r"pyobf\.call\.frame\d* = alloca (\{[^\n]+\})", text)))
            run([str(args.compiler), str(output), str(harness), str(imports), "-o", str(binary)])
            if run([str(binary)]).stdout != expected: raise AssertionError("external ABI/effects/callback/reentrant/thread results changed")
            run([str(args.compiler), "-shared", str(output), str(imports), "-o", str(image)])
            headers = run([str(args.objdump), "-p", str(image)]).stdout
            if "provider.dll" not in headers: raise AssertionError("provider was not a real DLL import")
            exports = set(re.findall(r"^\s+\d+\s+0x[0-9a-fA-F]+\s+(\S+)", headers, re.M))
            if any(row["function"] in exports for row in generated): raise AssertionError("private external adapter exported")
            final = directory / "final.json"
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report), "--output", str(final)])
            for row in json.loads(final.read_text())["functions"]:
                for component in row.get("components", []):
                    if component["component"] == "external-calls" and component["applied"]:
                        if not component["final_presence_verified"] or component["individual_sites_verified"]:
                            raise AssertionError("external presence evidence missing or overstated")
        if layouts[0] != layouts[2] or layouts[0] == layouts[1] or layouts[0][1] == layouts[1][1]:
            raise AssertionError("external layout/identity is nondeterministic or seed invariant")

        # Erase just one adapter's actual indirect invocation while preserving its CFF.
        invoker = next(row["function"] for row in generated if row["generated_owner"] == "tail_call")
        body = re.search(rf"define internal void @{invoker}\(.*?\n\}}", text, re.S)
        changed, count = re.subn(r"(call i32 )%[\w.]+(\(i32 )", r"\g<1>@increment\2", body.group())
        if count != 1: raise AssertionError("external erasure missed actual target invocation")
        altered = directory / "altered.ll"
        altered.write_text(text[:body.start()] + changed + text[body.end():], encoding="utf-8")
        run([str(args.compiler), "-shared", str(altered), str(imports), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost typed frame invoker" not in result.stderr: raise AssertionError("external erasure failed for an unrelated reason")

        for name, budgets, reason in (("calls", {"max_frame_sites": 2}, "max_frame_sites"),
                ("calls", {"max_frame_bytes": 8}, "max_frame_bytes"),
                ("calls", {"max_frame_total_bytes": 16}, "max_frame_total_bytes"),
                ("musttail_use", {}, "musttail"), ("variadic_use", {}, "nonvariadic"), ("bundled", {}, "bundles"),
                ("recursive", {}, "zero eligible")):
            transform({name: {"components": {"external-calls": "required"}, "budgets": budgets}}, succeeds=False)
            if reason not in report.read_text(): raise AssertionError(f"external rejection lost {reason}")
        transform({"calls": {"components": {"external-calls": "required", "call-frames": "required"},
                             "budgets": {"max_frame_sites": 3}}}, succeeds=False)
        if "max_frame_sites" not in report.read_text(): raise AssertionError("combined internal/external frame budget was bypassed")
        result = transform({"calls": {"components": {"external-calls": "required", "internal-calls": "optional"}}}, succeeds=False)
        if "mutually exclusive" not in result.stderr: raise AssertionError("legacy routing was allowed to replace owned external helper routes")

        for declaration, call, reason in (
                ("declare extern_weak i32 @weak(i32)", "%r = call i32 @weak(i32 %x)", "strong external"),
                ("declare i32 @twice(i32) returns_twice", "%r = call i32 @twice(i32 %x)", "special call-control"),
                ("declare fastcc i32 @fast(i32)", "%r = call i32 @fast(i32 %x)", "exact nonvariadic")):
            altered.write_text('target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n' + declaration +
                '\ndefine i32 @f(i32 %x) {\n' + call + '\nret i32 %r\n}\n', encoding="utf-8")
            transform({"f": {"components": {"external-calls": "required"}}}, input_ir=altered, succeeds=False)
            if reason not in report.read_text(): raise AssertionError(f"external ABI rejection missed {reason}")
            nonlocal_control = "returns_twice" in declaration
            transform({"f": {"components": {"external-calls": "optional"}}}, input_ir=altered, succeeds=not nonlocal_control)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "f")
            component = next(item for item in row["components"] if item["component"] == "external-calls")
            if nonlocal_control and "returns-twice" not in row.get("reason", ""):
                raise AssertionError("optional framing bypassed unsafe function control semantics")
            if component["applied"] or not component["unsupported"]: raise AssertionError("unsupported external was credited")

        requests, requested, optimized = (directory / name for name in ("requests.json", "requested.ll", "optimized.ll"))
        for name, survives in (("calls", True), ("folded_external", False)):
            selection = {name: {"components": {"external-calls": "required"}}}
            config.write_text(json.dumps({"schema_version": 1, "functions": selection}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}", "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            transform(selection, input_ir=optimized, succeeds=survives, extra=(f"-pyobf-cff-requests-input={requests}",))
            if survives:
                run([str(args.compiler), str(output), str(harness), str(imports), "-o", str(binary)])
                if run([str(binary)]).stdout != expected: raise AssertionError("O2 external ABI/effects changed")
            elif "did not survive ordinary optimization" not in report.read_text(): raise AssertionError("lost external request credited")

        altered.write_text(SOURCE_IR.replace('e-p:64:64-i64:64-n8:16:32:64-S128',
                                             'e-p:32:32-i64:64-n8:16:32-S128'), encoding="utf-8")
        for prepared, expected_bytes in ((False, 44), (True, 68)):
            components = {"external-calls": "required"}
            if prepared: components["call-preparation"] = "required"
            transform({"calls": {"components": components}}, input_ir=altered)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "calls")
            frame = next(item for item in row["components"] if item["component"] == "external-calls")
            if frame["preparation"]["per_invocation_bytes"] != expected_bytes:
                raise AssertionError("external frames used host layout instead of target-32 layout")
        transform({"calls": {"components": {"external-calls": "required", "call-preparation": "required"},
                              "budgets": {"max_preparation_steps": 1}}}, succeeds=False)
        if "max_preparation_steps" not in report.read_text(): raise AssertionError("external preparation budget ignored")

        cpp_user, cpp_provider = directory / "user.cpp", directory / "provider.cpp"
        cpp_user.write_text(CPP_USER, encoding="utf-8"); cpp_provider.write_text(CPP_PROVIDER, encoding="utf-8")
        cpp_harness = Path(__file__).with_name("frame_cpp_harness.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-shared", str(cpp_provider),
             "-o", str(library), f"-Wl,--out-implib,{imports}"])
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(cpp_user), "-o", str(source)])
        run([str(args.compiler), str(source), str(cpp_harness), str(imports), "-o", str(baseline)])
        cpp_expected = run([str(baseline)]).stdout
        transform({name: {"components": {"external-calls": "required", "call-preparation": "required", "reference-routes": "required"}}
                   for name in ("frame_cpp_values", "frame_throwing_caller")})
        run([str(args.compiler), str(output), str(cpp_harness), str(imports), "-o", str(binary)])
        if run([str(binary)]).stdout != cpp_expected: raise AssertionError("real external C++ ABI/exception propagation changed")


if __name__ == "__main__":
    main()
