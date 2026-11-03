"""Execute imported-address routes, exact original uses and typed-frame composition."""

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run, invalid_execution
from external_cases import SOURCE_IR, PROVIDER_IR, HARNESS, HELPER, CPP_USER, CPP_PROVIDER


FUNCTIONS = ("calls", "abi", "callback", "choose", "phi", "returned", "same_address",
             "address_bits", "save_address", "tail_call", "framed_reentrant", "framed_loop", "framed_values")


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

        def transform(selection: dict, seed: int = 1, *, input_ir: Path = source, succeeds: bool = True, extra: tuple[str, ...] = ()):
            config.write_text(json.dumps({"schema_version": 1, "functions": selection}), encoding="utf-8")
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            try:
                result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                    f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", f"-pyobf-cff-seed={seed}", *extra,
                    "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            except AssertionError as error:
                reasons = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                           if row.get("selected") and row["status"] != "transformed"] if report.exists() else []
                raise AssertionError(f"import route failures: {reasons}") from error
            if not succeeds and output.exists(): raise AssertionError("rejected imported route emitted output")
            return result

        layouts = []
        for seed, mixed in ((1, False), (17, False), (1, False), (17, True)):
            selection = {name: {"components": {"import-routes": "required"}} for name in FUNCTIONS}
            if mixed:
                for override in selection.values(): override["components"].update({name: "optional" for name in
                    ("external-calls", "call-frames", "call-preparation", "reference-routes", "indexed-locals", "common-exit",
                     "split-blocks", "deduplicate-blocks", "integer-literals", "comparison-constants", "opaque-choices",
                     "reachable-junk", "bogus-clones", "bogus-synthesis")})
            transform(selection, seed)
            rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
            for name in FUNCTIONS:
                component = next(item for item in rows[name]["components"] if item["component"] == "import-routes")
                metrics = component["preparation"]
                if (not component["applied"] or component["unsupported"] or metrics["source_uses"] != component["applied"] or
                        metrics["per_invocation_bytes"] != metrics["table_slots"] * 8):
                    raise AssertionError(f"imported source/use/table accounting differs: {name}: {component}")
            text = output.read_text()
            if "!pyobf.ref." in text: raise AssertionError("private imported route state/layout leaked")
            if not mixed:
                body = re.search(r"define i32 @calls\(.*?\n\}", text, re.S).group()
                layouts.append(re.findall(r"store volatile ptr ([^,]+), ptr %pyobf\.import\.init\d*", body))
            run([str(args.compiler), str(output), str(harness), str(imports), "-o", str(binary)])
            if run([str(binary)]).stdout != expected: raise AssertionError("imported target/callback/PHI/select/escape/ABI/effects changed")
            run([str(args.compiler), "-shared", str(output), str(imports), "-o", str(image)])
            final = directory / "final.json"
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report), "--output", str(final)])
            for row in json.loads(final.read_text())["functions"]:
                for component in row.get("components", []):
                    if component["component"] == "import-routes" and component["applied"]:
                        if not component["final_presence_verified"] or component["individual_sites_verified"]:
                            raise AssertionError("imported final presence missing or overstated")
        if layouts[0] != layouts[2] or layouts[0] == layouts[1]: raise AssertionError("import layout is nondeterministic or seed invariant")

        selection = {"calls": {"components": {"import-routes": "required"}}}
        transform(selection)
        text = output.read_text()
        altered = directory / "altered.ll"
        coefficient = str(0xD3A2646D - (1 << 32))
        if coefficient not in text: raise AssertionError("missing imported mask coefficient")
        altered.write_text(text.replace(coefficient, str(int(coefficient) + 2)), encoding="utf-8")
        run([str(args.compiler), "-shared", str(altered), str(imports), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost state-dependent reference routes" not in result.stderr: raise AssertionError("import erasure failed for an unrelated reason")
        changed, count = re.subn(r"(%pyobf\.reference\.state\d*) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
            lambda match: f"{match[1]}.wrong = {match[2]}\n  {match[1]} = xor i32 {match[1]}.wrong, 255", text)
        if not count: raise AssertionError("missing live imported state read")
        altered.write_text(changed, encoding="utf-8")
        run([str(args.compiler), str(altered), str(harness), str(imports), "-o", str(binary)])
        invalid_execution(binary, expected)

        for name, budgets, reason in (("calls", {"max_import_sites": 1}, "max_import_sites"),
                ("calls", {"max_import_slots": 2}, "max_import_slots"), ("calls", {"max_import_slots": 3}, "power of two"),
                ("variadic_use", {}, "nonvariadic"), ("musttail_use", {}, "musttail"),
                ("bundled", {}, "bundles"), ("nested", {}, "scalar AS0"), ("recursive", {}, "zero eligible")):
            result = transform({name: {"components": {"import-routes": "required"}, "budgets": budgets}}, succeeds=False)
            message = result.stderr + (report.read_text() if report.exists() else "")
            if reason not in message: raise AssertionError(f"import rejection lost {reason}")
        for declaration, call, reason in (("declare extern_weak i32 @weak(i32)", "%r = call i32 @weak(i32 %x)", "strong external"),
                ("declare i32 @twice(i32) returns_twice", "%r = call i32 @twice(i32 %x)", "special call-control")):
            altered.write_text('target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n' + declaration +
                '\ndefine i32 @f(i32 %x) {\n' + call + '\nret i32 %r\n}\n', encoding="utf-8")
            transform({"f": {"components": {"import-routes": "required"}}}, input_ir=altered, succeeds=False)
            if reason not in report.read_text(): raise AssertionError(f"import control rejection missed {reason}")
            nonlocal_control = "returns_twice" in declaration
            transform({"f": {"components": {"import-routes": "optional"}}}, input_ir=altered, succeeds=not nonlocal_control)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "f")
            component = next(item for item in row["components"] if item["component"] == "import-routes")
            if nonlocal_control and "returns-twice" not in row.get("reason", ""):
                raise AssertionError("optional importing bypassed unsafe function control semantics")
            if component["applied"] or not component["unsupported"]: raise AssertionError("unsupported import received route credit")
        for label, text, reason in (
                ("private", SOURCE_IR.replace("ret i64 %bits", "ret i64 %bits, !pyobf.ref.layout !0") + '\n!0 = !{}\n', "private route artifacts"),
                ("private-function", SOURCE_IR.replace('define i32 @calls(i32 %x, ptr %p) noinline {',
                    'define i32 @calls(i32 %x, ptr %p) noinline !pyobf.ref.layout !0 {') + '\n!0 = !{}\n', "private route artifacts"),
                ("private-named", SOURCE_IR + '\n!pyobf.ref.layout = !{}\n', "private route artifacts"),
                ("layout", SOURCE_IR.replace('target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"', ''), "explicit 32-bit or 64-bit"),
                ("mixed-nested", SOURCE_IR + '\ndefine void @mixed_nested(ptr %p) {\nstore [2 x ptr] [ptr @local_identity, ptr @increment], ptr %p\nret void\n}\n', "scalar AS0")):
            altered.write_text(text, encoding="utf-8")
            name = "mixed_nested" if label == "mixed-nested" else "calls"
            result = transform({name: {"components": {"import-routes": "required"}}}, input_ir=altered, succeeds=False)
            if reason not in result.stderr + (report.read_text() if report.exists() else ""):
                raise AssertionError(f"import edge rejection lost {label}")
        altered.write_text(SOURCE_IR + '''
define ptr @pure_address() noinline memory(none) speculatable willreturn nounwind {
  ret ptr @increment
}
define void @discarded_call() {
  %unused = call ptr @pure_address()
  ret void
}
''', encoding="utf-8")
        observed = directory / "effects.ll"
        run([str(args.opt), "-passes=default<O2>", "-S", str(altered), "-o", str(observed)])
        consumer = re.search(r"define void @discarded_call\(.*?\n\}", observed.read_text(), re.S).group()
        if "@pure_address" in consumer: raise AssertionError("pure source call was not removable before instrumentation")
        transform({"pure_address": {"components": {"import-routes": "required"}}}, input_ir=altered)
        # This checks attribute semantics only; arbitrary post-CFF O2 shape retention is not supported.
        run([str(args.opt), "-passes=default<O2>", "-S", str(output), "-o", str(observed)])
        consumer = re.search(r"define void @discarded_call\(.*?\n\}", observed.read_text(), re.S).group()
        if "@pure_address" not in consumer: raise AssertionError("stale pure/speculatable attributes erased the new volatile observation")
        altered.write_text(SOURCE_IR.replace('e-p:64:64-i64:64-n8:16:32:64-S128',
                                             'e-p:32:32-i64:64-n8:16:32-S128'), encoding="utf-8")
        transform(selection, input_ir=altered)
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "calls")
        component = next(item for item in row["components"] if item["component"] == "import-routes")
        if component["preparation"]["per_invocation_bytes"] != 16: raise AssertionError("import table used host instead of target-32 pointers")

        requests, requested, optimized = (directory / name for name in ("requests.json", "requested.ll", "optimized.ll"))
        for name, survives in (("calls", True), ("folded", False)):
            selection = {name: {"components": {"import-routes": "required"}}}
            config.write_text(json.dumps({"schema_version": 1, "functions": selection}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}", "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            transform(selection, input_ir=optimized, succeeds=survives, extra=(f"-pyobf-cff-requests-input={requests}",))
            if survives:
                run([str(args.compiler), str(output), str(harness), str(imports), "-o", str(binary)])
                if run([str(binary)]).stdout != expected: raise AssertionError("O2 imported source behavior changed")
            elif "did not survive ordinary optimization" not in report.read_text(): raise AssertionError("lost imported source credited")

        cpp_user, cpp_provider = directory / "user.cpp", directory / "provider.cpp"
        cpp_user.write_text(CPP_USER, encoding="utf-8"); cpp_provider.write_text(CPP_PROVIDER, encoding="utf-8")
        cpp_harness = Path(__file__).with_name("frame_cpp_harness.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-shared", str(cpp_provider),
             "-o", str(library), f"-Wl,--out-implib,{imports}"])
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(cpp_user), "-o", str(source)])
        run([str(args.compiler), str(source), str(cpp_harness), str(imports), "-o", str(baseline)])
        cpp_expected = run([str(baseline)]).stdout
        transform({name: {"components": {"import-routes": "required", "external-calls": "required",
            "call-preparation": "required", "reference-routes": "required"}}
                   for name in ("frame_cpp_values", "frame_throwing_caller")})
        run([str(args.compiler), str(output), str(cpp_harness), str(imports), "-o", str(binary)])
        if run([str(binary)]).stdout != cpp_expected: raise AssertionError("real imported C++ ABI/exception propagation changed")


if __name__ == "__main__":
    main()
