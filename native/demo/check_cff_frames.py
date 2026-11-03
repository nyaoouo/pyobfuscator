"""Differential typed call-frame, generated-helper and original-source checks."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from frame_cases import FUNCTIONS, SOURCE_IR, HARNESS, HELPER


def main(*, preparation: bool = False) -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output = directory / "source.ll", directory / "protected.ll"
        config_file, report, private = (directory / name for name in ("recipe.json", "report.json", "private.json"))
        harness, helper = directory / "harness.cpp", directory / "helper.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        helper.write_text(HELPER, encoding="utf-8")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), str(harness), str(helper), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def enable_preparation(config: dict) -> None:
            if preparation:
                for override in config.values():
                    if override.get("components", {}).get("call-frames"):
                        override["components"].setdefault("call-preparation", "required")

        def transform(config: dict, seed: int = 1, *, succeeds: bool = True, input_ir: Path = source,
                      extra: tuple[str, ...] = ()):
            enable_preparation(config)
            config_file.write_text(json.dumps({"schema_version": 1, "functions": config}), encoding="utf-8")
            output.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            try:
                result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                    f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={report}",
                    f"-pyobf-cff-private-map={private}", f"-pyobf-cff-seed={seed}", *extra,
                    "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            except AssertionError as error:
                reasons = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                           if row.get("selected") and row["status"] != "transformed"] if report.exists() else []
                raise AssertionError(f"frame failures: {reasons}") from error
            if not succeeds and output.exists(): raise AssertionError("rejected frame pipeline emitted output")
            return result

        layouts = []
        for seed, mixed in ((1, False), (17, False), (1, False), (17, True)):
            config = {name: {"components": {"call-frames": "required"}} for name in FUNCTIONS}
            if mixed:
                for override in config.values():
                    override["components"].update({name: "optional" for name in (
                        "reference-routes", "common-exit", "deduplicate-blocks", "split-blocks",
                        "integer-literals", "comparison-constants", "opaque-choices", "reachable-junk", "bogus-clones", "bogus-synthesis")})
            transform(config, seed)
            rows = json.loads(report.read_text())["functions"]
            generated = [row for row in rows if row.get("generation_component") == "call-frames"]
            frame_count = 0
            for name in FUNCTIONS:
                row = next(item for item in rows if item["function"] == name)
                frame = next(item for item in row["components"] if item["component"] == "call-frames")
                frame_count += frame["applied"]
                if frame["applied"] == 0 or frame["relocated"] != frame["applied"]:
                    raise AssertionError("original call obligations lost their actual frame invocations")
                helpers = [item for item in generated if item["generated_owner"] == name]
                if len(helpers) != frame["applied"] or any(item["requested"] or item["status"] != "transformed" or
                        item["coverage_kind"] != "shape-only" for item in helpers):
                    raise AssertionError("helper selection/coverage was missing, recursive or overstated")
            if len(generated) != frame_count: raise AssertionError("generated helper inventory differs from source frames")
            if preparation:
                for row in rows:
                    if row["function"] not in FUNCTIONS and row not in generated: continue
                    component = next(item for item in row["components"] if item["component"] == "call-preparation")
                    metrics = component["preparation"]
                    expected_sites = 1 if row in generated else next(item["applied"] for item in row["components"]
                        if item["component"] == "call-frames")
                    if (component["applied"] != expected_sites or metrics["state_steps"] !=
                            metrics["field_addresses"] + expected_sites or metrics["created_blocks"] != 2 * metrics["state_steps"]):
                        raise AssertionError("cross-state preparation counts lost actual fields/steps/invoker support")
            ir = output.read_text()
            if "!pyobf.frame." in ir or "!pyobf.prep." in ir: raise AssertionError("private frame construction data leaked")
            if not mixed:
                layouts.append((sorted(item["function"] for item in generated),
                    re.findall(r"pyobf\.call\.frame\d* = alloca (\{[^\n]+\})", ir)))
            for text in ("call fastcc signext i32 %", "sret(%Pair) align 8", "byval(%Pair) align 8"):
                if text not in ir: raise AssertionError(f"typed invoker lost original ABI: {text}")
            binary = directory / "protected.exe"
            run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
            if run([str(binary)]).stdout != expected:
                raise AssertionError("call frames changed ABI/effects/recursion/reentrant/thread behavior")
            image = directory / "protected.dll"
            run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(image)])
            headers = run([str(args.objdump), "-p", str(image)]).stdout
            exports = set(re.findall(r"^\s+\d+\s+0x[0-9a-fA-F]+\s+(\S+)", headers, re.M))
            if not set(FUNCTIONS).issubset(exports) or any(row["function"] in exports for row in generated):
                raise AssertionError("public entry exports changed or a private frame invoker was exported")
            final_report = directory / "final.json"
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report),
                 "--output", str(final_report)])
            finalized = json.loads(final_report.read_text())["functions"]
            if any(not row["final_binary_verified"] or row["requested"] for row in finalized if row.get("generated")):
                raise AssertionError("generated final coverage was omitted or counted as an original request")
            for row in finalized:
                for component in row.get("components", []):
                    if component["component"] in ("call-frames", "call-preparation") and component["applied"]:
                        if not component["final_presence_verified"] or component["individual_sites_verified"]:
                            raise AssertionError("frame presence evidence was lost or overstated")
        if layouts[0] != layouts[2] or layouts[0] == layouts[1] or layouts[0][1] == layouts[1][1]:
            raise AssertionError("helper identity/layout is nondeterministic or ignores the public seed")

        # Preserve the invoker CFG while bypassing its target field. Normal output is
        # still equivalent, but the frame-specific final feature must not be credited.
        invoker = next(row["function"] for row in generated if row["generated_owner"] == "recursive")
        body = re.search(rf"define internal void @{invoker}\(.*?\n\}}", ir, re.S)
        changed, count = re.subn(r"(call i32 )%[\w.]+(\(i32 )", r"\g<1>@recursive\2", body.group())
        if count != 1: raise AssertionError("frame erasure did not reach the real target invocation")
        altered = directory / "altered.ll"
        altered.write_text(ir[:body.start()] + changed + ir[body.end():], encoding="utf-8")
        image = directory / "erased.dll"
        run([str(args.compiler), "-shared", str(altered), str(helper), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost typed frame invoker" not in result.stderr:
            raise AssertionError(f"frame erasure failed for an unrelated reason: {result.stderr}")
        missing = json.loads(report.read_text())
        missing["functions"] = [row for row in missing["functions"] if row["function"] != invoker]
        bad_report = directory / "missing-helper.json"
        bad_report.write_text(json.dumps(missing), encoding="utf-8")
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump),
                      str(directory / "protected.dll"), str(bad_report)], succeeds=False)
        if "call frame helper inventory is incomplete" not in result.stderr:
            raise AssertionError("missing generated helper report was credited as complete frame coverage")

        for name, budgets, reason in (("calls", {"max_frame_sites": 1}, "max_frame_sites"),
                ("calls", {"max_frame_bytes": 8}, "max_frame_bytes"),
                ("calls", {"max_frame_total_bytes": 16}, "max_frame_total_bytes"),
                ("musttail_use", {}, "musttail"), ("variadic_use", {}, "nonvariadic"),
                ("bundled", {}, "bundles"), ("callback", {}, "zero eligible")):
            transform({name: {"components": {"call-frames": "required"}, "budgets": budgets}}, succeeds=False)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            if reason not in row.get("reason", ""): raise AssertionError(f"incorrect unsupported frame: {row}")
        result = transform({"calls": {"components": {"call-frames": "required", "internal-calls": "optional"}}}, succeeds=False)
        if "mutually exclusive" not in result.stderr: raise AssertionError("legacy frame routing conflict did not fail")
        transform({"recursive": {"components": {"call-frames": "required"}}}, succeeds=False,
                  extra=("-pyobf-cff-require-decision-flow=true",))
        failures = [row for row in json.loads(report.read_text())["functions"] if row.get("generated")]
        if not failures or any("no original decision flow" not in row.get("reason", "") for row in failures):
            raise AssertionError("strict decision-flow silently exempted generated invokers")
        for label, text, reason in (
                ("private", SOURCE_IR.replace("ret i64 %bits", "ret i64 %bits, !pyobf.frame.storage !0") + "\n!0 = !{}\n",
                 "private frame artifacts"),
                ("inventory", SOURCE_IR + "\n!pyobf.frame.inventory = !{}\n", "private inventory"),
                ("collision", SOURCE_IR + f"\ndeclare void @{invoker}(ptr)\n", "collides with an existing symbol"),
                ("scalable", '''target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
define internal <vscale x 2 x i32> @v(<vscale x 2 x i32> %x) { ret <vscale x 2 x i32> %x }
define void @f(<vscale x 2 x i32> %x) { %r = call <vscale x 2 x i32> @v(<vscale x 2 x i32> %x)
ret void }
''', "unsupported storage"),
                ("physical-frame", '''target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
declare ptr @llvm.returnaddress(i32 immarg)
define internal ptr @peek() { %p = call ptr @llvm.returnaddress(i32 0)
ret ptr %p }
define ptr @f() { %p = call ptr @peek()
ret ptr %p }
''', "physical caller-frame observation")):
            altered.write_text(text, encoding="utf-8")
            name = "f" if label in ("scalable", "physical-frame") else "recursive"
            result = transform({name: {"components": {"call-frames": "required"}}}, 17,
                               succeeds=False, input_ir=altered)
            failure = result.stderr + (report.read_text() if report.exists() else "")
            if reason not in failure: raise AssertionError(f"{label} frame rejection failed for an unrelated reason")
        altered.write_text(SOURCE_IR.replace('e-p:64:64-i64:64-n8:16:32:64-S128',
                                             'e-p:32:32-i64:64-n8:16:32-S128'), encoding="utf-8")
        transform({"calls": {"components": {"call-frames": "required"}}}, input_ir=altered)
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "calls")
        frame = next(item for item in row["components"] if item["component"] == "call-frames")
        if frame["preparation"]["per_invocation_bytes"] != (68 if preparation else 44):
            raise AssertionError("call frame storage used build-host pointer size instead of the target layout")

        requests, requested, optimized = (directory / name for name in ("requests.json", "requested.ll", "optimized.ll"))
        for name, succeeds in (("calls", True), ("folded_call", False)):
            config = {name: {"components": {"call-frames": "required"}}}
            enable_preparation(config)
            config_file.write_text(json.dumps({"schema_version": 1, "functions": config}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-requests-output={requests}",
                 "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            transform(config, succeeds=succeeds, input_ir=optimized, extra=(f"-pyobf-cff-requests-input={requests}",))
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            if succeeds:
                run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
                if run([str(binary)]).stdout != expected: raise AssertionError("O2/frame ABI or effects changed")
            elif "did not survive ordinary optimization" not in row.get("reason", ""):
                raise AssertionError("lost original calls were credited as generated frame coverage")

        # Use real frontend-lowered C++ sret/by-value calls and propagate an exception
        # through a caller with no local cleanup. Selecting EH cleanup scopes is still D1b.
        cpp = Path(__file__).with_name("frame_cpp_fixture.cpp")
        cpp_harness = Path(__file__).with_name("frame_cpp_harness.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(cpp), "-o", str(source)])
        run([str(args.compiler), str(source), str(cpp_harness), "-o", str(baseline)])
        cpp_expected = run([str(baseline)]).stdout
        transform({name: {"components": {"call-frames": "required", "reference-routes": "required"}}
                   for name in ("frame_cpp_values", "frame_throwing_caller")})
        run([str(args.compiler), str(output), str(cpp_harness), "-o", str(binary)])
        if run([str(binary)]).stdout != cpp_expected:
            raise AssertionError("real frontend C++ ABI or exception propagation changed")


if __name__ == "__main__":
    main()
