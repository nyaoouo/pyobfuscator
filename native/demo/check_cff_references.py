"""Exercise function reference routing, ABI/address identity and source obligations."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run, invalid_execution
from reference_cases import FUNCTIONS, SOURCE_IR, HARNESS, HELPER


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output = directory / "source.ll", directory / "output.ll"
        report, private, config_file = (directory / name for name in ("report.json", "private.json", "recipe.json"))
        harness, helper = directory / "harness.cpp", directory / "helper.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        helper.write_text(HELPER, encoding="utf-8")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), str(harness), str(helper), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def transform(config: dict, seed: int = 1, *, succeeds: bool = True, input_ir: Path = source,
                      extra: tuple[str, ...] = ()):
            config_file.write_text(json.dumps({"schema_version": 1, "functions": config}), encoding="utf-8")
            output.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            try:
                result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                     f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={report}",
                     f"-pyobf-cff-private-map={private}", f"-pyobf-cff-seed={seed}",
                     *extra, "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            except AssertionError as error:
                reasons = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                           if row.get("selected") and row["status"] != "transformed"] if report.exists() else []
                raise AssertionError(f"reference route failures: {reasons}") from error
            if not succeeds and output.exists(): raise AssertionError("rejected routes emitted output")
            return result

        layouts = []
        for seed, combined in ((1, False), (17, False), (1, False), (17, True)):
            config = {name: {"components": {"reference-routes": "required"}} for name in FUNCTIONS}
            if combined:
                for value in config.values():
                    value["components"].update({name: "optional" for name in (
                        "common-exit", "deduplicate-blocks", "split-blocks", "bogus-clones",
                        "bogus-synthesis", "opaque-choices", "reachable-junk", "integer-literals",
                        "comparison-constants", "decoy-transitions")})
            transform(config, seed)
            ir = output.read_text()
            rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
            maps = {row["function"]: row for row in json.loads(private.read_text())["functions"]}
            if "!pyobf.ref." in ir: raise AssertionError("private route descriptors leaked into final output")
            for name in FUNCTIONS:
                component = next(item for item in rows[name]["components"] if item["component"] == "reference-routes")
                if not component["applied"] or sum(component["applied_types"].values()) != component["applied"]:
                    raise AssertionError(f"missing physical reference evidence: {component}")
                aliases = [site for site in component["sites"] if site["status"] == "relocated"]
                locations = {site["id"]: site for site in maps[name]["sites"]}
                if not aliases or any(not site.get("replacement") or
                        not locations[site["id"]]["transformed_ir"] for site in aliases):
                    raise AssertionError("source reference aliases lost their physical route")
            body = re.search(r"define i32 @abi\(.*?\n\}", ir, re.S).group()
            for text in ("call fastcc signext i32 %", "sret(%Pair) align 8", "byval(%Pair) align 8"):
                if text not in body: raise AssertionError(f"call ABI changed: {text}")
            if not combined:
                call_body = re.search(r"define i32 @calls\(.*?\n\}", ir, re.S).group()
                layout = re.findall(r"store volatile ptr ([^,\n]+), ptr %pyobf\.reference\.init", call_body)
                if not layout: raise AssertionError("reference table has no actual initialization")
                layouts.append(layout)
            binary = directory / "protected.exe"
            run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
            if run([str(binary)]).stdout != expected:
                raise AssertionError("ABI/effects/recursion/reentrancy/PHI/address/thread semantics changed")
            image = directory / "protected.dll"
            run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(image)])
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])
        if layouts[0] != layouts[2] or layouts[0] == layouts[1]:
            raise AssertionError("route layout is nondeterministic or ignores the build seed")

        # Corrupt only a reference state read; leave CFG transitions and other routes intact.
        body = re.search(r"define i32 @tail_call\(.*?\n\}", ir, re.S)
        changed, count = re.subn(r"(%pyobf\.reference\.state(?:\.?\d+)?) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
            lambda match: f"{match[1]}.original = {match[2]}\n  {match[1]} = xor i32 {match[1]}.original, 1", body.group())
        if count != 1: raise AssertionError("tail route lost its actual CFF state dependency")
        altered = directory / "altered.ll"
        altered.write_text(ir[:body.start()] + changed + ir[body.end():], encoding="utf-8")
        binary = directory / "altered.exe"
        run([str(args.compiler), str(altered), str(harness), str(helper), "-o", str(binary)])
        invalid_execution(binary, expected)

        # Keep the CFG key domain while erasing just the reference-domain coefficient.
        erased = directory / "erased.ll"
        if str(0x165667b1) not in ir: raise AssertionError("route key domain is absent")
        erased.write_text(ir.replace(str(0x165667b1), str(0x165667b3)), encoding="utf-8")
        image = directory / "erased.dll"
        run([str(args.compiler), "-shared", str(erased), str(helper), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost state-dependent reference routes" not in result.stderr:
            raise AssertionError(f"reference erasure failed for an unrelated reason: {result.stderr}")

        for name, reason, budgets in (("calls", "max_reference_slots", {"max_reference_slots": 2}),
                ("calls", "max_reference_sites", {"max_reference_sites": 1}),
                ("variadic_use", "nonvariadic", {}), ("musttail_use", "musttail", {}),
                ("bundled", "bundles", {}), ("nested", "scalar AS0", {})):
            transform({name: {"components": {"reference-routes": "required"}, "budgets": budgets}}, succeeds=False)
            row = next(item for item in json.loads(report.read_text())["functions"] if item["function"] == name)
            if reason not in row.get("reason", ""): raise AssertionError(f"incorrect unsupported route: {row}")
        result = transform({"calls": {"components": {"reference-routes": "required", "internal-calls": "optional"}}}, succeeds=False)
        if "mutually exclusive" not in result.stderr: raise AssertionError("legacy route conflict did not reject")
        transform({"nested": {"components": {"reference-routes": "optional"}}})
        row = next(item for item in json.loads(report.read_text())["functions"] if item["function"] == "nested")
        component = next(item for item in row["components"] if item["component"] == "reference-routes")
        if component["applied"] or component["unsupported"] != 1:
            raise AssertionError("optional nested aggregate reference was falsely credited")
        for name, text, reason in (
                ("layout", SOURCE_IR.replace('target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"', ''), "explicit 32-bit"),
                ("private", SOURCE_IR.replace("ret i64 %bits", "ret i64 %bits, !pyobf.ref.bound !0") + "\n!0 = !{}\n",
                 "unfinished private route artifacts")):
            altered.write_text(text, encoding="utf-8")
            result = transform({"calls": {"components": {"reference-routes": "required"}}},
                               succeeds=False, input_ir=altered)
            failure = result.stderr + (report.read_text() if report.exists() else "")
            if reason not in failure: raise AssertionError(f"{name} rejection failed at an unrelated boundary")
        altered.write_text(SOURCE_IR.replace('e-p:64:64-i64:64-n8:16:32:64-S128',
                                             'e-p:32:32-i64:64-n8:16:32-S128'), encoding="utf-8")
        transform({"calls": {"components": {"reference-routes": "required"}}}, input_ir=altered)
        row = next(item for item in json.loads(report.read_text())["functions"] if item["function"] == "calls")
        preparation = next(item for item in row["components"] if item["component"] == "reference-routes")["preparation"]
        if preparation["per_invocation_bytes"] != 4 * preparation["table_slots"]:
            raise AssertionError("32-bit table storage used host pointer size")

        # Original obligations erased by ordinary optimization must fail strict coverage.
        requests, requested, optimized = (directory / name for name in ("requests.json", "requested.ll", "optimized.ll"))
        for name, succeeds in (("calls", True), ("folded", False)):
            config = {name: {"components": {"reference-routes": "required"}}}
            config_file.write_text(json.dumps({"schema_version": 1, "functions": config}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-requests-output={requests}",
                 "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            transform(config, succeeds=succeeds, input_ir=optimized, extra=(f"-pyobf-cff-requests-input={requests}",))
            row = next(item for item in json.loads(report.read_text())["functions"] if item["function"] == name)
            if succeeds:
                binary = directory / "optimized.exe"
                run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
                if row["status"] != "transformed" or run([str(binary)]).stdout != expected:
                    raise AssertionError("retained O2 reference requests changed executable behavior")
            elif "did not survive ordinary optimization" not in row.get("reason", ""):
                raise AssertionError("erased original function references were silently credited")


if __name__ == "__main__":
    main()
