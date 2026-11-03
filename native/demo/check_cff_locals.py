"""Execute typed original locals through state-indexed private object tables."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run, invalid_execution
from local_cases import FUNCTIONS, SOURCE_IR, HARNESS, HELPER


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, config, report, private = (directory / name for name in
            ("source.ll", "protected.ll", "recipe.json", "report.json", "private.json"))
        harness, helper = directory / "harness.cpp", directory / "helper.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8"); helper.write_text(HELPER, encoding="utf-8")
        baseline, binary, image = directory / "plain.exe", directory / "protected.exe", directory / "protected.dll"
        run([str(args.compiler), str(source), str(harness), str(helper), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def transform(functions: dict, seed: int = 1, *, input_ir: Path = source, succeeds: bool = True, extra: tuple[str, ...] = ()):
            config.write_text(json.dumps({"schema_version": 1, "functions": functions}), encoding="utf-8")
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", f"-pyobf-cff-private-map={private}",
                f"-pyobf-cff-seed={seed}", *extra, "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("rejected local pipeline emitted output")
            return result

        layouts = []
        for seed, mixed in ((1, False), (17, False), (1, False), (17, True)):
            selection = {name: {"components": {"indexed-locals": "required"}} for name in FUNCTIONS}
            if mixed:
                for override in selection.values(): override["components"].update({name: "optional" for name in
                    ("reference-routes", "call-frames", "call-preparation", "common-exit", "split-blocks", "deduplicate-blocks",
                     "integer-literals", "comparison-constants", "opaque-choices", "reachable-junk", "bogus-clones", "bogus-synthesis")})
            transform(selection, seed)
            rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
            for name in FUNCTIONS:
                component = next(item for item in rows[name]["components"] if item["component"] == "indexed-locals")
                body = re.search(rf"define i32 @{name}\(.*?\n\}}", SOURCE_IR, re.S).group()
                objects = len(re.findall(r"\balloca\b", body))
                metrics = component["preparation"]
                if (component["applied"] != objects or metrics["objects"] != objects or component["unsupported"] or
                        metrics["address_routes"] < objects or metrics["table_slots"] <= objects or
                        metrics["per_invocation_bytes"] != metrics["table_slots"] * 8):
                    raise AssertionError(f"indexed local object/use/storage counts differ: {name}: {component}")
            text = output.read_text()
            if "!pyobf.local." in text: raise AssertionError("private local inventory/construction data leaked")
            if not mixed:
                body = re.search(r"define i32 @local_values\(.*?\n\}", text, re.S).group()
                layouts.append(re.findall(r"store volatile ptr ([^,]+), ptr %pyobf\.local\.init\d*", body))
            if "llvm.lifetime.start.p0(ptr %value)" not in text or "llvm.lifetime.end.p0(ptr %value)" not in text:
                raise AssertionError("local lifetime markers lost the original allocation identity")
            run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
            if run([str(binary)]).stdout != expected: raise AssertionError("indexed locals changed typed/alias/escape/lifetime/recursive/thread behavior")
            run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(image)])
            final_report = directory / "final.json"
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report), "--output", str(final_report)])
            for row in json.loads(final_report.read_text())["functions"]:
                for item in row.get("components", []):
                    if item["component"] == "indexed-locals" and item["applied"]:
                        if not item["final_presence_verified"] or item["individual_sites_verified"]:
                            raise AssertionError("local final-presence evidence missing or overstated")
        if not layouts[0] or layouts[0] != layouts[2] or layouts[0] == layouts[1]:
            raise AssertionError("local object slot layout is nondeterministic or ignores the seed")

        changed, count = re.subn(r"(%pyobf\.local\.state\d*) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
            lambda m: f"{m[1]}.wrong = {m[2]}\n  {m[1]} = xor i32 {m[1]}.wrong, 255", text)
        if not count: raise AssertionError("no live local state read to perturb")
        altered = directory / "altered.ll"; altered.write_text(changed, encoding="utf-8")
        run([str(args.compiler), str(altered), str(harness), str(helper), "-o", str(binary)])
        invalid_execution(binary, expected)
        coefficient = str(0x9E6C63D1 - (1 << 32))
        if coefficient not in text: raise AssertionError("missing local mask coefficient")
        altered.write_text(text.replace(coefficient, str(int(coefficient) + 2)), encoding="utf-8")
        run([str(args.compiler), "-shared", str(altered), str(helper), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost indexed local address routes" not in result.stderr: raise AssertionError("erased local feature failed for an unrelated reason")

        requests, requested, optimized = (directory / name for name in ("requests.json", "requested.ll", "optimized.ll"))
        for name, survives in (("local_volatile", True), ("folded_local", False)):
            selection = {name: {"components": {"indexed-locals": "required"}}}
            config.write_text(json.dumps({"schema_version": 1, "functions": selection}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}", "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            result = transform(selection, input_ir=optimized, succeeds=survives, extra=(f"-pyobf-cff-requests-input={requests}",))
            if survives:
                run([str(args.compiler), str(output), str(harness), str(helper), "-o", str(binary)])
                if run([str(binary)]).stdout != expected: raise AssertionError("O2/local variable execution changed")
            elif "did not survive ordinary optimization" not in report.read_text(): raise AssertionError("lost original local request credited")

        cpp = Path(__file__).with_name("frame_cpp_fixture.cpp"); cpp_harness = Path(__file__).with_name("frame_cpp_harness.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(cpp), "-o", str(source)])
        run([str(args.compiler), str(source), str(cpp_harness), "-o", str(baseline)])
        cpp_expected = run([str(baseline)]).stdout
        transform({"frame_cpp_values": {"components": {"indexed-locals": "required", "reference-routes": "required",
            "call-frames": "required", "call-preparation": "required"}}})
        run([str(args.compiler), str(output), str(cpp_harness), "-o", str(binary)])
        if run([str(binary)]).stdout != cpp_expected: raise AssertionError("frontend C++ layout/lifetime/ABI changed")


if __name__ == "__main__":
    main()
