"""Validate typed literals/equality in the full pass, including provenance and final code."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run, invalid_execution
from scalar_cases import WIDTHS, literal, source_ir, harness_source


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output = directory / "source.ll", directory / "output.ll"
        report, config_file = directory / "coverage.json", directory / "recipe.json"
        private = directory / "private.json"
        harness = directory / "harness.cpp"
        source.write_text(source_ir(), encoding="utf-8")
        harness.write_text(harness_source(), encoding="utf-8")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout

        def transform(config: dict, seed: int = 1, *, succeeds: bool = True):
            config_file.write_text(json.dumps({"schema_version": 1, "functions": config}), encoding="utf-8")
            output.unlink(missing_ok=True)
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={report}",
                 f"-pyobf-cff-private-map={private}",
                 f"-pyobf-cff-seed={seed}", "-verify-each", "-S", str(source), "-o", str(output)],
                succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("rejected typed recipe emitted output")
            return {row["function"]: row for row in json.loads(report.read_text())["functions"]}

        for seed in (1, 17):
            for combined in (False, True):
                config = {f"literal_{width}": {"components": {"integer-literals": "required"}} for width in WIDTHS}
                config["literal_loop"] = {"components": {"integer-literals": "required"}}
                names = [f"{prefix}_{width}" for width in WIDTHS if width >= 2 for prefix in ("eq", "ne")]
                for name in (*names, "same_sign"):
                    config[name] = {"components": {"comparison-constants": "required"}}
                    if combined: config[name]["components"]["integer-literals"] = "required"
                config["mixed"] = {"components": {"comparison-constants": "optional"}}
                if combined:
                    config["eq_64"]["components"].update({name: "optional" for name in (
                        "common-exit", "split-blocks", "bogus-clones", "bogus-synthesis", "opaque-choices", "reachable-junk")})
                rows = transform(config, seed)
                maps = {row["function"]: row for row in json.loads(private.read_text())["functions"]}
                for width in WIDTHS:
                    component = next(item for item in rows[f"literal_{width}"]["components"] if item["component"] == "integer-literals")
                    if component["applied_types"].get(f"i{width}", 0) == 0:
                        raise AssertionError("scalar width was silently truncated or unprotected")
                for name in names:
                    components = {item["component"]: item for item in rows[name]["components"]}
                    comparison = components["comparison-constants"]
                    if comparison["applied"] != 1 or sum(comparison["applied_types"].values()) != 1:
                        raise AssertionError(f"comparison coverage differs: {comparison}")
                    identity = next(site["id"] for site in comparison["sites"] if site["status"] == "applied")
                    mapped = next(site for site in maps[name]["sites"] if site["id"] == identity)
                    if mapped["operand_index"] != int(name.startswith("eq_")) or len(mapped["transformed_ir"]) != 1:
                        raise AssertionError("semantic identity lost the physical operand or duplicated its map")
                    if combined and name.startswith("ne_") and not components["integer-literals"]["relocated"]:
                        raise AssertionError("left literal obligation did not move to the encoded right operand")
                mixed = next(item for item in rows["mixed"]["components"] if item["component"] == "comparison-constants")
                if mixed["applied"] != 1 or mixed["unsupported"] != 1:
                    raise AssertionError("optional pointer comparison was silently credited or blocked all work")
                ir = output.read_text()
                body = re.search(r"define i32 @same_sign\(.*?\n\}", ir, re.S)
                if body is None or "icmp samesign" in body.group():
                    raise AssertionError("bijection retained an invalid same-sign assumption")
                binary = directory / "protected.exe"
                run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
                if run([str(binary)]).stdout != expected:
                    raise AssertionError("typed wrapping/order/shift/store/PHI/equality semantics differ")
                image = directory / "protected.dll"
                run([str(args.compiler), "-shared", str(output), "-o", str(image)])
                run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])
                if literal(64).to_bytes(8, "little") in image.read_bytes():
                    raise AssertionError("selected wide literal remains in final static image bytes")

        body = re.search(r"define i32 @eq_64\(.*?\n\}", ir, re.S)
        def perturb(match: re.Match[str]) -> str:
            temporary = match[1].replace("pyobf.compare.state", "pyobf.test.state")
            return f"{temporary} = {match[2]}\n  {match[1]} = xor i32 {temporary}, 1"
        changed, count = re.subn(r"(%pyobf\.compare\.state(?:\.?\d+)?) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
                                 perturb, body.group())
        if count != 1: raise AssertionError("comparison key has no unique live state read")
        altered = directory / "altered.ll"
        altered.write_text(ir[:body.start()] + changed + ir[body.end():], encoding="utf-8")
        binary = directory / "altered.exe"
        run([str(args.compiler), str(altered), str(harness), "-o", str(binary)])
        invalid_execution(binary, expected)

        # Erase only the comparison-specific key domain, retaining scalar and CFG features.
        erased = directory / "erased.ll"
        decimal = str(0xd168aaad - (1 << 32))
        if decimal not in ir: raise AssertionError("comparison domain multiplier is absent")
        erased.write_text(ir.replace(decimal, str(0xd168aaaf - (1 << 32))), encoding="utf-8")
        image = directory / "erased.dll"
        run([str(args.compiler), "-shared", str(erased), "-o", str(image)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)], succeeds=False)
        if "lost state-dependent comparison keys" not in result.stderr:
            raise AssertionError(f"comparison erasure failed for unrelated reason: {result.stderr}")

        for name, component, reason in (("only_order", "comparison-constants", "zero eligible"),
                ("boolean_eq", "comparison-constants", "i2 through i128"),
                ("pointer_eq", "comparison-constants", "i2 through i128"),
                ("vector_eq", "comparison-constants", "i2 through i128"),
                ("oversized_eq", "comparison-constants", "i2 through i128"),
                ("oversized_literal", "integer-literals", "i1 through i128"),
                ("mixed", "comparison-constants", "i2 through i128")):
            rejected = transform({name: {"components": {component: "required"}}}, succeeds=False)[name]
            if rejected["status"] != "unsupported" or reason not in rejected["reason"]:
                raise AssertionError(f"unsupported typed site was hidden: {rejected}")

        # A new component must honor the existing pre-optimization request contract too.
        requests = directory / "requests.json"
        requested, optimized = directory / "requested.ll", directory / "optimized.ll"
        for name, succeeds in (("ne_64", True), ("comparison_folded", False)):
            config_file.write_text(json.dumps({"schema_version": 1, "functions": {
                name: {"components": {"comparison-constants": "required"}}}}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-requests-output={requests}",
                 "-S", str(source), "-o", str(requested)])
            run([str(args.opt), "-passes=default<O2>", "-S", str(requested), "-o", str(optimized)])
            output.unlink(missing_ok=True)
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-requests-input={requests}",
                 f"-pyobf-cff-report={report}", "-verify-each", "-S", str(optimized), "-o", str(output)],
                succeeds=succeeds)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            component = next(item for item in row["components"] if item["component"] == "comparison-constants")
            if succeeds:
                if row["status"] != "transformed" or component["applied"] != 1:
                    raise AssertionError("retained requested comparison was lost")
                binary = directory / "requested.exe"
                run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
                if run([str(binary)]).stdout != expected:
                    raise AssertionError("ordinary optimization plus comparison binding changed behavior")
            elif (output.exists() or component["optimized_away"] != 1 or
                  "did not survive ordinary optimization" not in row["reason"]):
                raise AssertionError("optimized-away required comparison was silently credited")


if __name__ == "__main__":
    main()
