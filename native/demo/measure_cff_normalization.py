"""Pair normalization recipes against the same IR with the same literal protection."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from check_cff_normalization import SOURCE_IR, run
from measure_cff import digest, text_size


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "harness", "build_dir", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness = directory / "measure.exe"
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        cases = (
            ("dedup", "duplicate_math", 14, {"deduplicate-blocks": "required"}),
            ("common_exit", "mixed_returns", 99, {"common-exit": "required"}),
            ("combined", "combined_case", 43,
             {"common-exit": "required", "deduplicate-blocks": "required", "split-blocks": "required"}),
        )
        results = {}
        for case, function, expected, features in cases:
            images = {}
            reports = {}
            for label in ("baseline", "normalized"):
                components = {"integer-literals": "required"}
                if case == "common_exit": components["internal-calls"] = "required"
                if label == "normalized": components.update(features)
                settings = {"components": components, "budgets": {"max_block_instructions": 2}}
                config = {"schema_version": 1, "functions": {function: settings}}
                config_file = directory / f"{case}.{label}.json"
                config_file.write_text(json.dumps(config), encoding="utf-8")
                transformed = directory / f"{case}.{label}.ll"
                coverage = directory / f"{case}.{label}.coverage.json"
                run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                     f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={coverage}",
                     "-pyobf-cff-markers=false", "-verify-each", "-S", str(source), "-o", str(transformed)])
                image = directory / f"{case}.{label}.dll"
                run([str(args.compiler), "-shared", str(transformed), "-o", str(image)])
                images[label] = image
                reports[label] = next(row for row in json.loads(coverage.read_text())["functions"]
                                      if row["function"] == function)
            measured = run([str(harness), str(images["baseline"].resolve()),
                            str(images["normalized"].resolve()), function, str(expected)]).stdout
            timings = {key: float(value) for key, value in
                       (line.split("=", 1) for line in measured.splitlines())}
            expected_fields = {"baseline_startup_us", "protected_startup_us", "baseline_hot_ns",
                               "protected_hot_ns", "startup_samples", "hot_samples", "hot_iterations"}
            if set(timings) != expected_fields or min(timings.values()) <= 0:
                raise AssertionError(f"incomplete measurement output: {measured}")
            results[case] = {
                "function": function,
                "images": {
                    label: {"sha256": digest(image), "file_bytes": image.stat().st_size,
                            "text_bytes": text_size(args.objdump, image),
                            "site_totals": reports[label]["site_totals"],
                            "components": {row["component"]: {field: row[field] for field in
                                ("applied", "coalesced", "relocated")} for row in reports[label]["components"]}}
                    for label, image in images.items()},
                "timings": timings,
                "ratios": {
                    "text": text_size(args.objdump, images["normalized"]) /
                            text_size(args.objdump, images["baseline"]),
                    "startup": timings["protected_startup_us"] / timings["baseline_startup_us"],
                    "hot_call": timings["protected_hot_ns"] / timings["baseline_hot_ns"],
                },
            }
        result = {"comparison": "same input IR, seed and data/call protection; normalized recipe differs",
                  "input_ir_sha256": digest(source), "cases": results}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({case: {"ratios": record["ratios"], "timings": record["timings"]}
                          for case, record in results.items()}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
