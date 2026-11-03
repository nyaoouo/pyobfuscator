"""Isolate the added size, startup and hot-call cost of instruction-budget splitting."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from check_cff_split import SOURCE_IR, run
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
        images = {}
        reports = {}
        for label in ("baseline", "split"):
            config = {"schema_version": 1, "functions": {"heavy": {}}}
            if label == "split":
                config["functions"]["heavy"] = {
                    "components": {"split-blocks": "required"},
                    "budgets": {"max_block_instructions": 4, "max_body_blocks": 100}}
            config_file = directory / f"{label}.json"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            transformed = directory / f"{label}.ll"
            coverage = directory / f"{label}.coverage.json"
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={coverage}",
                 "-pyobf-cff-markers=false", "-verify-each", "-S", str(source), "-o", str(transformed)])
            image = directory / f"{label}.dll"
            run([str(args.compiler), "-shared", str(transformed), "-o", str(image)])
            images[label] = image
            reports[label] = next(row for row in json.loads(coverage.read_text())["functions"]
                                  if row["function"] == "heavy")
        harness = directory / "measure.exe"
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        expected = (10 * 7) ^ 10
        for index in range(1, 20):
            operand = index * 23 + 5
            expected = (expected + operand if index % 2 else expected ^ operand) & 0xffffffff
        if expected >= 0x80000000:
            expected -= 0x100000000
        measured = run([str(harness), str(images["baseline"].resolve()),
                        str(images["split"].resolve()), "heavy", str(expected)]).stdout
        timings = {key: float(value) for key, value in
                   (line.split("=", 1) for line in measured.splitlines())}
        result = {
            "comparison": "cfg-only versus cfg plus splitting; same source IR and public seed",
            "instruction_budget": 4,
            "input_ir_sha256": digest(source),
            "images": {
                label: {"sha256": digest(image), "file_bytes": image.stat().st_size,
                        "text_bytes": text_size(args.objdump, image),
                        "site_totals": reports[label]["site_totals"]}
                for label, image in images.items()},
            "timings": timings,
            "ratios": {
                "text": text_size(args.objdump, images["split"]) /
                        text_size(args.objdump, images["baseline"]),
                "startup": timings["protected_startup_us"] / timings["baseline_startup_us"],
                "hot_call": timings["protected_hot_ns"] / timings["baseline_hot_ns"],
            },
        }
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(args.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
