"""Pair each misleading-CFG component with a same-source CFG-only baseline."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
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
        features = ("opaque-choices", "reachable-junk", "decoy-transitions", "bogus-clones", "bogus-synthesis")
        images, rows, build_times = {}, {}, {}
        for label in ("baseline", *features, "combined"):
            selected = features if label == "combined" else () if label == "baseline" else (label,)
            config = {"schema_version": 1, "functions": {"heavy": {
                "components": {name: "required" for name in selected}, "budgets": {
                    "max_bogus_blocks": 4, "max_opaque_sites": 2, "max_junk_sites": 2,
                    "max_clone_instructions": 3, "junk_rounds": 3, "synthesis_rounds": 3}}}}
            config_file = directory / f"{label}.json"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            transformed, coverage = directory / f"{label}.ll", directory / f"{label}.coverage.json"
            started = time.perf_counter()
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={coverage}",
                 "-verify-each", "-S", str(source), "-o", str(transformed)])
            image = directory / f"{label}.dll"
            run([str(args.compiler), "-shared", str(transformed), "-o", str(image)])
            build_times[label] = time.perf_counter() - started
            images[label] = image
            rows[label] = next(row for row in json.loads(coverage.read_text())["functions"]
                               if row["function"] == "heavy")
        harness = directory / "measure.exe"
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        expected = (10 * 7) ^ 10
        for index in range(1, 20):
            operand = index * 23 + 5
            expected = (expected + operand if index % 2 else expected ^ operand) & 0xffffffff
        if expected >= 0x80000000: expected -= 0x100000000
        cases = {}
        for label in (*features, "combined"):
            measured = run([str(harness), str(images["baseline"].resolve()),
                            str(images[label].resolve()), "heavy", str(expected)]).stdout
            timings = {key: float(value) for key, value in
                       (line.split("=", 1) for line in measured.splitlines())}
            cases[label] = {"timings": timings, "hot_ratio":
                            timings["protected_hot_ns"] / timings["baseline_hot_ns"]}
        result = {"comparison": "same IR/public seed, CFG-only versus one/all misleading components",
                  "input_ir_sha256": digest(source), "cases": cases, "images": {
                      label: {"sha256": digest(image), "text_bytes": text_size(args.objdump, image),
                              "file_bytes": image.stat().st_size, "transform_link_seconds": build_times[label],
                              "site_totals": rows[label]["site_totals"]}
                      for label, image in images.items()}}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(args.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
