"""Pair scalar/equality feature costs with the same-source CFG-only path."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from check_cff_split import run
from measure_cff import digest, text_size


SOURCE_IR = '''
define i32 @typed_compute(i32 %x) {
entry:
  %wide = zext i32 %x to i64
  %value = add i64 %wide, 1311768467463733248
  %match = icmp eq i64 %value, 1311768467463733255
  br i1 %match, label %yes, label %no
yes:
  ret i32 17
no:
  %result = trunc i64 %value to i32
  ret i32 %result
}
'''


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
        features = ("integer-literals", "comparison-constants")
        images, rows = {}, {}
        for label in ("baseline", *features, "combined"):
            selected = features if label == "combined" else () if label == "baseline" else (label,)
            config_file = directory / f"{label}.json"
            config_file.write_text(json.dumps({"schema_version": 1, "functions": {"typed_compute": {
                "components": {name: "required" for name in selected}}}}), encoding="utf-8")
            transformed, coverage = directory / f"{label}.ll", directory / f"{label}.coverage.json"
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                 f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={coverage}",
                 "-verify-each", "-S", str(source), "-o", str(transformed)])
            image = directory / f"{label}.dll"
            run([str(args.compiler), "-shared", str(transformed), "-o", str(image)])
            images[label] = image
            rows[label] = next(row for row in json.loads(coverage.read_text())["functions"] if row["function"] == "typed_compute")
        harness = directory / "measure.exe"
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        cases = {}
        for label in (*features, "combined"):
            measured = run([str(harness), str(images["baseline"].resolve()),
                            str(images[label].resolve()), "typed_compute", "17"]).stdout
            timings = {key: float(value) for key, value in
                       (line.split("=", 1) for line in measured.splitlines())}
            cases[label] = {"timings": timings, "hot_ratio":
                            timings["protected_hot_ns"] / timings["baseline_hot_ns"]}
        result = {"comparison": "same IR/public seed, CFG-only versus scalar/equality/both",
                  "input_ir_sha256": digest(source), "cases": cases, "images": {
                      label: {"sha256": digest(image), "text_bytes": text_size(args.objdump, image),
                              "file_bytes": image.stat().st_size, "components": rows[label]["components"]}
                      for label, image in images.items()}}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"comparison": result["comparison"], "cases": cases,
                          "text_bytes": {label: item["text_bytes"] for label, item in result["images"].items()}},
                         indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
