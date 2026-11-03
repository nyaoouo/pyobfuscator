"""Measure reference-table costs against the same-source plain, CFG and legacy paths."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path

from check_cff_transition_depth import run
from measure_cff import digest, text_size


SOURCE_IR = r'''
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
define internal i32 @scale(i32 %x) noinline {
entry:
  %a = mul i32 %x, 3
  %b = add i32 %a, 7
  ret i32 %b
}
define internal i32 @adjust(i32 %x) noinline {
entry:
  %r = sub i32 %x, 5
  ret i32 %r
}
define i32 @reference_compute(i32 %x) noinline {
entry:
  %a = call i32 @scale(i32 %x)
  %b = call i32 @adjust(i32 %a)
  %negative = icmp slt i32 %x, 0
  br i1 %negative, label %minus, label %plus
minus:
  %m = sub i32 %b, 11
  ret i32 %m
plus:
  %p = add i32 %b, 13
  ret i32 %p
}
'''


def main(*, recipes: dict[str, dict[str, str]] | None = None,
         source_ir: str = SOURCE_IR,
         provider_ir: str | None = None,
         comparison: str = "same-source/seed plain, CFG-only, legacy slots and state-bound reference tables") -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "harness", "build_dir", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    if recipes is None:
        recipes = {"plain": {}, "cfg": {}, "internal-calls": {"internal-calls": "required"},
                   "reference-routes": {"reference-routes": "required"}}
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    profiles = {}
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        source.write_text(source_ir, encoding="utf-8")
        harness = directory / "measure.exe"
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        link_inputs, provider_record = [], None
        if provider_ir is not None:
            provider = directory / "provider.ll"
            provider.write_text(provider_ir, encoding="utf-8")
            library, imports = directory / "provider.dll", directory / "provider.a"
            start = time.perf_counter()
            run([str(args.compiler), "-O0", "-fno-lto", "-shared", str(provider), "-o", str(library),
                 f"-Wl,--out-implib,{imports}"])
            provider_seconds = time.perf_counter() - start
            provider_record = {"input_ir_sha256": digest(provider), "image_sha256": digest(library),
                "text_bytes": text_size(args.objdump, library), "codegen_link_seconds": provider_seconds,
                "scope": "one unchanged separately linked provider DLL shared by every paired variant"}
            link_inputs.append(str(imports))
        for optimization in ("none", "O2"):
            optimized = directory / f"{optimization}.ll"
            start = time.perf_counter()
            run([str(args.opt), f"-passes={'verify' if optimization == 'none' else 'default<O2>'}",
                 "-S", str(source), "-o", str(optimized)])
            optimize_seconds = time.perf_counter() - start
            images, rows = {}, {}
            for label, components in recipes.items():
                transformed, coverage = directory / f"{label}.ll", directory / f"{label}.coverage.json"
                transform_seconds = 0.0
                row = None
                if label == "plain":
                    transformed.write_bytes(optimized.read_bytes())
                else:
                    config = directory / f"{label}.json"
                    config.write_text(json.dumps({"schema_version": 1, "functions": {"reference_compute": {
                        "components": components}}}), encoding="utf-8")
                    start = time.perf_counter()
                    run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                         f"-pyobf-cff-config={config}", f"-pyobf-cff-report={coverage}",
                         "-verify-each", "-S", str(optimized), "-o", str(transformed)])
                    transform_seconds = time.perf_counter() - start
                    row = next(item for item in json.loads(coverage.read_text())["functions"]
                               if item["function"] == "reference_compute")
                image = directory / f"{optimization}-{label}.dll"
                start = time.perf_counter()
                run([str(args.compiler), "-O0", "-fno-lto", "-shared", str(transformed), *link_inputs, "-o", str(image)])
                link_seconds = time.perf_counter() - start
                if label != "plain":
                    run([os.sys.executable, str(Path(__file__).with_name("check_linked_cff.py")),
                         str(args.objdump), str(image), str(coverage)])
                images[label] = image
                rows[label] = {"sha256": digest(image), "text_bytes": text_size(args.objdump, image),
                    "file_bytes": image.stat().st_size, "transform_seconds": transform_seconds,
                    "codegen_link_seconds": link_seconds, "components": row["components"] if row else []}
            cases = {}
            for label in recipes:
                if label == "plain": continue
                measured = run([str(harness), str(images["plain"].resolve()),
                                str(images[label].resolve()), "reference_compute", "36"]).stdout
                timings = {key: float(value) for key, value in
                           (line.split("=", 1) for line in measured.splitlines())}
                cases[label] = {"timings": timings, "hot_ratio":
                                timings["protected_hot_ns"] / timings["baseline_hot_ns"]}
            profiles[optimization] = {"ordinary_optimize_seconds": optimize_seconds,
                                      "images": rows, "cases": cases}
        result = {"comparison": comparison,
            "input_ir_sha256": digest(source), "plugin_sha256": digest(args.plugin),
            "harness_sha256": digest(args.harness),
            "compiler": run([str(args.compiler), "--version"]).stdout,
            "scope": "Windows x64 CLANG64 microbenchmark; warm paired medians, no strength or performance bound",
            "build_cost_scope": "ordinary opt, CFF transform and O0/no-LTO codegen/link; excludes frontend/plugin/outer packaging",
            "startup_scope": "module load, symbol lookup, one checked call and unload; not isolated function initialization",
            "profiles": profiles}
        if provider_record is not None: result["provider"] = provider_record
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({name: {"text_bytes": {label: row["text_bytes"] for label, row in profile["images"].items()},
            "build_seconds": {label: round(row["transform_seconds"] + row["codegen_link_seconds"], 4)
                              for label, row in profile["images"].items()}, "cases": profile["cases"]}
                          for name, profile in profiles.items()}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
