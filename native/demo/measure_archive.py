"""Measure plain/CFF/archive images, typed first use and warm access without speed gates."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import tempfile
import time

from archive_measure_build import build_variant, command
from archive_measure_input import DATA, source_ir
from measure_cff import digest, text_size


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "harness", "build_dir", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        probe, probe_ir = directory / "target.cpp", directory / "target.ll"
        probe.write_text("// Matching frontend target probe.\n", encoding="utf-8")
        command([str(args.compiler), "-std=c++17", "-S", "-emit-llvm", str(probe), "-o", str(probe_ir)])
        source = directory / "source.ll"
        source.write_text(source_ir(probe_ir.read_text()), encoding="utf-8")
        harness = directory / "measure.exe"
        command([str(args.compiler), "-std=c++17", "-O2", str(args.harness), "-o", str(harness)])
        profiles = {}
        for optimization in ("none", "O2"):
            variants, images = {}, {}
            for name in ("plain", "cff", "archive"):
                started = time.perf_counter()
                built = build_variant(args, root, source, directory / f"{optimization}.{name}", name, optimization)
                elapsed = time.perf_counter() - started
                image = built.image
                if name == "archive" and DATA in image.read_bytes():
                    raise AssertionError("selected source bytes survived in the archived measurement image")
                selected = [row for row in (built.report or {}).get("functions", []) if row["selected"]]
                images[name] = image
                variants[name] = {"sha256": digest(image), "file_bytes": image.stat().st_size,
                    "text_bytes": text_size(args.objdump, image), "build_seconds": elapsed,
                    "phase_seconds": built.phases, "selected_functions": len(selected),
                    "records": len(built.plan["records"]) if built.plan else 0,
                    "acquisitions": sum(row.get("archive_sources", {}).get("acquisitions", 0) for row in selected),
                    "complete_acquisitions": sum(row.get("archive_sources", {}).get("complete_acquisitions", 0) for row in selected)}
                if name == "archive" and (not variants[name]["records"] or
                        variants[name]["acquisitions"] != variants[name]["complete_acquisitions"] or
                        not variants[name]["acquisitions"]):
                    raise AssertionError("archive cost was measured without complete acquisition coverage")
            pairs = {}
            for baseline, protected in (("plain", "cff"), ("cff", "archive")):
                output = command([str(harness), str(images[baseline]), str(images[protected])])
                timings = {key: float(value) for key, value in (line.split("=", 1) for line in output.splitlines())}
                expected = {f"{name}_{field}" for name in ("baseline", "protected")
                            for field in ("startup_us", "first_call_us", "hot_ns")}
                expected |= {"cold_samples", "hot_samples", "hot_iterations"}
                if set(timings) != expected or any(not math.isfinite(value) or value < 0 or
                        (value == 0 and not key.endswith("_first_call_us")) for key, value in timings.items()):
                    raise AssertionError(f"archive benchmark emitted incomplete or invalid timing evidence:\n{output}")
                pairs[f"{baseline}_to_{protected}"] = {"timings": timings,
                    "first_call_below_resolution": {name: timings[f"{name}_first_call_us"] == 0
                        for name in ("baseline", "protected")},
                    "hot_ratio": timings["protected_hot_ns"] / timings["baseline_hot_ns"]}
            profiles[optimization] = {"images": variants, "pairs": pairs}
        report = {"comparison": "same typed source IR/public seed, plain versus CFF/scalars versus added archive",
            "input_ir_sha256": digest(source), "plugin_sha256": digest(args.plugin),
            "compiler": command([str(args.compiler), "--version"]).splitlines()[0],
            "limits": ["Windows user-mode CLANG64 fixture; warm OS/dependency caches",
                "startup includes load, first use and unload; first_call excludes loader; full typed validation is outside timing",
                "build_seconds covers IR requests/optimization/transform/helpers/link/final gate, not user-source frontend or LLVM plugin build",
                "no archive helper compilation is cached between variants; each record is authenticated on warm use",
                "ordinary O2 may fold typed globals into scalar literals; actual record/acquisition counts are reported",
                "a zero first_call median means below the observed clock resolution, not a zero-cost claim",
                "machine/workload timing observations are not protection-strength or general performance bounds"],
            "profiles": profiles}
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(args.output), "profiles": profiles}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
