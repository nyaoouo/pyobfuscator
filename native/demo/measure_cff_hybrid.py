"""Measure paired real EH paths separately from build/test activity."""

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from measure_cff import digest, run, text_size


RECIPES = {"plain": {}, "cfg": {}, "frames": {"call-frames": "required"},
    "composed": {name: "required" for name in ("call-frames", "external-calls", "call-preparation",
                                                "reference-routes", "import-routes")}}
SCALARS = ("integer-literals", "comparison-constants")
RECIPES.update({"integers": {SCALARS[0]: "required"}, "comparisons": {SCALARS[1]: "required"},
    "scalars": {name: "required" for name in SCALARS},
    "scalar_composed": {**RECIPES["composed"], **{name: "required" for name in SCALARS}}})
BASELINES = {label: "composed" if label == "scalar_composed" else
    "cfg" if label in ("integers", "comparisons", "scalars") else "plain" for label in RECIPES if label != "plain"}


def timed(command: list[str]) -> float:
    start = time.perf_counter()
    run(command)
    return time.perf_counter() - start


def measurement(harness: Path, baseline: Path, image: Path, mode: int) -> dict:
    record = json.loads(run([str(harness), str(baseline.resolve()), str(image.resolve()), str(mode)]))
    if (record["startup_samples"] != 20 or record["hot_samples"] != 7 or
            record["hot_iterations"] != (500000 if mode == 0 else 2000) or record["warmup_calls_per_image"] != 64):
        raise AssertionError("incomplete hybrid measurement workload")
    summary = {}
    for name, count in (("baseline_startup_us", 20), ("protected_startup_us", 20),
                        ("baseline_hot_ns", 7), ("protected_hot_ns", 7)):
        values = record[name]
        if len(values) != count or any(not math.isfinite(value) or value <= 0 for value in values):
            raise AssertionError(f"invalid hybrid timing samples: {name}")
        summary[name] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
    record["summary"] = summary
    record["hot_ratio"] = summary["protected_hot_ns"]["median"] / summary["baseline_hot_ns"]["median"]
    return record


def reject_changed_behavior(compiler: Path, harness: Path, baseline: Path, fixture: Path, directory: Path) -> list[dict]:
    original, records = fixture.read_text(), []
    for name, before, after, mode, reason in (
        ("normal_result", "return value + 9;", "return value + 10;", 0, "changed result, rethrow or guard effects"),
        ("cleanup_effect", "++*effects;", "*effects += 2;", 1, "changed result, rethrow or guard effects"),
        ("thrown_value", "throw input + 23;", "throw input + 24;", 2, "changed thrown value"),
        ("swallowed_rethrow", "if (mode == 2) throw;", "if (mode == 2) return error;", 2, "changed result, rethrow or guard effects")):
        if original.count(before) != 1: raise AssertionError(f"ambiguous measurement mutation: {name}")
        source, image = directory / f"bad-{name}.cpp", directory / f"bad-{name}.dll"
        source.write_text(original.replace(before, after), encoding="utf-8")
        run([str(compiler), "-std=c++17", "-O1", "-shared", str(source), "-o", str(image)])
        result = subprocess.run([str(harness), str(baseline.resolve()), str(image.resolve()), str(mode)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode != 2 or reason not in result.stderr:
            raise AssertionError(f"hybrid measurement accepted mutation or failed outside its behavior gate: {name}")
        records.append({"case": name, "mode": mode, "fixture_sha256": digest(source), "image_sha256": digest(image)})
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "build_dir", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--locals", action="store_true", help="pair indexed locals with matching CFG/frame baselines")
    args = parser.parse_args()
    recipes, baselines = RECIPES, BASELINES
    if args.locals:
        recipes = {name: RECIPES[name] for name in ("plain", "cfg", "composed")}
        recipes.update({"locals": {"indexed-locals": "required"},
            "locals_composed": {**RECIPES["composed"], "indexed-locals": "required"}})
        baselines = {"cfg": "plain", "composed": "plain", "locals": "cfg", "locals_composed": "composed"}
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    fixture, harness_source = (Path(__file__).with_name(name) for name in
        ("measure_cff_hybrid_fixture.cpp", "measure_cff_hybrid.cpp"))
    with tempfile.TemporaryDirectory(prefix="hybrid measure ", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, harness = directory / "source.ll", directory / "measure.exe"
        frontend = timed([str(args.compiler), "-std=c++17", "-O1", "-fno-inline",
                          "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        timed([str(args.compiler), "-std=c++17", "-O2", str(harness_source), "-o", str(harness)])
        profiles = {}
        for optimization in ("none", "O2"):
            images, records = {}, {}
            for label, components in recipes.items():
                components = {name: "optional" if optimization == "O2" and name in SCALARS else requirement
                    for name, requirement in components.items()}
                stem = directory / f"{optimization}-{label}"
                config, requests, stamped, optimized, protected, report, image, final = (
                    stem.with_suffix(suffix) for suffix in (".json", ".requests.json", ".stamped.ll",
                        ".optimized.ll", ".protected.ll", ".coverage.json", ".dll", ".final.json"))
                configuration = {"schema_version": 1, "functions": {"hybrid_measure": {
                    "coverage": "hybrid-eh", "components": components}}}
                config.write_text(json.dumps(configuration), encoding="utf-8")
                selection = [f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}",
                             f"-pyobf-cff-seed={args.seed}", "-verify-each", "-S"]
                collect_seconds = timed([str(args.opt), *selection, "-passes=pyobf-native-cff-requests",
                    f"-pyobf-cff-requests-output={requests}", str(source), "-o", str(stamped)])
                optimize_seconds = timed([str(args.opt), "-passes=" + ("verify" if optimization == "none" else "default<O2>"),
                                          "-verify-each", "-S", str(stamped), "-o", str(optimized)])
                transform_seconds, rows = 0.0, []
                emitted = optimized
                if label != "plain":
                    transform_seconds = timed([str(args.opt), *selection, "-passes=pyobf-native-cff",
                        f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={report}",
                        str(optimized), "-o", str(protected)])
                    rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
                    owner = next(row for row in rows if row["function"] == "hybrid_measure")
                    if any(row["status"] != "transformed" for row in rows) or not owner["hybrid_eh"]["ir_flow_graph_verified"]:
                        raise AssertionError("measurement lost required hybrid coverage")
                    for name in components:
                        item = next(item for item in owner["components"] if item["component"] == name)
                        if not item["applied"] or item["unsupported"] or (components[name] == "required" and item["optimized_away"]):
                            raise AssertionError(f"measurement lost required {name}")
                    emitted = protected
                link_seconds = timed([str(args.compiler), "-O0", "-fno-lto", "-shared", str(emitted), "-o", str(image)])
                if label != "plain":
                    run([sys.executable, str(Path(__file__).with_name("check_linked_cff.py")),
                         str(args.objdump), str(image), str(report), "--output", str(final)])
                images[label] = image
                records[label] = {"configuration": configuration, "configuration_sha256": digest(config),
                    "requests_sha256": digest(requests), "stamped_ir_sha256": digest(stamped),
                    "optimized_ir_sha256": digest(optimized), "emitted_ir_sha256": digest(emitted),
                    "image_sha256": digest(image), "text_bytes": text_size(args.objdump, image),
                    "file_bytes": image.stat().st_size, "request_seconds": collect_seconds,
                    "ordinary_optimize_seconds": optimize_seconds, "transform_seconds": transform_seconds,
                    "codegen_link_seconds": link_seconds, "selected_coverage": rows}
                if label != "plain":
                    records[label].update(coverage_sha256=digest(report), final_report_sha256=digest(final))
            cases = {label: {name: measurement(harness, images[baselines[label]], images[label], mode)
                for mode, name in enumerate(("normal", "local_catch", "external_rethrow"))}
                for label in recipes if label != "plain"}
            profiles[optimization] = {"images": records, "paired_cases": cases, "paired_baselines": baselines}
        negatives = reject_changed_behavior(args.compiler, harness, images["plain"], fixture, directory)
        result = {"created_at": datetime.now(timezone.utc).isoformat(), "seed": args.seed,
            "fixture_sha256": digest(fixture), "input_ir_sha256": digest(source),
            "harness_source_sha256": digest(harness_source), "harness_image_sha256": digest(harness),
            "plugin_sha256": digest(args.plugin), "frontend_seconds": frontend,
            "frontend_flags": ["-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm"],
            "compiler": run([str(args.compiler), "--version"]), "opt": run([str(args.opt), "--version"]),
            "host": platform.platform(), "python": sys.version,
            "comparison": ("same O1/no-inline C++ frontend/seed, then none or additional source O2; indexed-local additions versus matching CFG/composed"
                if args.locals else "same O1/no-inline C++ frontend/seed, then none or additional source O2; old CFG/frame/composed versus plain; scalar additions versus matching CFG/composed"),
            "build_scope": "single observations of frontend, request retention, ordinary opt, transform and O0/no-LTO codegen/link; excludes plugin/harness build and outer packaging",
            "startup_scope": "warm repeated DLL load, symbol lookup, one result/effect/exception-checked call and unload; not cold process startup",
            "hot_scope": "loaded modules, 64 checked warmups, alternating paired order, seven samples; includes harness catch/result/effect checks",
            "limits": "Windows x64 CLANG64 microbenchmark; raw samples include scheduling/loader noise; no general performance or strength bound",
            "harness_rejections": negatives, "profiles": profiles}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({name: {"text_bytes": {label: row["text_bytes"] for label, row in profile["images"].items()},
            "hot_ratios": {label: {case: row["hot_ratio"] for case, row in cases.items()}
                           for label, cases in profile["paired_cases"].items()}}
            for name, profile in profiles.items()}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
