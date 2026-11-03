"""Paired actual-CNG normalization costs using the existing semantic/effect host."""
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import re
import statistics
import time

from cff_build import run, verify_image
from measure_cff import digest, text_size
from preparation_cases import alternate


def measure_alias_cost(args, directory, transform, private, configuration, source, claimed, protected, checker, build_image):
    config = json.loads(configuration.read_text())
    config["functions"]["contribution_compute"]["components"]["deduplicate-blocks"] = "off"
    baseline_ir, baseline_report = alternate(args, directory, transform, private, config, "alias-cost-baseline")
    baseline = build_image("alias-cost-baseline", baseline_ir)
    baseline_claim = directory / "alias-cost-baseline.report.json"
    verify_image(checker, baseline, baseline_claim, directory / "alias-cost-baseline.final.json")
    images = {"baseline": baseline, "dedup": protected}
    reports = {"baseline": baseline_report, "dedup": json.loads(claimed.read_text())}
    records = {}
    component_seeds = None
    for label, image in images.items():
        owner = next(row for row in reports[label]["functions"] if row["function"] == "contribution_compute")
        edges = owner["runtime_contribution"]["original_edges"]
        expected = (6, 6, 6, 6 if label == "baseline" else 5, 0 if label == "baseline" else 1, 3)
        if tuple(edges[name] for name in ("original_edges", "selected_edges", "bound_edges",
                "physical_selected_edges", "coalesced_selected_edges", "explicit_points")) != expected:
            raise AssertionError("paired cost images differ from their independent logical/physical scopes")
        seeds = {item["component"]: item["seed"] for item in owner["effective_recipe"]["components"]}
        if component_seeds is not None and seeds != component_seeds:
            raise AssertionError("paired cost images use different component seeds")
        component_seeds = seeds
        records[label] = {"image_sha256": digest(image), "file_bytes": image.stat().st_size,
            "text_bytes": text_size(args.objdump, image), "compute": owner,
            "coverage_sha256": digest(baseline_claim if label == "baseline" else claimed)}

    def sample(image, iterations):
        started = time.perf_counter()
        process = run([image, "normal", str(iterations)])
        wall_ms = (time.perf_counter() - started) * 1000
        match = re.search(r"gate-benchmark iterations=(\d+) warmups=(\d+) top_calls=(\d+) elapsed_ns=([\d.]+)", process.stdout)
        if match is None or "gate-normal-completed" not in process.stdout or tuple(map(int, match.group(1, 2, 3))) != (iterations, 1, 81 * iterations):
            raise AssertionError("cost host did not complete its checked workload/warmup/effects")
        elapsed = float(match[4])
        if not math.isfinite(elapsed) or elapsed <= 0 or not math.isfinite(wall_ms) or wall_ms <= 0:
            raise AssertionError("invalid paired CNG timing")
        return {"process_ms": wall_ms, "loop_ns_per_workload": elapsed / iterations}

    cases = {}
    for iterations in (1, 64):
        samples = {label: [] for label in images}
        for index in range(7):
            for label in (("baseline", "dedup") if index % 2 == 0 else ("dedup", "baseline")):
                samples[label].append(sample(images[label], iterations))
        summary = {label: {metric: {"median": statistics.median(item[metric] for item in values),
            "min": min(item[metric] for item in values), "max": max(item[metric] for item in values)}
            for metric in ("process_ms", "loop_ns_per_workload")} for label, values in samples.items()}
        cases[str(iterations)] = {"iterations": iterations, "warmups": 1, "top_calls_per_workload": 81,
            "samples": samples, "summary": summary, "loop_ratio": summary["dedup"]["loop_ns_per_workload"]["median"] /
            summary["baseline"]["loop_ns_per_workload"]["median"]}
    refused = []
    for mode, iterations in (("normal", "0"), ("normal", "4097"), ("normal", "bad"), ("wrong", "1")):
        result = run([protected, mode, iterations], succeeds=False)
        if result.returncode != 64 or "gate-benchmark" in result.stdout or "gate-normal-completed" in result.stdout:
            raise AssertionError("cost host accepted invalid iterations or material mode")
        refused.append([mode, iterations])
    inputs = {"plugin": args.plugin, "source": source, "private_input": private, "configuration": configuration,
        "host": Path(__file__).with_name("gate_host.cpp")}
    record = {"created_at": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
        "compiler": run([args.compiler, "--version"]).stdout, "opt": run([args.opt, "--version"]).stdout,
        "input_sha256": {label: digest(path) for label, path in inputs.items()}, "ipo": args.ipo,
        "backend_sha256": {str(path): digest(path) for path in args.backend_source},
        "component_seeds": component_seeds,
        "comparison": "same actual CNG source/seed, common-exit/split and SDK scope; only compute dedup off/on",
        "process_scope": "warm-cache fresh process, owned context setup, warmup, checked loops, stdout and shutdown",
        "loop_scope": "steady_clock loop after one checked warmup; context retained, actual CNG queries, host result/effect checks",
        "limits": "fixed Windows CLANG64 fixture; static query sites differ, runtime query counts on a path need not; no general performance bound or complete bootstrap cost",
        "images": records, "cases": cases, "harness_refusals": refused}
    args.alias_measurements.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("paired actual-CNG alias cost record: " + str(args.alias_measurements))
