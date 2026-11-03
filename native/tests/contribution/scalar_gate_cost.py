"""Paired actual-CNG scalar composition cost with independent effect gates."""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import re
import statistics
import time

from cff_build import run, verify_image
from measure_cff import digest
from preparation_cases import alternate
from scalar_gate_cases import scalar_refusals


SCALARS = ("integer-literals", "comparison-constants")
BENCHMARK = re.compile(r"gate-benchmark iterations=(\d+) warmups=(\d+) top_calls=(\d+) elapsed_ns=([\d.]+)")


def owner(report, name):
    return next(row for row in report["functions"] if row["function"] == name and row["selected"])


def applied(row):
    return {item["component"]: item["applied"] for item in row["components"]}


def common_seeds(row):
    return {item["component"]: item["seed"] for item in row["effective_recipe"]["components"]
        if item["component"] not in SCALARS}


def source_inventory(row):
    proof = row["runtime_contribution"]
    return [(site["label"], site["mixing_domain"], site["sources"]) for site in proof["sites"]]


def section_sizes(objdump, image):
    listing = run([objdump, "-h", image]).stdout
    sections = {name: int(size, 16) for name, size in re.findall(
        r"(?m)^\s*\d+\s+(\.[\w.$-]+)\s+([0-9a-fA-F]+)\b", listing)}
    if not sections.get(".text") or ".data" not in sections or ".rdata" not in sections:
        raise AssertionError("paired image lacks measured PE code/data sections")
    return {"text_bytes": sections[".text"], "data_bytes": sections[".data"] + sections[".rdata"],
        "data_sections": {name: sections[name] for name in (".data", ".rdata")}}


def check_image(image):
    if "gate-normal-completed" not in run([image]).stdout:
        raise AssertionError("paired image lost the checked normal effects")
    for mode in ("wrong", "provider", "closed", "unbound", "source-17", "source-29", "source-41"):
        refusal = run([image, mode], succeeds=False)
        if "gate-enter" not in refusal.stdout or "gate-normal-completed" in refusal.stdout:
            raise AssertionError(f"paired image lost its actual {mode} refusal")


def sample(image, iterations):
    started = time.perf_counter()
    output = run([image, "normal", str(iterations)]).stdout
    process_ms = (time.perf_counter() - started) * 1000
    match = BENCHMARK.search(output)
    if match is None or "gate-normal-completed" not in output or tuple(map(int, match.group(1, 2, 3))) != (iterations, 1, 81 * iterations):
        raise AssertionError("paired cost host lost checked warmup, calls or effects")
    elapsed = float(match[4])
    if not math.isfinite(elapsed) or elapsed <= 0 or not math.isfinite(process_ms) or process_ms <= 0:
        raise AssertionError("paired cost host returned invalid timing")
    return {"process_ms": process_ms, "loop_ns_per_workload": elapsed / iterations}


def measure_scalar_cost(args, directory, transform, private, configuration, retained_source, requests,
        claimed, protected, checker, build_image):
    output = args.scalar_measurements
    output.unlink(missing_ok=True)
    config = json.loads(configuration.read_text())
    off = json.loads(json.dumps(config))
    for component in SCALARS:
        if off["functions"]["contribution_compute"]["components"].get(component) != "required":
            raise AssertionError("scalar cost requires both scalar components on the compute owner")
        off["functions"]["contribution_compute"]["components"][component] = "off"
    off_ir, off_report = alternate(args, directory, transform, private, off, "scalar-cost-off")
    off_claim = directory / "scalar-cost-off.report.json"
    off_config = directory / "scalar-cost-off.json"
    images = {"scalar_off": build_image("scalar-cost-off", off_ir), "scalar_on": protected}
    reports = {"scalar_off": off_report, "scalar_on": json.loads(claimed.read_text())}
    claims = {"scalar_off": off_claim, "scalar_on": claimed}
    rows = {label: owner(report, "contribution_compute") for label, report in reports.items()}
    base, scalar = rows["scalar_off"], rows["scalar_on"]
    if (base["status"] != "transformed" or scalar["status"] != "transformed" or
            any(applied(base).get(name) != 0 or applied(scalar).get(name, 0) < 1 for name in SCALARS) or
            common_seeds(base) != common_seeds(scalar) or source_inventory(base) != source_inventory(scalar) or
            base["runtime_contribution"]["private_input_sha256"] != digest(private) or
            scalar["runtime_contribution"]["private_input_sha256"] != digest(private)):
        raise AssertionError("paired scalar images changed common source authority, seeds or feature state")
    for name in ("query_count", "source_subset_contract_verified", "original_real_edge_density_verified", "original_edges"):
        if base["runtime_contribution"].get(name) != scalar["runtime_contribution"].get(name):
            raise AssertionError(f"paired scalar images changed source CFF {name}")
    if not base["runtime_contribution"]["source_subset_contract_verified"] or not base["runtime_contribution"]["original_real_edge_density_verified"]:
        raise AssertionError("paired scalar images lack real grouped automatic source binding")
    recorded_images = {}
    for label, image in images.items():
        check_image(image)
        final = directory / (label + ".cost.final.json")
        verify_image(checker, image, claims[label], final)
        recorded_images[label] = {"image_sha256": digest(image), "file_bytes": image.stat().st_size,
            "report_sha256": digest(claims[label]), "final_sha256": digest(final),
            **section_sizes(args.objdump, image)}
    scalar_refusal_count = scalar_refusals(args, directory, transform, private, configuration, claimed, checker, build_image)
    if scalar_refusal_count < len(SCALARS):
        raise AssertionError("paired scalar cost lacked individual scalar removal refusals")
    cases = {}
    for iterations in (1, 64):
        samples = {label: [] for label in images}
        for index in range(5):
            for label in (("scalar_off", "scalar_on") if index % 2 == 0 else
                    ("scalar_on", "scalar_off")):
                samples[label].append(sample(images[label], iterations))
        summary = {label: {metric: {"median": statistics.median(item[metric] for item in values),
            "min": min(item[metric] for item in values), "max": max(item[metric] for item in values)}
            for metric in ("process_ms", "loop_ns_per_workload")} for label, values in samples.items()}
        cases[str(iterations)] = {"iterations": iterations, "warmups": 1, "top_calls_per_workload": 81,
            "samples": samples, "summary": summary,
            "loop_ratio": summary["scalar_on"]["loop_ns_per_workload"]["median"] /
                summary["scalar_off"]["loop_ns_per_workload"]["median"]}
    refused = []
    for mode, count in (("normal", "0"), ("normal", "4097"), ("normal", "bad"), ("wrong", "1")):
        result = run([protected, mode, count], succeeds=False)
        if result.returncode != 64 or "gate-benchmark" in result.stdout or "gate-normal-completed" in result.stdout:
            raise AssertionError("scalar cost host accepted invalid workload or failure mode")
        refused.append([mode, count])
    inputs = {"plugin": args.plugin, "retained_source": retained_source, "private_input": private,
        "requests": requests, "scalar_on_config": configuration,
        "scalar_off_config": off_config, "host": Path(__file__).with_name("gate_host.cpp"),
        "driver": Path(__file__).with_name("check_gates.py"), "cost_helper": Path(__file__)}
    record = {"created_at": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
        "compiler": run([args.compiler, "--version"]).stdout, "opt": run([args.opt, "--version"]).stdout,
        "input_sha256": {label: digest(path) for label, path in inputs.items()},
        "backend_sha256": {str(path): digest(path) for path in args.backend_source},
        "component_seeds": common_seeds(base),
        "comparison": "same retained source/private input/requests/seeds and grouped automatic CNG; only two compute scalar components off/on",
        "process_scope": "fresh process, owned context setup, warmup, checked calls and effects, output and teardown",
        "loop_scope": "steady_clock after one checked warmup; owned context retained across real source queries",
        "limits": "fixed Windows CLANG64 source-none fixture; not complete bootstrap or D6 provider costs; no speedup guarantee",
        "images": recorded_images, "cases": cases, "harness_refusals": refused,
        "scalar_refusals": scalar_refusal_count}
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("paired actual-CNG scalar cost record: " + str(output))
