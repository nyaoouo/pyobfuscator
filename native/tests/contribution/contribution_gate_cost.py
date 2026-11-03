"""Paired actual-CNG contribution cost on one authored grouped CFF fixture."""

from datetime import datetime, timezone
import copy
import json
from pathlib import Path
import platform
import re
import statistics

from cff_build import run, verify_image
from measure_cff import digest
from scalar_gate_cost import SCALARS, applied, common_seeds, owner, sample, section_sizes, check_image


ROOT = Path(__file__).resolve().parents[2]
MARKER = r"(?m)^  call void @pyobf_native_contribution_site_v1[^\n]*\n"


def non_contribution_seeds(row):
    seeds = common_seeds(row)
    seeds.update({item["component"]: item["seed"] for item in row["effective_recipe"]["components"]
        if item["component"] in SCALARS})
    seeds.pop("runtime-contribution", None)
    return seeds


def disabled_image(args, directory, combined, configuration, build_image):
    recipe = json.loads(configuration.read_text())
    for selected in recipe["functions"].values():
        selected["components"]["runtime-contribution"] = "off"
        selected["contribution"] = {"selection": "explicit-points"}
    off_config = directory / "contribution-cost-off.json"
    off_config.write_text(json.dumps(recipe))
    source, removed = re.subn(MARKER, "", combined.read_text())
    if removed == 0:
        raise AssertionError("contribution cost baseline has no authored markers to remove")
    off_source = directory / "contribution-cost-off.source.ll"
    off_source.write_text(source)
    off_requests = directory / "contribution-cost-off.requests.json"
    off_requested = directory / "contribution-cost-off.requested.ll"
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={off_config}"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={off_requests}",
        "-verify-each", "-S", off_source, "-o", off_requested])
    off_ir = directory / "contribution-cost-off.ll"
    off_report = directory / "contribution-cost-off.report.json"
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={off_requests}",
        f"-pyobf-cff-report={off_report}", "-verify-each", "-S", off_requested, "-o", off_ir])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
        "-disable-output", off_ir])
    return build_image("contribution-cost-off", off_ir), off_report, off_config, off_source, off_requests, removed


def inspect_pair(args, directory, on_image, off_image, on_claim, off_claim, on_report, off_report, checker):
    on = owner(on_report, "contribution_compute")
    off = owner(off_report, "contribution_compute")
    on_switch = owner(on_report, "contribution_switch")
    off_switch = owner(off_report, "contribution_switch")
    if any(row["status"] != "transformed" for row in (on, off, on_switch, off_switch)):
        raise AssertionError("paired images did not transform both authored owners")
    downstream = {}
    for active, disabled in ((on, off), (on_switch, off_switch)):
        if (applied(active).get("runtime-contribution", 0) < 1 or
                applied(disabled).get("runtime-contribution", 0) != 0 or
                disabled.get("runtime_contribution") is not None):
            raise AssertionError("paired images changed runtime contribution state")
        if non_contribution_seeds(active) != non_contribution_seeds(disabled):
            raise AssertionError(f"paired images changed common seeds: {active['function']}: "
                f"{non_contribution_seeds(active)} != {non_contribution_seeds(disabled)}")
        active_counts, disabled_counts = applied(active), applied(disabled)
        changed = {name: {"on": active_counts[name], "off": disabled_counts[name]}
            for name in active_counts if name != "runtime-contribution" and
                active_counts[name] != disabled_counts.get(name)}
        # Later scalar and decoy emitters see a different contribution-shaped CFG.
        if set(changed) - {"integer-literals", "decoy-transitions"}:
            raise AssertionError(f"paired images changed unrelated component counts: {active['function']}: {changed}")
        downstream[active["function"]] = changed
    proof = on["runtime_contribution"]
    if (not proof["source_subset_contract_verified"] or
            not proof["original_real_edge_density_verified"] or
            proof["query_count"] < 3):
        raise AssertionError("enabled image lacks grouped automatic source protection")
    check_image(on_image)
    for mode in ("normal", "wrong", "provider", "closed", "unbound", "empty", "foreign",
            "source-17", "source-29", "source-41"):
        if "gate-normal-completed" not in run([off_image, mode]).stdout:
            raise AssertionError(f"disabled image changed ordinary reference behavior: {mode}")
    images = {}
    for label, image, claim in (("contribution_on", on_image, on_claim),
            ("contribution_off", off_image, off_claim)):
        final = directory / (label + ".cost.final.json")
        verify_image(checker, image, claim, final)
        if label == "contribution_off" and any("runtime_contribution" in row for row in
                json.loads(final.read_text())["functions"]):
            raise AssertionError("disabled image received contribution credit")
        images[label] = {"image_sha256": digest(image), "file_bytes": image.stat().st_size,
            "report_sha256": digest(claim), "final_sha256": digest(final),
            **section_sizes(args.objdump, image)}
    for label, image, false_claim in (("removed-gate", off_image, on_claim),
            ("forged-off-report", on_image, off_claim)):
        final = directory / (label + ".final.json")
        refusal = run([*checker, image, false_claim, "--output", final], succeeds=False)
        if final.exists() or not refusal.stderr.strip():
            raise AssertionError(f"paired {label} borrowed another image's evidence")
    forged = copy.deepcopy(on_report)
    owner(forged, "contribution_compute")["runtime_contribution"]["source_subset_contract_verified"] = False
    forged_claim = directory / "contribution-cost-forged.report.json"
    forged_claim.write_text(json.dumps(forged))
    forged_final = directory / "contribution-cost-forged.final.json"
    refused = run([*checker, on_image, forged_claim, "--output", forged_final], succeeds=False)
    if forged_final.exists() or "contribution" not in refused.stderr:
        raise AssertionError("forged grouped source report escaped linked image gate")
    return images, downstream


def measure_contribution_cost(args, directory, combined, private, configuration, retained_source,
        requests, claimed, protected, checker, build_image):
    output = args.contribution_measurements
    output.unlink(missing_ok=True)
    off_image, off_claim, off_config, off_source, off_requests, removed = disabled_image(
        args, directory, combined, configuration, build_image)
    images, downstream = inspect_pair(args, directory, protected, off_image, claimed, off_claim,
        json.loads(claimed.read_text()), json.loads(off_claim.read_text()), checker)
    executions = {"contribution_off": off_image, "contribution_on": protected}
    cases = {}
    for iterations in (1, 64):
        samples = {label: [] for label in executions}
        for index in range(5):
            for label in (("contribution_off", "contribution_on") if index % 2 == 0 else
                    ("contribution_on", "contribution_off")):
                samples[label].append(sample(executions[label], iterations))
        summary = {label: {metric: {"median": statistics.median(item[metric] for item in values),
            "min": min(item[metric] for item in values), "max": max(item[metric] for item in values)}
            for metric in ("process_ms", "loop_ns_per_workload")} for label, values in samples.items()}
        cases[str(iterations)] = {"iterations": iterations, "warmups": 1, "top_calls_per_workload": 81,
            "samples": samples, "summary": summary,
            "loop_ratio": summary["contribution_on"]["loop_ns_per_workload"]["median"] /
                summary["contribution_off"]["loop_ns_per_workload"]["median"]}
    refused = []
    for image in executions.values():
        for mode, count in (("normal", "0"), ("normal", "4097"), ("normal", "bad"), ("wrong", "1")):
            result = run([image, mode, count], succeeds=False)
            if result.returncode != 64 or "gate-benchmark" in result.stdout or "gate-normal-completed" in result.stdout:
                raise AssertionError("contribution cost host accepted invalid workload or failure mode")
            refused.append([image.name, mode, count])
    inputs = {"plugin": args.plugin, "authored_source": combined, "retained_on_source": retained_source,
        "source_off": off_source, "private_input": private, "requests_on": requests,
        "requests_off": off_requests, "config_on": configuration, "config_off": off_config,
        "host": Path(__file__).with_name("gate_host.cpp"),
        "driver": Path(__file__).with_name("check_gates.py"), "cost_helper": Path(__file__)}
    on_row = owner(json.loads(claimed.read_text()), "contribution_compute")
    record = {"created_at": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
        "compiler": run([args.compiler, "--version"]).stdout, "opt": run([args.opt, "--version"]).stdout,
        "input_sha256": {label: digest(path) for label, path in inputs.items()},
        "backend_sha256": {str(path): digest(path) for path in args.backend_source},
        "common_non_contribution_seeds": non_contribution_seeds(on_row),
        "comparison": "one authored grouped automatic CNG fixture and common non-contribution seeds; runtime contribution on/off; requests differ by design",
        "downstream_component_count_changes": downstream,
        "baseline_marker_calls_removed": removed,
        "process_scope": "fresh process, context setup, manual pre-entry CNG query, warmup, checked effects, output and teardown",
        "loop_scope": "steady_clock after one checked warmup; on image queries CNG per site, off image retains no generated contribution queries",
        "limits": "fixed Windows CLANG64 source-none fixture; not full bootstrap, all providers or D6 closure; no speedup guarantee",
        "images": images, "cases": cases, "harness_refusals": refused,
        "removed_gate_and_forged_report_refusals": 3}
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("paired actual-CNG contribution cost record: " + str(output))
