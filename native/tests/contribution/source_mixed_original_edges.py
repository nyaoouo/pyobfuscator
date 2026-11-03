"""Two planned original edges with actual CNG sources and exact linked PE proof."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"),
               str(ROOT / "tools"), str(ROOT / "demo")]
from cff_build import run
from linked_machine_mutations import _replace
from pe_layout import parse_image
from cff_joint_machine_evidence import _instructions
from site_scope_cff import actual_subject
from source_mixed_original_negatives import check_artifacts


OWNER = "mixed_original_body"
CONFIGURATION = {"schema_version": 1, "functions": {OWNER: {
    "components": {"runtime-contribution": "required"},
    "contribution": {"selection": "original-edges", "minimum_edges": 2,
                     "maximum_edges": 2, "minimum_percent": 100}}}}


def policy(labels):
    return {"schema_version": 4, "provider": "source-mixed-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {OWNER: 7},
        "sources": [
            {"id": "owned-a", "word_label": 13, "group": "context", "provider": "owned-context-v1", "provider_version": 1},
            {"id": "owned-b", "word_label": 17, "group": "context", "provider": "owned-context-v1", "provider_version": 1},
            {"id": "measured-code", "word_label": 29, "group": "code", "provider": "measured-scope-v1", "provider_version": 1},
            {"id": "owned-c", "word_label": 37, "group": "context", "provider": "owned-context-v1", "provider_version": 1}],
        "bindings": {OWNER: {"sites": {
            str(labels[0]): {"sources": ["owned-a", "owned-b", "measured-code"],
                "mixing_domain": "source-mixed-first",
                "groups": [{"id": "context", "minimum": 2}, {"id": "code", "minimum": 1}]},
            str(labels[1]): {"sources": ["measured-code", "owned-c"],
                "mixing_domain": "source-mixed-second",
                "groups": [{"id": "code", "minimum": 1}, {"id": "context", "minimum": 1}]}}}}}


def refuse(command, output, reason=None):
    output.write_text("stale final output")
    result = run([*command, "--output", output], succeeds=False)
    if output.exists() or (reason is not None and reason not in result.stderr):
        raise AssertionError(f"expected rejection {reason!r}: {result.stderr}")
    return result


def check_final(final, report, plan, private):
    document = json.loads(final.read_text())
    raw = json.loads(report.read_text())
    row = next(item for item in document["functions"] if item.get("function") == OWNER)
    proof = row["runtime_contribution"]
    expected = {"verified": True, "profile": "schema4-original-edges-two-v1",
        "planned_edges": 2, "selected_edges": 2, "bound_edges": 2,
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest()}
    if (raw.get("original_edge_plan_sha256") != expected["plan_sha256"] or
            proof.get("original_edge_machine") != expected or
            any(proof.get(key) is not False for key in (
                "cross_provider_owner_binding_verified", "generated_owner_independence_verified",
                "individual_sites_verified")) or
            proof["private_input_sha256"] != hashlib.sha256(private.read_bytes()).hexdigest()):
        raise AssertionError("final source-mixed original-edge proof overstated or lost a boundary")


def compile_case(args, directory, includes):
    raw, requested, manifest, optimized, plan, private, report, protected, configuration = (
        directory / name for name in ("raw.ll", "requested.ll", "requests.json", "optimized.ll",
            "plan.json", "private.json", "report.json", "protected.ll", "config.json"))
    configuration.write_text(json.dumps(CONFIGURATION))
    raw.write_bytes((ROOT / "tests/contribution/source_mixed_original_body.ll").read_bytes())
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}",
              f"-pyobf-cff-functions={OWNER}", "-pyobf-cff-markers=false"]
    source = raw
    if args.optimization == "O2":
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized])
        source = optimized
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={manifest}",
         "-verify-each", "-S", source, "-o", requested])
    source = requested
    run([*plugin, "-passes=pyobf-native-cff-edge-plan", f"-pyobf-cff-edge-ir-input={source}",
         f"-pyobf-cff-edge-plan-output={plan}", "-disable-output", source])
    planned = json.loads(plan.read_text())
    if (planned.get("owner") != OWNER or len(planned.get("edges", [])) != 2 or
            [edge.get("successor_index") for edge in planned["edges"]] != [0, 1]):
        raise AssertionError("the retained input has no bounded two-edge plan")
    labels = [edge["label"] for edge in planned["edges"]]
    private.write_text(json.dumps(policy(labels)))
    duplicate = copy.deepcopy(planned)
    duplicate["edges"][1]["label"] = labels[0]
    duplicate_plan = directory / "duplicate-label.plan.json"
    duplicate_plan.write_text(json.dumps(duplicate))
    rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan-verify",
        f"-pyobf-cff-edge-ir-input={source}", f"-pyobf-cff-edge-plan-input={duplicate_plan}",
        "-disable-output", source], succeeds=False)
    if "frozen plan differs from exact retained IR and recipe" not in rejected.stderr:
        raise AssertionError("duplicate planned label crossed exact-IR preflight")
    for name, changed in (("missing", policy(labels)), ("wrong", policy(labels))):
        rules = changed["bindings"][OWNER]["sites"]
        if name == "missing":
            rules.pop(str(labels[1]))
        else:
            rules[str(labels[1] + 1)] = rules.pop(str(labels[1]))
        wrong_private = directory / f"{name}-site.private.json"
        wrong_private.write_text(json.dumps(changed))
        wrong_body = directory / f"{name}-site.protected.ll"
        rejected = run([*plugin, "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={manifest}", f"-pyobf-cff-edge-plan-input={plan}",
            f"-pyobf-cff-contribution-input={wrong_private}", "-S", source, "-o", wrong_body],
            succeeds=False)
        if wrong_body.exists() or "source-mixed" not in rejected.stderr:
            raise AssertionError(f"{name} planned site rule crossed compiler gate: {rejected.stderr}")
    run([*plugin, "-passes=pyobf-native-cff-edge-plan-verify", f"-pyobf-cff-edge-ir-input={source}",
         f"-pyobf-cff-edge-plan-input={plan}", "-disable-output", source])
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={manifest}",
         f"-pyobf-cff-edge-plan-input={plan}", f"-pyobf-cff-contribution-input={private}",
         f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", protected])
    run([args.opt, f"-load-pass-plugin={args.plugin}",
         "-passes=pyobf-native-contribution-verify", "-disable-output", protected])
    row = next(item for item in json.loads(report.read_text())["functions"] if item.get("function") == OWNER)
    if (row.get("status") != "transformed" or
            row["runtime_contribution"].get("query_count") != 5 or
            row["runtime_contribution"]["original_edges"]["bound_edges"] != 2):
        raise AssertionError("actual compiler did not bind both original edge groups")
    return source, manifest, configuration, plan, private, report, protected, labels


def check_o2_rejection(args, directory, configuration):
    raw = ROOT / "tests/contribution/source_mixed_original_body.ll"
    optimized, requested, manifest, plan = (
        directory / name for name in ("o2.ll", "o2.requested.ll", "o2.requests.json", "o2.plan.json"))
    run([args.opt, "-passes=default<O2>", "-verify-each", "-S", raw, "-o", optimized])
    source = optimized.read_text()
    if "common.ret:" not in source or source.count("br label %common.ret") != 2:
        raise AssertionError("O2 fixture no longer exhibits the unsupported merged-return shape")
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}",
              f"-pyobf-cff-functions={OWNER}", "-pyobf-cff-markers=false"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={manifest}",
         "-verify-each", "-S", optimized, "-o", requested])
    refused = run([*plugin, "-passes=pyobf-native-cff-edge-plan",
        f"-pyobf-cff-edge-ir-input={requested}", f"-pyobf-cff-edge-plan-output={plan}",
        "-disable-output", requested], succeeds=False)
    if plan.exists() or "needs one conditional decision with exactly two retained normal edges" not in refused.stderr:
        raise AssertionError(f"O2 merged-return shape escaped bounded planner: {refused.stderr}")
    print("O2 merged-return four-edge shape remains explicitly unsupported", flush=True)


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    for name in ("core", "backend"):
        parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    parser.add_argument("--foreign-provider", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="source-mixed-edges-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        if args.optimization == "O2":
            configuration = directory / "config.json"
            configuration.write_text(json.dumps(CONFIGURATION))
            check_o2_rejection(args, directory, configuration)
            return
        source, manifest, configuration, plan, private, report, protected, labels = compile_case(args, directory, includes)
        obj = directory / "protected.obj"
        binary = directory / "protected.exe"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", obj])
        defines = [f"-DPYOBF_ORIGINAL_EDGE_0={labels[0]}",
                   f"-DPYOBF_ORIGINAL_EDGE_1={labels[1]}"]
        core = list(dict.fromkeys([*args.core, *args.backend]))
        run([args.compiler, "-std=c++17", "-O2", *defines, obj,
             ROOT / "tests/contribution/source_mixed_original_probe.cpp", *core,
             *includes, "-lbcrypt", "-o", binary])
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        strict = [*checker, binary, report, "--contribution-input", private,
                  "--source-mixed-original-edges", plan]
        final = directory / "final.json"
        refuse([*checker, binary, report, "--contribution-input", private],
               directory / "default.final.json", "source-mixed contribution acquisition is unsupported")
        refuse([*checker, binary, report, "--contribution-input", private,
                "--source-mixed-bounded-edges", plan], directory / "wrong-profile.final.json")
        refuse([*strict, "--source-mixed-bounded-edges", plan],
               directory / "dual-profile.final.json", "mutually exclusive")
        run([*strict, "--output", final])
        check_final(final, report, plan, private)
        check_artifacts(checker, args.objdump, binary, report, private, plan,
                        final, directory, OWNER)
        inputs = actual_subject(args, directory)
        os.environ.pop("PYOBF_TEST_ORIGINAL_EDGE", None)
        run([binary, *inputs, "normal", args.foreign_provider])
        for edge in ("positive", "negative"):
            environment = os.environ.copy()
            if edge == "negative":
                environment["PYOBF_TEST_ORIGINAL_EDGE"] = "negative"
            for mode in ("wrong-owned", "wrong-measured", "bad-snapshot", "bad-material",
                         "empty-owned", "closed-owned", "rebound-owned", "same-generation-foreign"):
                denied = subprocess.run(list(map(str, [binary, *inputs, mode, args.foreign_provider])),
                                        capture_output=True, text=True, timeout=15, env=environment)
                if denied.returncode & 0xffffffff != 0xe04f0702:
                    raise AssertionError(f"{edge} {mode} crossed source gate or effect ran: "
                                         f"{denied.returncode}: {denied.stderr}")
        check_o2_rejection(args, directory, configuration)
        print(f"source-mixed original edges {args.optimization}: actual CNG runtime and PE pass", flush=True)


if __name__ == "__main__":
    main()
