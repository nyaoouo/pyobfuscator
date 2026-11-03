"""Exercise two live Scope references assigned to generated original edges."""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"), str(ROOT / "tools"), str(ROOT / "demo")]
from cff_build import run, verify_image
from site_scope_cff import actual_subject


def policy():
    return {"schema_version": 2, "provider": "measured-scope-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {"multi_scope_edge_body": 7},
        "sources": [{"id": "first-code", "word_label": 13, "group": "code"},
            {"id": "second-code", "word_label": 29, "group": "code"}],
        "bindings": {"multi_scope_edge_body": {"sites": {
            "701": {"sources": ["first-code"], "mixing_domain": "first-site",
                "groups": [{"id": "code", "minimum": 1}]},
            "702": {"sources": ["second-code"], "mixing_domain": "second-site",
                "groups": [{"id": "code", "minimum": 1}]}}}}}


def configuration(maximum):
    return {"schema_version": 1, "functions": {"multi_scope_edge_body": {
        "components": {"runtime-contribution": "required", "external-calls": "required"},
        "contribution": {"selection": "original-edges", "minimum_edges": 0 if maximum == 0 else 1,
            "minimum_percent": 0 if maximum == 0 else 100, "maximum_edges": maximum}}}}


def selected_row(report):
    rows = [row for row in report["functions"] if row.get("function") == "multi_scope_edge_body"]
    if len(rows) != 1 or rows[0].get("status") != "transformed":
        raise AssertionError(f"multi-Scope CFF was not transformed: {rows}")
    return rows[0]


def compile_pass(args, source, requests, config, private, output, report, succeeds=True):
    return run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-input={requests}",
        f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
        "-verify-each", "-S", source, "-o", output], succeeds=succeeds)


def negative_ir(args, directory, protected, label, changed, phrase):
    if changed == protected: raise AssertionError(f"{label} did not alter actual CFF IR")
    mutant = directory / f"{label}.ll"
    mutant.write_text(changed)
    run([args.opt, "-passes=verify", "-disable-output", mutant])
    refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
        "-passes=pyobf-native-contribution-verify", "-disable-output", mutant], succeeds=False)
    if phrase not in refused.stderr:
        raise AssertionError(f"{label} refused for a different reason: {refused.stderr}")
    return mutant


def negative_policy(args, directory, source, requests, config, base, edges):
    first = str(edges[0]["point"])
    for label, change, phrase in (
            ("missing-reference-site", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"][first].pop(
                "reference_site"), "needs an explicit reference_site"),
            ("absent-reference-site", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"][first].update(
                reference_site=999), "names an absent reference_site"),
            ("wrong-anchor-source", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"][first].update(
                sources=["second-code"]), "source or domain differs"),
            ("wrong-anchor-domain", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"][first].update(
                mixing_domain="other-site"), "source or domain differs"),
            ("stale-edge-label", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"].update({
                "4294967295": p["bindings"]["multi_scope_edge_body"]["sites"].pop(first)}),
                "reference_site requires a selected original edge"),
            ("mapped-explicit-anchor", lambda p: p["bindings"]["multi_scope_edge_body"]["sites"]["701"].update(
                reference_site=701), "explicit Scope anchor cannot have reference_site")):
        changed = copy.deepcopy(base); change(changed)
        private = directory / f"{label}.private.json"; private.write_text(json.dumps(changed))
        output, report = directory / f"{label}.ll", directory / f"{label}.coverage.json"
        refused = compile_pass(args, source, requests, config, private, output, report, succeeds=False)
        if phrase not in refused.stderr or output.exists() or report.exists():
            raise AssertionError(f"{label} escaped the pre-output policy gate: {refused.stderr}")
    unselected = policy()
    rule = copy.deepcopy(unselected["bindings"]["multi_scope_edge_body"]["sites"]["701"])
    rule["reference_site"] = 701
    unselected["bindings"]["multi_scope_edge_body"]["sites"][first] = rule
    planning_config = directory / "unselected-reference.config.json"
    planning_config.write_text(json.dumps(configuration(0)))
    private = directory / "unselected-reference.private.json"; private.write_text(json.dumps(unselected))
    output, report = directory / "unselected-reference.ll", directory / "unselected-reference.coverage.json"
    refused = compile_pass(args, source, requests, planning_config, private, output, report, succeeds=False)
    if "reference_site requires a selected original edge" not in refused.stderr or output.exists() or report.exists():
        raise AssertionError(f"unselected reference_site escaped the pre-output gate: {refused.stderr}")
    for component in ("split-blocks", "common-exit"):
        combo = configuration(len(edges))
        combo["functions"]["multi_scope_edge_body"]["components"][component] = "required"
        combo_config = directory / f"{component}.config.json"; combo_config.write_text(json.dumps(combo))
        combo_private = directory / f"{component}.private.json"; combo_private.write_text(json.dumps(base))
        output, report = directory / f"{component}.ll", directory / f"{component}.coverage.json"
        refused = compile_pass(args, source, requests, combo_config, combo_private, output, report, succeeds=False)
        if ("multiple Scope original edges do not support split-blocks or common-exit" not in refused.stderr or
                output.exists() or report.exists()):
            raise AssertionError(f"{component} escaped the unsupported-combination gate: {refused.stderr}")


def negative_single_scope(args, directory, includes):
    raw, requested, requests, config = [directory / name for name in (
        "single.raw.ll", "single.requested.ll", "single.requests.json", "single.config.json")]
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        *includes, ROOT / "tests/contribution/multi_scope_edge_single.cpp", "-o", raw])
    one_config = configuration(0)
    one_config["functions"]["multi_scope_edge_body"]["components"]["external-calls"] = "off"
    config.write_text(json.dumps(one_config))
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
        "-verify-each", "-S", raw, "-o", requested])
    source = requested
    if args.optimization == "O2":
        source = directory / "single.retained.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    one_policy = policy()
    one_policy["bindings"]["multi_scope_edge_body"]["sites"] = {
        "701": one_policy["bindings"]["multi_scope_edge_body"]["sites"]["701"],
        "999": {"sources": ["first-code"], "mixing_domain": "first-site",
            "groups": [{"id": "code", "minimum": 1}], "reference_site": 701}}
    private = directory / "single.private.json"; private.write_text(json.dumps(one_policy))
    output, report = directory / "single.ll", directory / "single.coverage.json"
    refused = compile_pass(args, source, requests, config, private, output, report, succeeds=False)
    if "reference_site requires multiple distinct Scope references" not in refused.stderr or output.exists() or report.exists():
        raise AssertionError(f"single Scope reference_site escaped the pre-output gate: {refused.stderr}")


def negative_dominance(args, directory, includes):
    raw = directory / "nondominating.raw.ll"
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        *includes, ROOT / "tests/contribution/multi_scope_edge_nondominating.cpp", "-o", raw])
    config, requests, requested = [directory / name for name in
        ("nondominating.config.json", "nondominating.requests.json", "nondominating.requested.ll")]
    config.write_text(json.dumps(configuration(0)))
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
        "-verify-each", "-S", raw, "-o", requested])
    source = requested
    if args.optimization == "O2":
        source = directory / "nondominating.retained.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    private = directory / "nondominating.private.json"; private.write_text(json.dumps(policy()))
    plan, report = directory / "nondominating.plan.ll", directory / "nondominating.plan.json"
    compile_pass(args, source, requests, config, private, plan, report)
    edges = selected_row(json.loads(report.read_text()))["runtime_contribution"]["original_edges"]["edges"]
    if not edges: raise AssertionError("nondominating fixture has no original edge")
    config.write_text(json.dumps(configuration(len(edges))))
    candidate = policy()["bindings"]["multi_scope_edge_body"]["sites"]
    for index, edge in enumerate(edges):
        anchor = 702 if index == 0 else 701
        rule = copy.deepcopy(candidate[str(anchor)]); rule["reference_site"] = anchor
        candidate[str(edge["point"])] = rule
    private.write_text(json.dumps(policy() | {"bindings": {"multi_scope_edge_body": {"sites": candidate}}}))
    output, rejected_report = directory / "nondominating.ll", directory / "nondominating.coverage.json"
    refused = compile_pass(args, source, requests, config, private, output, rejected_report, succeeds=False)
    if "does not dominate its original edge" not in refused.stderr or output.exists() or rejected_report.exists():
        raise AssertionError(f"nondominating anchor escaped the original IR gate: {refused.stderr}")
    text = raw.read_text()
    duplicate = re.sub(r"(call void @pyobf_native_measured_contribution_site_v1\([^\n]+i32 noundef )702\)",
        r"\g<1>701)", text, count=1)
    if duplicate == text: raise AssertionError("duplicate anchor mutation did not change raw IR")
    duplicate_raw = directory / "duplicate-anchor.raw.ll"; duplicate_raw.write_text(duplicate)
    run([args.opt, "-passes=verify", "-disable-output", duplicate_raw])
    duplicate_requested, duplicate_requests = directory / "duplicate-anchor.requested.ll", directory / "duplicate-anchor.requests.json"
    config.write_text(json.dumps(configuration(0)))
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={duplicate_requests}",
        "-verify-each", "-S", duplicate_raw, "-o", duplicate_requested])
    duplicate_private = directory / "duplicate-anchor.private.json"
    duplicate_private.write_text(json.dumps(policy()))
    duplicate_output, duplicate_report = directory / "duplicate-anchor.ll", directory / "duplicate-anchor.coverage.json"
    duplicate_refusal = compile_pass(args, duplicate_requested, duplicate_requests, config,
        duplicate_private, duplicate_output, duplicate_report, succeeds=False)
    if "anchor site is duplicated" not in duplicate_refusal.stderr or duplicate_output.exists() or duplicate_report.exists():
        raise AssertionError(f"duplicated anchor escaped the original IR gate: {duplicate_refusal.stderr}")


def global_origin_contract(args, directory, includes):
    raw, requested, requests, config, private = [directory / name for name in (
        "global.raw.ll", "global.requested.ll", "global.requests.json", "global.config.json", "global.private.json")]
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        *includes, ROOT / "tests/contribution/multi_scope_edge_global.cpp", "-o", raw])
    global_config = configuration(0)
    global_config["functions"]["multi_scope_edge_body"]["components"]["external-calls"] = "off"
    config.write_text(json.dumps(global_config))
    private.write_text(json.dumps(policy()))
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
        "-verify-each", "-S", raw, "-o", requested])
    source = requested
    if args.optimization == "O2":
        source = directory / "global.retained.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    plan, plan_report = directory / "global.plan.ll", directory / "global.plan.json"
    compile_pass(args, source, requests, config, private, plan, plan_report)
    edges = selected_row(json.loads(plan_report.read_text()))["runtime_contribution"]["original_edges"]["edges"]
    if not edges: raise AssertionError("global fixture has no generated edge")
    global_config = configuration(len(edges))
    global_config["functions"]["multi_scope_edge_body"]["components"]["external-calls"] = "off"
    config.write_text(json.dumps(global_config))
    data = policy()
    for index, edge in enumerate(edges):
        anchor = 701 if index % 2 == 0 else 702
        rule = copy.deepcopy(data["bindings"]["multi_scope_edge_body"]["sites"][str(anchor)])
        rule["reference_site"] = anchor
        data["bindings"]["multi_scope_edge_body"]["sites"][str(edge["point"])] = rule
    private.write_text(json.dumps(data))
    protected, report = directory / "global.protected.ll", directory / "global.coverage.json"
    compile_pass(args, source, requests, config, private, protected, report)
    proof = selected_row(json.loads(report.read_text()))["runtime_contribution"]["original_edges"]
    if proof["bound_edges"] != len(edges) or not proof["density_verified"]:
        raise AssertionError("global Scope references did not bind all original edges")
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
        "-disable-output", protected])
    actual = protected.read_text()
    query = re.search(r"(?m)^  %[-\w.$]+ = call i32 @pyobf_native_measured_contribution_word_v1\(ptr "
        r"@edge_scope_first_global, i32 4128, i32 1, i32 7, i32 (?!701\b)-?\d+,[^\n]+$", actual)
    if query is None: raise AssertionError("generated global query was not retained")
    swapped = actual[:query.start()] + query.group().replace(
        "ptr @edge_scope_first_global", "ptr @edge_scope_second_global", 1) + actual[query.end():]
    negative_ir(args, directory, actual, "swapped-global-pointer", swapped, "anchored global")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    for name in ("core", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="multi-scope-edge-", dir=args.build_dir,
            delete=os.environ.get("PYOBF_KEEP_TMP") != "1") as temporary:
        directory = Path(temporary)
        raw, requested, requests, source, planning, planning_report, protected, report = [
            directory / name for name in ("raw.ll", "requested.ll", "requests.json", "retained.ll",
                "planning.ll", "planning.json", "protected.ll", "coverage.json")]
        config, private = directory / "config.json", directory / "private.json"
        config.write_text(json.dumps(configuration(0)))
        private.write_text(json.dumps(policy()))
        run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
            *includes, ROOT / "tests/contribution/multi_scope_edge_body.cpp", "-o", raw])
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-config={config}",
            f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", raw, "-o", requested])
        if args.optimization == "O2":
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
        else: source.write_bytes(requested.read_bytes())
        compile_pass(args, source, requests, config, private, planning, planning_report)
        planned = selected_row(json.loads(planning_report.read_text()))["runtime_contribution"]["original_edges"]
        edges = planned["edges"]
        if (len(edges) < 2 or planned["selected_edges"] != 0 or planned["bound_edges"] != 0 or
                planned["density_verified"] or any(edge["selected"] for edge in edges)):
            raise AssertionError("zero-selected planning did not preserve a truthful edge inventory")
        if "pyobf.contribution.edge" in planning.read_text():
            raise AssertionError("planning emitted an unselected generated gateway")
        config.write_text(json.dumps(configuration(len(edges))))
        for index, edge in enumerate(edges):
            site = 701 if index % 2 == 0 else 702
            rule = copy.deepcopy(policy()["bindings"]["multi_scope_edge_body"]["sites"][str(site)])
            rule["reference_site"] = site
            entry = json.loads(private.read_text())
            entry["bindings"]["multi_scope_edge_body"]["sites"][str(edge["point"])] = rule
            private.write_text(json.dumps(entry))
        negative_policy(args, directory, source, requests, config, json.loads(private.read_text()), edges)
        negative_single_scope(args, directory, includes)
        if args.optimization == "none": negative_dominance(args, directory, includes)
        global_origin_contract(args, directory, includes)
        compile_pass(args, source, requests, config, private, protected, report)
        row = selected_row(json.loads(report.read_text()))
        bound = row["runtime_contribution"]["original_edges"]
        if (bound["selected_edges"] != len(edges) or bound["bound_edges"] != len(edges) or
                not bound["density_verified"] or
                {edge.get("reference_site") for edge in bound["edges"] if edge["selected"]} != {701, 702}):
            raise AssertionError("generated edges lost independently configured Scope anchors")
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", protected])
        actual = protected.read_text()
        query_pattern = re.compile(r"(?m)^  (?P<result>%[-\w.$]+) = call i32 "
            r"@pyobf_native_measured_contribution_word_v1\(ptr (?P<reference>%[-\w.$]+), "
            r"i32 4128, i32 1, i32 7, i32 (?P<site>-?\d+), i32 (?P<source>\d+), [^\n]+$")
        queries = list(query_pattern.finditer(actual))
        generated = next((query for query in queries if int(query["site"]) & 0xffffffff not in (701, 702)), None)
        if generated is None or generated["reference"] not in ("%0", "%1"):
            raise AssertionError("generated query has no direct frozen Scope argument")
        other = "%1" if generated["reference"] == "%0" else "%0"
        swapped = actual[:generated.start()] + generated.group().replace(
            f"ptr {generated['reference']}", f"ptr {other}", 1) + actual[generated.end():]
        negative_ir(args, directory, actual, "swapped-generated-pointer", swapped, "anchored argument")
        if "!pyobf.contribution.edge.anchor" not in generated.group():
            raise AssertionError("generated query has no standalone anchor descriptor")
        untagged = actual[:generated.start()] + re.sub(
            r", !pyobf\.contribution\.edge\.anchor !\d+", "", generated.group()) + actual[generated.end():]
        negative_ir(args, directory, actual, "missing-generated-anchor", untagged, "lost its anchor descriptor")
        detached = actual[:generated.end()] + re.sub(re.escape(generated["result"]) + r"(?![-\w.$])",
            "0", actual[generated.end():])
        detached_ir = negative_ir(args, directory, actual, "detached-generated-result", detached,
            "framed state update")
        if args.optimization == "none":
            explicit = next(query for query in queries if int(query["site"]) == 701)
            load = re.search(rf"(?m)^  {re.escape(explicit['reference'])} = load ptr, ptr (%[-\w.$]+),", actual)
            if load is None: raise AssertionError("none profile lost its explicit anchor entry spill")
            slot = load[1]
            write = re.search(rf"(?m)^  store ptr (%[-\w.$]+), ptr {re.escape(slot)}, align 8[^\n]*\n", actual)
            if write is None or write[1] != "%0": raise AssertionError("explicit anchor has no first Scope spill")
            changed_write = actual[:write.start()] + write.group().replace("ptr %0,", "ptr %1,", 1) + actual[write.end():]
            negative_ir(args, directory, actual, "changed-anchor-store", changed_write,
                "pointer differs from its explicit anchor")
            doubled = actual[:write.end()] + f"  store ptr %1, ptr {slot}, align 8\n" + actual[write.end():]
            negative_ir(args, directory, actual, "second-anchor-store", doubled,
                "explicit anchor has no canonical origin")
        core = list(dict.fromkeys([*args.core, *args.backend]))
        protected_obj, binary, final = directory / "protected.obj", directory / "protected.exe", directory / "final.json"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", protected_obj])
        run([args.compiler, "-std=c++17", "-O2", protected_obj,
            ROOT / "tests/contribution/multi_scope_edge_probe.cpp", *core, *includes, "-lbcrypt", "-o", binary])
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        verify_image(checker, binary, report, final)
        detached_obj, detached_image = directory / "detached.obj", directory / "detached.exe"
        run([args.compiler, "-O0", "-fno-lto", "-c", detached_ir, "-o", detached_obj])
        run([args.compiler, "-std=c++17", "-O2", detached_obj,
            ROOT / "tests/contribution/multi_scope_edge_probe.cpp", *core, *includes, "-lbcrypt", "-o", detached_image])
        detached_final = directory / "detached.final.json"
        refusal = run([*checker, detached_image, report, "--output", detached_final], succeeds=False)
        if detached_final.exists() or "linked image lost measured query return flow" not in refusal.stderr:
            raise AssertionError(f"real detached generated edge failed at the wrong boundary: {refusal.stderr}")
        inputs = actual_subject(args, directory)
        run([binary, *inputs])
        for mode in ("swapped", "wrong-spec", "bad-snapshot", "bad-material"):
            denied = subprocess.run(list(map(str, [binary, *inputs, mode])),
                capture_output=True, text=True, timeout=15)
            if denied.returncode & 0xffffffff != 0xe04f0702:
                raise AssertionError(f"{mode} reached a wrong boundary: {denied.returncode}, {denied.stderr}")
        print(f"multi-Scope generated edges {args.optimization}: {len(edges)} planned/bound, actual CNG and final image pass")


if __name__ == "__main__": main()
