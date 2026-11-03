"""Exercise owned and measured providers within one CFF site."""

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
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"), str(ROOT / "tools"), str(ROOT / "demo")]
from cff_build import run, verify_image
from cff_contribution_groups import check_contribution_groups
from site_scope_cff import actual_subject
from linked_machine_mutations import check_linked_mutations, check_two_site_linked_mutations
from policy_witness_cases import positive as check_policy_positive, negatives as check_policy_negatives
from numeric_witness_cases import (check_numeric_cancelled, check_unknown_linked,
                                   check_unknown_semantics)
from private_argument_cases import check_private_arguments
from dispatcher_interval_cases import check_dispatcher_interval_mutations
from helper_write_cases import check_helper_write_mutations
from helper_route_cases import check_helper_route_mutations
from cff_joint_machine_evidence import MEASURED


def private_input():
    return {"schema_version": 4, "provider": "source-mixed-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {"mixed_site_body": 7},
        "sources": [{"id": "owned-context", "word_label": 13, "group": "context",
            "provider": "owned-context-v1", "provider_version": 1},
            {"id": "measured-code", "word_label": 29, "group": "code",
                "provider": "measured-scope-v1", "provider_version": 1}],
        "bindings": {"mixed_site_body": {"sites": {
            "701": {"sources": ["owned-context", "measured-code"], "mixing_domain": "source-mixed-site",
                "groups": [{"id": "context", "minimum": 1}, {"id": "code", "minimum": 1}]}}}}}


def add_second_site(data):
    data["sources"].append({"id": "owned-extra", "word_label": 37, "group": "context-extra",
        "provider": "owned-context-v1", "provider_version": 1})
    data["bindings"]["mixed_site_body"]["sites"]["703"] = {
        "sources": ["measured-code", "owned-extra"], "mixing_domain": "source-mixed-other",
        "groups": [{"id": "code", "minimum": 1}, {"id": "context-extra", "minimum": 1}]}


def add_third_site(data):
    add_second_site(data)
    data["sources"].append({"id": "owned-third", "word_label": 41, "group": "context-third",
        "provider": "owned-context-v1", "provider_version": 1})
    data["bindings"]["mixed_site_body"]["sites"]["705"] = {
        "sources": ["measured-code", "owned-third"], "mixing_domain": "source-mixed-third",
        "groups": [{"id": "code", "minimum": 1}, {"id": "context-third", "minimum": 1}]}


def two_site_input(three_owned):
    data = private_input()
    data["sources"][0].update(id="owned-a")
    if three_owned:
        data["sources"].insert(1, {"id": "owned-b", "word_label": 17,
            "group": "context", "provider": "owned-context-v1", "provider_version": 1})
    data["sources"].append({"id": "owned-c", "word_label": 37,
        "group": "context", "provider": "owned-context-v1", "provider_version": 1})
    sites = data["bindings"]["mixed_site_body"]["sites"]
    sites["701"] = {"sources": (["owned-a", "owned-b", "measured-code"] if three_owned else
        ["owned-a", "measured-code"]), "mixing_domain": "source-mixed-first",
        "groups": [{"id": "context", "minimum": 2 if three_owned else 1},
                   {"id": "code", "minimum": 1}]}
    sites["703"] = {"sources": ["measured-code", "owned-c"],
        "mixing_domain": "source-mixed-second",
        "groups": [{"id": "code", "minimum": 1}, {"id": "context", "minimum": 1}]}
    return data


def check_report(document, expected):
    rows = [row for row in document["functions"] if row.get("selected") and not row.get("generated")]
    if len(rows) != 1 or rows[0].get("function") != "mixed_site_body" or rows[0].get("status") != "transformed":
        raise AssertionError("mixed function is absent from actual CFF output")
    proof = rows[0]["runtime_contribution"]
    check_contribution_groups(proof, 1, "mixed_site_body")
    if (proof.get("scheme_version") != 4 or proof.get("acquisition") != "explicit-source-point" or
            proof.get("query_count") != 2 or
            proof.get("generated_owner_independence_verified") is not False or
            proof.get("cross_provider_owner_binding_verified") is not False or
            proof.get("joint_helper_contract") != "source-mixed-context-v1" or
            proof.get("individual_sites_verified") is not False or
            any(field in proof for field in ("joint_caller_pointer_provenance_verified",
                "joint_machine_scope", "joint_return_routing_scope", "original_edge_machine")) or
            proof.get("helper_counts") != {"owned-context-v1": 1, "measured-scope-v1": 1} or
            proof.get("private_input_sha256") != hashlib.sha256(json.dumps(expected).encode()).hexdigest()):
        raise AssertionError("mixed source report overstates or loses its two helpers")
    catalog = {source["id"]: source for source in expected["sources"]}
    for site in proof["sites"]:
        rule = expected["bindings"]["mixed_site_body"]["sites"].get(str(site["label"]))
        if rule is None: raise AssertionError("unexpected mixed site in report")
        sources = [catalog[name] for name in rule["sources"]]
        expected_sources = [{"id": source["id"], "word_label": source["word_label"], "encoding": 1,
            "group": source["group"], "class": "referenced-evidence" if source["provider"] == "measured-scope-v1" else "authenticated-material",
            "sharing": "owner-independent" if source["provider"] == "measured-scope-v1" else "context-material",
            "use": "required-binding", "provider": source["provider"], "provider_version": 1} for source in sources]
        if (site.get("provider") != "source-mixed-v1" or site.get("provider_version") != 1 or
                site.get("mixing_domain") != rule["mixing_domain"] or site.get("sources") != expected_sources):
            raise AssertionError("mixed site report differs from independently supplied private policy")
    return rows[0]


def check_two_site_report(document, expected):
    rows = [row for row in document["functions"] if row.get("selected") and not row.get("generated")]
    if len(rows) != 1 or rows[0].get("function") != "mixed_site_body" or rows[0].get("status") != "transformed":
        raise AssertionError("two source-mixed sites were not transformed")
    proof = rows[0]["runtime_contribution"]
    check_contribution_groups(proof, 2, "mixed_site_body")
    catalog = {source["id"]: source for source in expected["sources"]}
    rules = expected["bindings"]["mixed_site_body"]["sites"]
    if (proof.get("query_count") != sum(len(rule["sources"]) for rule in rules.values()) or
            [site.get("label") for site in proof["sites"]] != [701, 703] or
            [site.get("index") for site in proof["sites"]] != [0, 1] or
            proof.get("cross_provider_owner_binding_verified") is not False or
            proof.get("individual_sites_verified") is not False or
            proof.get("private_input_sha256") != hashlib.sha256(json.dumps(expected).encode()).hexdigest()):
        raise AssertionError("two-site compiler report is incomplete or not canonical")
    for site in proof["sites"]:
        rule = rules[str(site["label"])]
        if (site.get("mixing_domain") != rule["mixing_domain"] or
                [(source["id"], source["word_label"], source["provider"]) for source in site["sources"]] !=
                [(name, catalog[name]["word_label"], catalog[name]["provider"]) for name in rule["sources"]]):
            raise AssertionError("two-site report differs from independently supplied private policy")
    return rows[0]


def negative_compiler(args, directory, source, requests, configuration, protected):
    command = [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={configuration}", f"-pyobf-cff-requests-input={requests}"]
    for label, change, reason in (
            ("unknown-provider", lambda d: d["sources"][1].update(provider="missing-scope"), "unsupported provider/version"),
            ("provider-version", lambda d: d["sources"][1].update(provider_version=2), "unsupported provider/version"),
            ("reordered-binding", lambda d: d["bindings"]["mixed_site_body"]["sites"]["701"].update(
                sources=["measured-code", "owned-context"]), "binding must follow catalog order"),
            ("missing-owned", lambda d: d["bindings"]["mixed_site_body"]["sites"]["701"].update(
                sources=["measured-code"], groups=[{"id": "code", "minimum": 1}]),
                "source-mixed site needs one measured and at least one owned reference"),
            ("missing-measured", lambda d: d["bindings"]["mixed_site_body"]["sites"]["701"].update(
                sources=["owned-context"], groups=[{"id": "context", "minimum": 1}]),
                "source-mixed site needs one measured and at least one owned reference"),
            ("unused-second-site-rule", add_second_site,
                "mixed source markers must exactly match explicit site rules"),
            ("three-site-unsupported", add_third_site,
                "source-mixed owner supports at most two explicit sites"),
            ("default-rule", lambda d: d["bindings"]["mixed_site_body"].update(default=copy.deepcopy(
                d["bindings"]["mixed_site_body"]["sites"]["701"])), "mixed owner needs explicit site rules")):
        data = copy.deepcopy(private_input()); change(data)
        candidate = directory / f"{label}.json"; candidate.write_text(json.dumps(data))
        output, report = directory / f"{label}.ll", directory / f"{label}.coverage.json"
        failed = run([*command, f"-pyobf-cff-contribution-input={candidate}",
            f"-pyobf-cff-report={report}", "-S", source, "-o", output], succeeds=False)
        if reason not in failed.stderr or output.exists() or report.exists():
            raise AssertionError(f"invalid mixed policy escaped compiler gate: {label}: {failed.stderr}")
    missing = private_input()
    sites = missing["bindings"]["mixed_site_body"]["sites"]
    sites["703"] = sites.pop("701")
    missing_input = directory / "missing-site-rule.json"; missing_input.write_text(json.dumps(missing))
    missing_output, missing_report = directory / "missing-site-rule.ll", directory / "missing-site-rule.coverage.json"
    failed = run([*command, f"-pyobf-cff-contribution-input={missing_input}",
        f"-pyobf-cff-report={missing_report}", "-S", source, "-o", missing_output], succeeds=False)
    row = next((row for row in json.loads(missing_report.read_text())["functions"]
        if row.get("function") == "mixed_site_body"), {}) if missing_report.exists() else {}
    if ("selection was not fully transformed" not in failed.stderr or missing_output.exists() or
            "mixed contribution marker has no explicit site rule" not in row.get("reason", "")):
        raise AssertionError(f"missing per-site rule escaped compiler gate: {failed.stderr}; {row}")
    from mixed_site_cff import private_input as schema3_private_input
    for schema in (1, 2, 3):
        legacy_data = schema3_private_input()
        if schema == 1:
            legacy_data = {"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 0x1020,
                "domain": 1, "source": 13, "private_words": legacy_data["private_words"],
                "owners": {"mixed_site_body": 7}}
        elif schema == 2:
            legacy_data["schema_version"] = 2
            legacy_data["provider"] = "owned-context-v1"
            legacy_data["sources"] = legacy_data["sources"][:1]
            legacy_data["bindings"]["mixed_site_body"]["sites"] = {
                "701": legacy_data["bindings"]["mixed_site_body"]["sites"]["701"]}
        legacy = directory / f"schema{schema}.private.json"; legacy.write_text(json.dumps(legacy_data))
        legacy_report = directory / f"schema{schema}.coverage.json"
        refused = run([*command, f"-pyobf-cff-contribution-input={legacy}",
            f"-pyobf-cff-report={legacy_report}", "-S", source,
            "-o", directory / f"schema{schema}.protected.ll"], succeeds=False)
        row = next((row for row in json.loads(legacy_report.read_text())["functions"]
            if row.get("function") == "mixed_site_body"), {}) if legacy_report.exists() else {}
        if ("selection was not fully transformed" not in refused.stderr or
                "mixed contribution marker requires schema4 source binding" not in row.get("reason", "")):
            raise AssertionError(f"schema{schema} silently admitted new marker: {refused.stderr}; {row}")
    original = source.read_text()
    invalid_abi = re.sub(r"(\b(?:call|declare)(?: dso_local)? void @pyobf_native_mixed_contribution_site_v1\([^\n]*?)i32 noundef(?= 701\)|\))",
        r"\1i64 noundef", original)
    if invalid_abi == original: raise AssertionError("mixed marker declaration/call was not retained")
    abi_source = directory / "wrong-marker-abi.ll"; abi_source.write_text(invalid_abi)
    run([args.opt, "-passes=verify", "-disable-output", abi_source])
    abi_report = directory / "wrong-marker-abi.coverage.json"
    refused = run([*command, f"-pyobf-cff-contribution-input={directory / 'mixed-site.private.json'}",
        f"-pyobf-cff-report={abi_report}", "-S", abi_source,
        "-o", directory / "wrong-marker-abi.protected.ll"], succeeds=False)
    row = next((row for row in json.loads(abi_report.read_text())["functions"]
        if row.get("function") == "mixed_site_body"), {}) if abi_report.exists() else {}
    if "contribution needs a live lease reference and nonzero fixed i32 site identity" not in row.get("reason", ""):
        raise AssertionError(f"wrong three-argument marker ABI escaped: {refused.stderr}; {row}")
    original_config = json.loads(configuration.read_text())
    original_config["functions"]["mixed_site_body"]["contribution"]["selection"] = "original-edges"
    automatic = directory / "automatic.json"; automatic.write_text(json.dumps(original_config))
    failure = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={automatic}", f"-pyobf-cff-requests-input={requests}",
        f"-pyobf-cff-contribution-input={directory / 'mixed-site.private.json'}",
        "-S", source, "-o", directory / "automatic.ll"], succeeds=False)
    if "schema4 original edges require frozen exact-IR plan" not in failure.stderr:
        raise AssertionError("mixed original-edge source selection escaped its frozen-plan gate")
    actual = protected.read_text()
    owned = next((match for match in re.finditer(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_mixed_owned_contribution_word_v1\([^\n]+", actual)
        if "i32 701, i32 13," in match.group()), None)
    measured = next((match for match in re.finditer(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_mixed_measured_contribution_word_v1\([^\n]+", actual)
        if "i32 701, i32 29," in match.group()), None)
    if owned is None or measured is None: raise AssertionError("mixed protected body lost its two provider queries")
    owned_reference = re.search(r"\(ptr ([^,]+),", owned.group())[1]
    measured_reference = re.search(r"\(ptr ([^,]+),", measured.group())[1]
    if owned_reference == measured_reference: raise AssertionError("source-mixed marker lost independent references")
    if (re.findall(r"ptr ([^,)]+)", owned.group()) != [owned_reference, measured_reference] or
            re.findall(r"ptr ([^,)]+)", measured.group()) != [measured_reference, owned_reference]):
        raise AssertionError("source-mixed helpers lost their paired references")
    body_end = actual.find("\n}", measured.end())
    if body_end < 0: raise AssertionError("selected source-mixed function has no IR boundary")
    mutants = {
        "wrong-owned-helper": actual[:owned.start()] + owned.group().replace(
            "@pyobf_native_mixed_owned_contribution_word_v1", "@pyobf_native_mixed_measured_contribution_word_v1") + actual[owned.end():],
        "wrong-measured-helper": actual[:measured.start()] + measured.group().replace(
            "@pyobf_native_mixed_measured_contribution_word_v1", "@pyobf_native_mixed_owned_contribution_word_v1") + actual[measured.end():],
        "wrong-owned-label": actual[:owned.start()] + owned.group().replace("i32 13,", "i32 29,") + actual[owned.end():],
        "wrong-measured-site": actual[:measured.start()] + measured.group().replace("i32 701,", "i32 702,") + actual[measured.end():],
        "wrong-owned-reference": actual[:owned.start()] + owned.group().replace(
            owned_reference, measured_reference, 1) + actual[owned.end():],
        "wrong-owned-peer": actual[:owned.start()] + owned.group().replace(
            f"ptr {measured_reference}", f"ptr {owned_reference}", 1) + actual[owned.end():],
        "wrong-measured-peer": actual[:measured.start()] + measured.group().replace(
            f"ptr {owned_reference}", f"ptr {measured_reference}", 1) + actual[measured.end():],
        "swapped-references": actual[:owned.start()] + owned.group().replace(
            owned_reference, measured_reference, 1) + actual[owned.end():measured.start()] +
            measured.group().replace(measured_reference, owned_reference, 1) + actual[measured.end():],
        "rauw-owned-reference": actual[:owned.start()] + re.sub(
            re.escape(owned_reference) + r"(?![-\w.$])", measured_reference, actual[owned.start():body_end]) + actual[body_end:],
        "swapped-query-order": actual[:owned.start()] + measured.group() + actual[owned.end():measured.start()] + owned.group() + actual[measured.end():],
        "detached-owned-result": actual[:owned.end()] + re.sub(re.escape(owned[1]) + r"(?![-\w.$])", "0", actual[owned.end():]),
        "detached-measured-result": actual[:measured.end()] + re.sub(re.escape(measured[1]) + r"(?![-\w.$])", "0", actual[measured.end():]),
    }
    for label, changed in mutants.items():
        if changed == actual: raise AssertionError(f"mutation did not change actual mixed IR: {label}")
        mutant = directory / f"{label}.ll"; mutant.write_text(changed)
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
            "-passes=pyobf-native-contribution-verify", "-disable-output", mutant], succeeds=False)
        if "contribution" not in refused.stderr:
            raise AssertionError(f"mixed IR mutation escaped proof: {label}: {refused.stderr}")
        print(f"valid-IR source-mixed mutation refused: {label}")
    return {kind: directory / f"{kind}.ll" for kind in (
        "detached-owned-result", "detached-measured-result")}


def two_site_ir_negatives(args, directory, requested, requests, configuration, private):
    original = requested.read_text()
    first = "  store ptr %0, ptr %4, align 8, !pyobf.cff.site !13"
    second = "  store ptr %1, ptr %5, align 8, !pyobf.cff.site !14"
    if first not in original or second not in original:
        raise AssertionError("two-site source lost its expected entry stores")
    swapped = original.replace(first, "  store ptr %1, ptr %4, align 8, !pyobf.cff.site !13").replace(
        second, "  store ptr %0, ptr %5, align 8, !pyobf.cff.site !14")
    later_marker = re.search(r"(?m)^  call void @pyobf_native_mixed_contribution_site_v1\([^\n]+i32 noundef 701\)[^\n]*$", original)
    if later_marker is None or "%11" not in later_marker.group():
        raise AssertionError("two-site source lost its second canonical marker")
    dynamic = (original[:later_marker.start()] +
        "  %pyobf.dynamic = select i1 false, ptr %0, ptr %1\n" +
        later_marker.group().replace("%11", "%pyobf.dynamic", 1) +
        original[later_marker.end():])
    changed = {"wrong-index-both-stores": (swapped, "contribution source acquisition changed"),
        "missing-initial-store": (original.replace(first + "\n", "", 1),
            "mixed contribution references need distinct canonical function arguments"),
        "extra-alias-write": (original.replace(first, first + "\n  store ptr %1, ptr %4, align 8", 1),
            "mixed contribution references need distinct canonical function arguments"),
        "gep-alias-write": (original.replace(first, first +
            "\n  %pyobf.alias = getelementptr i8, ptr %4, i64 0"
            "\n  store ptr %1, ptr %pyobf.alias, align 8", 1),
            "mixed contribution references need distinct canonical function arguments"),
        "dynamic-reference": (dynamic, "mixed contribution references need distinct canonical function arguments"),
        "duplicate-marker-label": (original.replace("i32 noundef 703)", "i32 noundef 701)", 1),
            "mixed source markers must exactly match explicit site rules")}
    for label, (source, reason) in changed.items():
        if source == original: raise AssertionError(f"two-site negative did not change IR: {label}")
        candidate = directory / f"two-{label}.ll"; candidate.write_text(source)
        run([args.opt, "-passes=verify", "-disable-output", candidate])
        report, output = directory / f"two-{label}.coverage.json", directory / f"two-{label}.protected.ll"
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
            f"-pyobf-cff-config={configuration}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-contribution-input={private}",
            f"-pyobf-cff-report={report}", "-S", candidate, "-o", output], succeeds=False)
        row = next((row for row in json.loads(report.read_text())["functions"]
            if row.get("function") == "mixed_site_body"), {}) if report.exists() else {}
        if output.exists() or reason not in (refused.stderr + row.get("reason", "")):
            raise AssertionError(f"two-site valid-IR negative escaped: {label}: {refused.stderr}; {row}")
        print(f"two-site valid-IR refusal: {label}")
    for label in ("missing-rule", "unused-rule"):
        policy = json.loads(private.read_text())
        sites = policy["bindings"]["mixed_site_body"]["sites"]
        removed = sites.pop("703")
        if label == "unused-rule": sites["705"] = removed
        candidate = directory / f"two-{label}.private.json"; candidate.write_text(json.dumps(policy))
        report, output = directory / f"two-{label}.coverage.json", directory / f"two-{label}.protected.ll"
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
            f"-pyobf-cff-config={configuration}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-contribution-input={candidate}",
            f"-pyobf-cff-report={report}", "-S", requested, "-o", output], succeeds=False)
        row = next((row for row in json.loads(report.read_text())["functions"]
            if row.get("function") == "mixed_site_body"), {}) if report.exists() else {}
        if output.exists() or "mixed contribution marker has no explicit site rule" not in row.get("reason", ""):
            raise AssertionError(f"two-site {label} escaped compiler: {refused.stderr}; {row}")
        print(f"two-site policy refusal: {label}")
    encoded = private.read_text()
    needles = list(re.finditer(r'"701"\s*:\s*\{', encoded))
    if len(needles) != 1:
        raise AssertionError("two-site raw duplicate-key fixture lost its exact rule")
    for label, key in (("literal", '"701"'), ("escaped", '"\\u0037\\u0030\\u0031"')):
        candidate = directory / f"two-duplicate-rule-{label}.json"
        candidate.write_text(encoded[:needles[0].start()] + f"{key}: null, " + encoded[needles[0].start():])
        output = directory / f"two-duplicate-rule-{label}.protected.ll"
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
            f"-pyobf-cff-config={configuration}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-contribution-input={candidate}",
            "-S", requested, "-o", output], succeeds=False)
        if output.exists() or "duplicate JSON object key" not in refused.stderr:
            raise AssertionError(f"two-site duplicate {label} rule escaped raw gate: {refused.stderr}")
        print(f"two-site duplicate raw rule refused: {label}")
    deep = json.loads(configuration.read_text())
    deep_rule = deep["functions"]["mixed_site_body"]
    deep_rule["recipe"] = "relative-tree-deep"
    deep_rule["components"]["internal-calls"] = "off"
    deep_config = directory / "two-out-of-scope-deep.json"; deep_config.write_text(json.dumps(deep))
    deep_output = directory / "two-out-of-scope-deep.protected.ll"
    refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
        f"-pyobf-cff-config={deep_config}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-contribution-input={private}",
        "-S", requested, "-o", deep_output], succeeds=False)
    if deep_output.exists() or "source-mixed two-site requires whole relative-tree scope" not in refused.stderr:
        raise AssertionError(f"two-site out-of-scope strategy escaped compiler: {refused.stderr}")
    print("two-site compiler scope refusal: deep strategy")


def two_site_final_negatives(args, directory, protected, binary, report, checker, core, includes):
    document = json.loads(report.read_text())
    for label, mutate in (("forged-site-label", lambda proof: proof["sites"][1].update(label=705)),
                          ("forged-source-label", lambda proof: (
                              proof["sites"][0]["sources"][0].update(word_label=37),
                              proof["sites"][1]["sources"][1].update(word_label=13)))):
        forged = copy.deepcopy(document)
        proof = next(row["runtime_contribution"] for row in forged["functions"]
            if row.get("function") == "mixed_site_body")
        mutate(proof)
        candidate = directory / f"two-{label}.json"; candidate.write_text(json.dumps(forged))
        final = directory / f"two-{label}.final.json"
        refused = run([*checker, binary, candidate, "--output", final], succeeds=False)
        if final.exists() or "source-mixed linked site map" not in refused.stderr:
            raise AssertionError(f"raw final-only two-site forgery escaped: {label}: {refused.stderr}")
        print(f"two-site raw final-only forgery refused: {label}")
    for label, change in (("region", lambda row: row.update(region_flow_contract_verified=True)),
                          ("hybrid-eh", lambda row: row["effective_recipe"].update(coverage="hybrid-eh"))):
        forged = copy.deepcopy(document)
        row = next(row for row in forged["functions"] if row.get("function") == "mixed_site_body")
        change(row)
        candidate = directory / f"two-forged-{label}-scope.json"; candidate.write_text(json.dumps(forged))
        final = directory / f"two-forged-{label}-scope.final.json"
        refused = run([*checker, binary, candidate, "--output", final], succeeds=False)
        if final.exists() or "source-mixed two-site needs whole relative-tree coverage" not in refused.stderr:
            raise AssertionError(f"out-of-scope two-site final report escaped: {label}: {refused.stderr}")
        print(f"two-site final scope refusal: {label}")
    original = protected.read_text()
    transition = re.search(r"(?m)^  store i32 [^\n]+, ptr %pyobf\.state, align 4, !pyobf\.contribution\.transition !\d+\n", original)
    if transition is None: raise AssertionError("two-site overlap fixture lost its transition write")
    for label, extra in (("wide-overwrite", "  store i64 0, ptr %pyobf.state, align 4\n"),
                         ("offset-overwrite", "  %pyobf.overlap = getelementptr i8, ptr %pyobf.state, i64 1\n"
                          "  store i32 0, ptr %pyobf.overlap, align 1\n")):
        changed = directory / f"two-{label}.ll"
        changed.write_text(original[:transition.end()] + extra + original[transition.end():])
        run([args.opt, "-passes=verify", "-disable-output", changed])
        body, linked, final = (directory / f"two-{label}.{suffix}" for suffix in
            ("obj", "exe", "final.json"))
        run([args.compiler, "-O0", "-fno-lto", "-c", changed, "-o", body])
        run([args.compiler, "-std=c++17", "-O2", "-DPYOBF_TWO_MIXED_SITES",
            "-DPYOBF_THREE_OWNED_WORDS", body,
            ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
            "-lbcrypt", "-o", linked])
        refused = run([*checker, linked, report, "--output", final], succeeds=False)
        if final.exists() or "overwrites or aliases the dispatcher state slot" not in refused.stderr:
            raise AssertionError(f"linked overlapping state overwrite escaped: {label}: {refused.stderr}")
        print(f"actual linked two-site state overlap refused: {label}")


def two_site_cases(args, directory, configuration, checker, inputs, core, includes):
    for three_owned in (False, True):
        tag = "three-two" if three_owned else "two-two"
        raw, requested, requests, optimized, protected, report, private = [
            directory / f"{tag}.{suffix}" for suffix in
            ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "private.json")]
        policy = two_site_input(three_owned); private.write_text(json.dumps(policy))
        run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone",
            "-DPYOBF_TWO_MIXED_SITES", "-S", "-emit-llvm", *includes,
            ROOT / "tests/contribution/source_mixed_body.cpp", "-o", raw])
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
            "-verify-each", "-S", raw, "-o", requested])
        source = requested
        if args.optimization == "O2":
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized]); source = optimized
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
            "-verify-each", "-S", source, "-o", protected])
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", protected])
        document = json.loads(report.read_text()); check_two_site_report(document, policy)
        if three_owned and args.optimization == "none":
            two_site_ir_negatives(args, directory, requested, requests, configuration, private)
        body, binary, final = (directory / f"{tag}.{suffix}" for suffix in
            ("obj", "exe", "final.json"))
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", body])
        defines = ["-DPYOBF_TWO_MIXED_SITES"] + (["-DPYOBF_THREE_OWNED_WORDS"] if three_owned else [])
        run([args.compiler, "-std=c++17", "-O2", *defines, body,
            ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
            "-lbcrypt", "-o", binary])
        verify_image(checker, binary, report, final)
        check_policy_positive(checker, binary, report, private, final, directory, run)
        if three_owned and args.optimization == "none":
            # cmd.exe exposes the option's '=' as a split between %2 and %3.
            wrapper = directory / "hide-measured-helper.cmd"
            wrapper.write_text(
                '@echo off\n'
                f'if "%~2"=="--disassemble-symbols" if "%~3"=="{MEASURED}" exit /b 0\n'
                f'"{args.objdump}" %*\n')
            missing_final = directory / "missing-helper.final.json"
            missing_final.write_text("stale final output")
            missing = subprocess.run(
                [*map(str, (checker[0], checker[1], wrapper, binary, report)),
                 "--contribution-input", str(private), "--output", str(missing_final)],
                capture_output=True, text=True, timeout=30)
            if (missing.returncode == 0 or missing_final.exists() or
                    f"source-mixed linked helper is absent: {MEASURED}" not in missing.stderr):
                raise AssertionError(f"missing linked helper disassembly escaped: {missing.stderr}")
            check_policy_negatives(checker, binary, report, private, directory, args.objdump, run,
                                   args.opt, args.plugin, configuration, requests, requested)
            check_two_site_linked_mutations(checker, binary, report, directory, args.objdump, run)
            check_dispatcher_interval_mutations(checker, binary, report, private,
                                                directory, args.objdump)
            check_helper_write_mutations(checker, binary, report, private,
                                         directory, args.objdump)
            check_helper_route_mutations(checker, binary, report, private,
                                         directory, args.objdump)
            two_site_final_negatives(args, directory, protected, binary, report, checker, core, includes)
            check_numeric_cancelled(args, directory, protected, report, checker, core,
                                    includes, final, run)
            check_unknown_linked(checker, binary, report, directory, args.objdump, final, run)
            check_unknown_semantics()
            check_private_arguments(checker, binary, report, private, final,
                                    directory, args.objdump, run)
        linked = next(row["runtime_contribution"] for row in json.loads(final.read_text())["functions"]
            if row.get("function") == "mixed_site_body")
        if (linked.get("cross_provider_owner_binding_verified") is not False or
                linked.get("individual_sites_verified") is not False or
                linked.get("joint_caller_pointer_provenance_verified") is True):
            raise AssertionError("two-site final report overstated an unproved binding")
        opted = directory / f"{tag}.joint.final.json"
        refusal = run([*checker, binary, report, "--check-joint-caller-flow", "--output", opted], succeeds=False)
        if opted.exists() or "one unproven explicit schema4 joint site is required" not in refusal.stderr:
            raise AssertionError(f"one-site G2e diagnostic accepted two sites: {refusal.stderr}")
        run([binary, *inputs, "normal", args.foreign_provider])
        for mode in ("wrong-owned", "wrong-measured"):
            denied = subprocess.run(list(map(str, [binary, *inputs, mode, args.foreign_provider])),
                capture_output=True, text=True, timeout=15)
            if denied.returncode & 0xffffffff != 0xe04f0702:
                raise AssertionError(f"{tag} {mode} crossed source gate: {denied.returncode}, {denied.stderr}")
        print(f"two-site {tag} {args.optimization} compiler, linked image and runtime pass")


def split_root_cases(args, directory, configuration, requests, source, core, includes):
    measured_root = bytes(range(32, 64))
    policy = private_input()
    policy["root_scheme"] = "provider-split-v1"
    policy["measured_private_words"] = list(struct.unpack("<8I", measured_root))
    private = directory / "provider-split.private.json"
    private.write_text(json.dumps(policy))
    protected = directory / "provider-split.ll"
    report = directory / "provider-split.coverage.json"
    command = [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={configuration}", f"-pyobf-cff-requests-input={requests}"]
    run([*command, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
        "-verify-each", "-S", source, "-o", protected])
    row = check_report(json.loads(report.read_text()), policy)
    if row["runtime_contribution"]["private_input_sha256"] != hashlib.sha256(private.read_bytes()).hexdigest():
        raise AssertionError("provider-split compiler report lost the exact private input")
    for label, change, reason in (
            ("missing-scheme", lambda data: data.pop("root_scheme"), "provider-split root scheme"),
            ("missing-measured", lambda data: data.pop("measured_private_words"), "eight measured private words"),
            ("unknown-scheme", lambda data: data.update(root_scheme="unknown"), "provider-split root scheme"),
            ("short-measured", lambda data: data["measured_private_words"].pop(), "eight measured private words"),
            ("aliased-roots", lambda data: data.update(measured_private_words=data["private_words"]),
                "provider-split roots must be distinct")):
        changed = copy.deepcopy(policy); change(changed)
        candidate = directory / f"provider-split-{label}.json"
        candidate.write_text(json.dumps(changed))
        output = directory / f"provider-split-{label}.ll"
        failed = run([*command, f"-pyobf-cff-contribution-input={candidate}",
            "-S", source, "-o", output], succeeds=False)
        if output.exists() or reason not in failed.stderr:
            raise AssertionError(f"provider-split malformed root escaped: {label}: {failed.stderr}")
    old_material = directory / "provider-split-old-material.bin"
    old_material.write_bytes((directory / "material.bin").read_bytes())
    inputs = actual_subject(args, directory, material_root=measured_root)
    body = directory / "provider-split.obj"
    binary = directory / "provider-split.exe"
    run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", body])
    run([args.compiler, "-std=c++17", "-O2", body,
        ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
        "-lbcrypt", "-o", binary])
    checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
    final = directory / "provider-split.final.json"
    verify_image(checker, binary, report, final)
    check_policy_positive(checker, binary, report, private, final, directory, run)
    run([binary, *inputs, "normal", args.foreign_provider])
    wrong = list(inputs); wrong[2] = old_material
    denied = subprocess.run(list(map(str, [binary, *wrong, "normal", args.foreign_provider])),
        capture_output=True, text=True, timeout=15)
    if denied.returncode == 0 or "mixed site providers did not control both transitions" not in denied.stderr:
        raise AssertionError(f"old measured root reached provider-split body: {denied.returncode}, {denied.stderr}")
    swapped = copy.deepcopy(policy)
    swapped["private_words"], swapped["measured_private_words"] = (
        swapped["measured_private_words"], swapped["private_words"])
    swapped_private = directory / "provider-split-swapped.private.json"
    swapped_private.write_text(json.dumps(swapped))
    swapped_final = directory / "provider-split-swapped.final.json"
    refused = run([*checker, binary, report, "--contribution-input", swapped_private,
        "--output", swapped_final], succeeds=False)
    if swapped_final.exists() or "raw input SHA-256 differs" not in refused.stderr:
        raise AssertionError(f"swapped roots borrowed the compiler's final report: {refused.stderr}")
    swapped_ir = directory / "provider-split-swapped.ll"
    swapped_report = directory / "provider-split-swapped.coverage.json"
    run([*command, f"-pyobf-cff-contribution-input={swapped_private}",
        f"-pyobf-cff-report={swapped_report}", "-verify-each", "-S", source, "-o", swapped_ir])
    swapped_obj = directory / "provider-split-swapped.obj"
    swapped_binary = directory / "provider-split-swapped.exe"
    run([args.compiler, "-O0", "-fno-lto", "-c", swapped_ir, "-o", swapped_obj])
    run([args.compiler, "-std=c++17", "-O2", swapped_obj,
        ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
        "-lbcrypt", "-o", swapped_binary])
    denied = subprocess.run(list(map(str, [swapped_binary, *inputs, "normal", args.foreign_provider])),
        capture_output=True, text=True, timeout=15)
    if denied.returncode == 0:
        raise AssertionError("swapped provider roots reached the normal body result")
    print(f"provider-split source roots {args.optimization}: actual CNG positive, old-root and swapped-root refusals pass")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--split-root-only", action="store_true")
    for name in ("core", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    parser.add_argument("--foreign-provider", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="source-mixed-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        raw, requested, requests, optimized, protected, report, configuration, private = [
            directory / ("mixed-site." + suffix) for suffix in
            ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "config.json", "private.json")]
        configuration.write_text(json.dumps({"schema_version": 1, "functions": {"mixed_site_body": {
            "components": {"runtime-contribution": "required", "external-calls": "required"},
            "contribution": {"selection": "explicit-points"}}}}))
        policy = private_input(); private.write_text(json.dumps(policy))
        run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
            *includes, ROOT / "tests/contribution/source_mixed_body.cpp", "-o", raw])
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
            "-verify-each", "-S", raw, "-o", requested])
        source = requested
        if args.optimization == "O2":
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized]); source = optimized
        if args.split_root_only:
            core = list(dict.fromkeys([*args.core, *args.backend]))
            actual_subject(args, directory)
            split_root_cases(args, directory, configuration, requests, source, core, includes)
            return
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
            "-verify-each", "-S", source, "-o", protected])
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", protected])
        document = json.loads(report.read_text())
        check_report(document, policy)
        detached = negative_compiler(args, directory, source, requests, configuration, protected)
        forged_reports = []
        for label, mutation in (("site-provider", lambda p: p["sites"][0].update(provider="measured-scope-v1")),
                ("source-order", lambda p: p["sites"][0]["sources"].reverse()),
                ("source-provider", lambda p: p["sites"][0]["sources"][1].update(provider="owned-context-v1")),
                ("helper-count", lambda p: p["helper_counts"].update({"owned-context-v1": 2})),
                ("old-helper-contract", lambda p: p.pop("joint_helper_contract")),
                ("wrong-helper-contract", lambda p: p.update(joint_helper_contract="unknown")),
                ("false-owner-binding", lambda p: p.update(cross_provider_owner_binding_verified=True)),
                ("false-individual-proof", lambda p: p.update(individual_sites_verified=True)),
                ("forged-machine-flag", lambda p: p.update(joint_caller_pointer_provenance_verified=True)),
                ("forged-machine-scope", lambda p: p.update(joint_machine_scope="forged")),
                ("forged-original-acquisition", lambda p: p.update(acquisition="original-edges-and-explicit-points")),
                ("forged-original-edge-machine", lambda p: p.update(original_edge_machine={"verified": True}))):
            false = copy.deepcopy(document)
            proof = next(row["runtime_contribution"] for row in false["functions"] if row.get("function") == "mixed_site_body")
            mutation(proof)
            try: check_report(false, policy)
            except (AssertionError, SystemExit): pass
            else: raise AssertionError(f"independent private policy admitted forged mixed {label}")
            forged_reports.append((label, false))
        top_level_forgery = copy.deepcopy(document)
        next(row for row in top_level_forgery["functions"] if row.get("function") == "mixed_site_body")[
            "joint_caller_pointer_provenance_verified"] = True
        forged_reports.append(("forged-machine-top-level", top_level_forgery))
        protected_obj, plain_obj = directory / "protected.obj", directory / "plain.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", protected_obj])
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", plain_obj])
        core = list(dict.fromkeys([*args.core, *args.backend]))
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        inputs = actual_subject(args, directory)
        for kind, changed in detached.items():
            body, binary = directory / f"detached-{kind}.obj", directory / f"detached-{kind}.exe"
            run([args.compiler, "-O0", "-fno-lto", "-c", changed, "-o", body])
            run([args.compiler, "-std=c++17", "-O2", body,
                ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
                "-lbcrypt", "-o", binary])
            final = directory / f"detached-{kind}.final.json"
            refused = run([*checker, binary, report, "--output", final], succeeds=False)
            if final.exists() or "query return flow" not in refused.stderr:
                raise AssertionError(f"detached {kind} return escaped final proof: {refused.stderr}")
            print(f"detached {kind} final refusal: {refused.stderr.strip()}")
        actual = protected.read_text()
        transition = list(re.finditer(r"(?m)^  store i32 [^\n]+, ptr %pyobf\.state, align 4, !pyobf\.contribution\.transition !\d+\n", actual))
        if len(transition) != 1:
            raise AssertionError("source-mixed transition store was not unique")
        for width, reason in ((32, "query return flow"), (64, "overlapping stack write")):
            label = f"overwritten-state-{width}"
            overwritten = directory / f"{label}.ll"
            overwritten.write_text(actual[:transition[0].end()] +
                f"  store i{width} 0, ptr %pyobf.state, align 4\n" + actual[transition[0].end():])
            run([args.opt, "-passes=verify", "-disable-output", overwritten])
            overwritten_obj, overwritten_exe = directory / f"{label}.obj", directory / f"{label}.exe"
            run([args.compiler, "-O0", "-fno-lto", "-c", overwritten, "-o", overwritten_obj])
            run([args.compiler, "-std=c++17", "-O2", overwritten_obj,
                ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes, "-lbcrypt", "-o", overwritten_exe])
            overwritten_final = directory / f"{label}.final.json"
            overwritten_refusal = run([*checker, overwritten_exe, report, "--output", overwritten_final], succeeds=False)
            if overwritten_final.exists() or reason not in overwritten_refusal.stderr:
                raise AssertionError(f"{width}-bit overwrite escaped final proof: {overwritten_refusal.stderr}")
            print(f"{width}-bit overwritten state final refusal: {overwritten_refusal.stderr.strip()}")
        for variant, body, markers in (("protected", protected_obj, []),
                ("plain", plain_obj, [ROOT / "src/contribution/mixed_marker.cpp"])):
            binary = directory / f"{variant}.exe"
            run([args.compiler, "-std=c++17", "-O2", body,
                ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *markers, *includes,
                "-lbcrypt", "-o", binary])
            final = directory / f"{variant}.final.json"
            if variant == "protected":
                verify_image(checker, binary, report, final)
                check_policy_positive(checker, binary, report, private, final, directory, run, joint=True)
                linked = next(row["runtime_contribution"] for row in json.loads(final.read_text())["functions"]
                    if row.get("function") == "mixed_site_body")
                if linked.get("cross_provider_owner_binding_verified") is not False:
                    raise AssertionError("linked image overstated machine reference provenance")
                joint_final = directory / "protected.joint.final.json"
                verify_image([*checker, "--check-joint-caller-flow"], binary, report, joint_final)
                joint = next(row["runtime_contribution"] for row in json.loads(joint_final.read_text())["functions"]
                    if row.get("function") == "mixed_site_body")
                if (joint.get("cross_provider_owner_binding_verified") is not False or
                        joint.get("joint_caller_pointer_provenance_verified") is not False or
                        joint.get("joint_machine_scope") !=
                        "windows-x64-single-unwind-interval-caller-setup; helper-write-effects-unverified" or
                        joint.get("joint_return_routing_scope") !=
                        "bounded-syntactic-def-use; numerical-influence-unverified"):
                    raise AssertionError("linked joint caller diagnostic was absent or overstated")
                check_linked_mutations(checker, binary, report, directory, args.objdump, run)
                for label, false in forged_reports:
                    forged = directory / f"forged-{label}.json"; forged.write_text(json.dumps(false))
                    output = directory / f"forged-{label}.final.json"
                    refused = run([*checker, binary, forged, "--output", output], succeeds=False)
                    if label == "source-order" and "provider order" not in refused.stderr:
                        raise AssertionError(f"linked provider ordering did not reject reordered evidence: {refused.stderr}")
                    if output.exists(): raise AssertionError(f"final gate accepted forged schema4 {label}")
                    if label.startswith("forged-machine") or label in ("old-helper-contract", "wrong-helper-contract"):
                        opted = directory / f"forged-{label}.joint.final.json"
                        run([*checker, binary, forged, "--check-joint-caller-flow",
                             "--output", opted], succeeds=False)
                        if opted.exists(): raise AssertionError(f"opt-in gate accepted forged {label}")
                print("protected source-mixed final image accepted; forged reports refused")
            else:
                run([*checker, binary, report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain mixed body borrowed protected final evidence")
            if variant == "protected": run([binary, *inputs, "normal", args.foreign_provider])
            for mode in ("wrong-owned", "same-generation-foreign", "empty-owned", "closed-owned",
                    "rebound-owned", "wrong-measured", "bad-snapshot", "bad-material"):
                denied = subprocess.run(list(map(str, [binary, *inputs, mode, args.foreign_provider])), capture_output=True, text=True, timeout=15)
                code = denied.returncode & 0xffffffff
                if variant == "plain" and code != 91:
                    raise AssertionError(f"plain {mode} did not reach its effect: {code}, {denied.stderr}")
                if variant == "protected" and code != 0xe04f0702:
                    raise AssertionError(f"protected {mode} crossed its source gate: {code}, {denied.stderr}")
                if variant == "protected": print(f"protected {mode} exit: 0x{code:08x}")
        two_site_cases(args, directory, configuration, checker, inputs, core, includes)
        print(f"source-mixed site {args.optimization} actual CNG/context, runtime refusals and final image pass")


if __name__ == "__main__": main()
