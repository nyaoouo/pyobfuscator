"""Original-alias compatibility, physical budgets and unsafe-donor controls."""
import copy
import json
from pathlib import Path

from cff_build import run, verify_image
from normalizer_gate_cases import check_normalizer_aliases
from edge_policies import function_body
from cff_contribution_evidence import check_original_edge_evidence
from preparation_cases import alternate


def alias_acceptance(args, directory, transform, private, configuration, source, combined, rows, checker, build_image):
    config, inputs = (json.loads(path.read_text()) for path in (configuration, private))
    owner = "contribution_compute"
    row = next(row for row in rows if row["function"] == owner)
    entries = row["runtime_contribution"]["original_edges"]["edges"]
    donor = next(edge for edge in entries if edge["canonical"] != edge["id"])
    leader = next(edge for edge in entries if edge["id"] == donor["canonical"])
    positives = negatives = 0

    def accept(label, recipe, data, *, selected=6, skipped=False, shape="branch", pipeline=None, retained=None):
        nonlocal positives
        reference = directory / (label + ".private.json"); reference.write_text(json.dumps(data))
        output, report = alternate(args, directory, transform if pipeline is None else pipeline, reference, recipe, label)
        actual = next(row for row in report["functions"] if row["function"] == owner)
        if skipped or selected == 0:
            proof = actual["runtime_contribution"]; edges = proof["original_edges"]
            counts = tuple(edges[name] for name in ("original_edges", "selected_edges", "bound_edges",
                "physical_selected_edges", "coalesced_selected_edges", "explicit_points"))
            components = {item["component"]: item for item in actual["components"]}
            dedup = components["deduplicate-blocks"]
            queries = selected * 2 + 5 if args.grouped else selected + 3
            expected_dedup = (0, 1) if skipped else (1, 0)
            if counts != (6, selected, selected, selected, 0, 3) or (dedup["applied"], dedup["unsupported"]) != expected_dedup or \
                    components["runtime-contribution"]["applied"] != selected + 3 or proof.get("query_count", selected + 3) != queries or \
                    (skipped and any(edge["id"] != edge["canonical"] for edge in edges["edges"])):
                raise AssertionError("alias selection/skip changed original source coverage or normalizer accounting")
            if selected == 0 and {edge["id"]: edge["canonical"] for edge in edges["edges"]} != \
                    {edge["id"]: edge["canonical"] for edge in entries}:
                raise AssertionError("zero-selected normalization changed the independently expected duplicate pair")
        else:
            check_normalizer_aliases(actual, source if retained is None else retained, shape=shape)
        image = build_image(label, output)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("compatible alias changed reference results or effects")
        verify_image(checker, image, directory / (label + ".report.json"), directory / (label + ".final.json"))
        positives += 1

    def refuse(label, recipe, data, reason, text=None):
        nonlocal negatives
        config_path, reference, report, output = [directory / (label + suffix)
            for suffix in (".json", ".private.json", ".report.json", ".ll")]
        config_path.write_text(json.dumps(recipe)); reference.write_text(json.dumps(data))
        command = [f"-pyobf-cff-config={config_path}" if str(arg).startswith("-pyobf-cff-config=") else arg for arg in transform]
        if text is not None:
            changed = directory / (label + ".input.ll"); changed.write_text(text)
            run([args.opt, "-passes=verify", "-disable-output", changed])
            command = [changed if arg == source else arg for arg in command]
        result = run([*command, f"-pyobf-cff-contribution-input={reference}", f"-pyobf-cff-report={report}", "-o", output], succeeds=False)
        reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
        if reason not in result.stderr + "\n".join(reasons):
            raise AssertionError(f"alias refusal failed outside {reason}: {label}; {result.stderr[:600]}; {reasons}")
        if output.exists() and output.stat().st_size:
            raise AssertionError("incompatible original alias emitted usable IR: " + label)
        negatives += 1

    limit = 15 if args.grouped else 8
    budget = copy.deepcopy(config)
    budget["functions"][owner].setdefault("budgets", {})["max_contribution_sites"] = limit
    accept("alias-physical-budget", budget, inputs)
    budget["functions"][owner]["budgets"]["max_contribution_sites"] -= 1
    refuse("alias-short-budget", budget, inputs, "queries exceed max_contribution_sites")

    partial = copy.deepcopy(config)
    ordered = sorted(edge["point"] for edge in entries)
    cutoff = min(ordered.index(donor["point"]), ordered.index(leader["point"])) + 1
    partial["functions"][owner]["contribution"].update(minimum_edges=0, minimum_percent=0, maximum_edges=cutoff)
    refuse("alias-mixed-selection", partial, inputs, "merges selected and unselected original edges")
    optional = copy.deepcopy(partial)
    optional["functions"][owner]["components"]["deduplicate-blocks"] = "optional"
    accept("alias-optional-mixed-selection", optional, inputs, selected=cutoff, skipped=True)
    zero = copy.deepcopy(config)
    zero["functions"][owner]["contribution"].update(minimum_edges=0, minimum_percent=0, maximum_edges=0)
    accept("alias-zero-selected", zero, inputs, selected=0)

    # Recollect each distinct authored input: a removed return has no outgoing
    # original edge, while a duplicate switch contributes one alias per ordinal.
    for shape, fixture in (("return", "normalizer_terminal_fixture.ll"), ("switch", "normalizer_switch_fixture.ll")):
        label = "alias-" + shape
        recipe = copy.deepcopy(config)
        recipe["functions"][owner]["components"].update({"common-exit": "off", "split-blocks": "off"})
        raw = combined.read_text(); replacement = Path(__file__).with_name(fixture).read_text()
        raw = raw.replace(function_body(raw, owner), function_body(replacement, owner), 1)
        authored, requested, requests, recipe_path = [directory / (label + suffix)
            for suffix in (".authored.ll", ".requested.ll", ".requests.json", ".collect.json")]
        authored.write_text(raw); recipe_path.write_text(json.dumps(recipe))
        run([args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={recipe_path}",
            "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", authored, "-o", requested])
        pipeline = [f"-pyobf-cff-requests-input={requests}" if str(arg).startswith("-pyobf-cff-requests-input=")
            else requested if arg == source else arg for arg in transform]
        accept(label, recipe, inputs, shape=shape, pipeline=pipeline, retained=requested)

    if args.grouped:
        exact = copy.deepcopy(inputs)
        rules = exact["bindings"][owner]
        rules.setdefault("sites", {})[str(donor["point"])] = copy.deepcopy(rules["default"])
        accept("alias-compatible-exact-rule", config, exact)
        for label, operation in (
            ("order", lambda rule: rule["sources"].reverse()),
            ("subset", lambda rule: rule.update(sources=["alpha"])),
            ("domain", lambda rule: rule.update(mixing_domain="alias-other")),
            ("required-group", lambda rule: rule["groups"][0].update(minimum=2))):
            changed = copy.deepcopy(exact)
            operation(changed["bindings"][owner]["sites"][str(donor["point"])])
            refuse("alias-incompatible-" + label, config, changed, "merges incompatible ordered source policies")
            if label == "order":
                optional = copy.deepcopy(config)
                optional["functions"][owner]["components"]["deduplicate-blocks"] = "optional"
                accept("alias-optional-source-order", optional, changed, skipped=True)

    original = source.read_text()
    changed = original.replace("%d = add i32 %value, 7", "%d = add i32 %value, 8", 1)
    if changed == original: raise AssertionError("unsafe alias fixture lost its arithmetic donor")
    refuse("alias-different-arithmetic", config, inputs, "deduplicate-blocks", changed)
    changed = original
    for name in ("a", "d"):
        before = f"  %{name} = add i32 %value, 7"
        if changed.count(before) != 1: raise AssertionError("unsafe alias fixture lost its named block")
        changed = changed.replace(before, "  call void @contribution_alias_effect(i32 %value)\n" + before)
    changed += "\ndeclare void @contribution_alias_effect(i32) nounwind\n"
    refuse("alias-unsafe-calls", config, inputs, "deduplicate-blocks", changed)
    reports = alias_report_refusal(row, source)
    return positives, negatives, reports


def alias_report_refusal(row, source):
    changed = copy.deepcopy(row)
    proof = changed["runtime_contribution"]; entries = proof["original_edges"]["edges"]
    donor = next(edge for edge in entries if edge["id"] != edge["canonical"])
    leader = next(edge for edge in entries if edge["id"] == donor["canonical"])
    wrong = next(edge for edge in entries if edge["id"] not in (donor["id"], leader["id"]) and
        edge["successor"] == leader["successor"])
    donor.update(canonical=donor["id"], canonical_point=donor["point"])
    wrong.update(canonical=leader["id"], canonical_point=leader["point"])
    for site in proof.get("sites", []):
        if site["label"] == wrong["point"]: site["label"] = donor["point"]
    # Structural counters alone cannot prove which source blocks were equivalent.
    check_original_edge_evidence(proof, 8, row["function"])
    try: check_normalizer_aliases(changed, source)
    except AssertionError as error:
        if "actual source duplicate pair" not in str(error): raise
    else: raise AssertionError("internally consistent false alias map replaced independent source evidence")
    return 1
