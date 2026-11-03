"""Selected-region binding, outside-point, quota and final-evidence controls."""
import copy
import json
import re

from cff_build import run
from cff_contribution_evidence import check_contribution_evidence
from edge_policies import function_body, region_inventory


def region_acceptance(args, directory, source, protected, configuration, private, rows):
    original = source.read_text()
    config = json.loads(configuration.read_text())
    owner = "contribution_region"
    row = next(row for row in rows if row["function"] == owner)
    body = function_body(protected.read_text(), owner)
    count = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
    selected = row["runtime_contribution"].get("original_edges", {}).get("selected_edges", 0)
    if (row.get("region_flow_contract_verified") is not True or count != 3 + selected or
            body.count("call void @pyobf_native_contribution_site_v1") != 2 or
            body.count("call i32 @pyobf_native_contribution_word_v1") != row["runtime_contribution"].get("query_count", count)):
        raise AssertionError("outside points were bound or region query coverage differs from independent three-point source")

    def transform(index, text, recipe, expected=None):
        path, config_path, report, output = [directory / f"region-control-{index}{suffix}"
            for suffix in (".ll", ".json", ".report.json", ".out.ll")]
        path.write_text(text); config_path.write_text(json.dumps(recipe))
        run([args.opt, "-passes=verify", "-disable-output", path])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", "-verify-each",
            "-pyobf-cff-region=contribution_region:region.start:region.out", f"-pyobf-cff-config={config_path}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-S", path, "-o", output], succeeds=expected is None)
        if expected is not None:
            reasons = [item.get("reason", "") for item in json.loads(report.read_text())["functions"]] if report.exists() else []
            if expected not in result.stderr + "\n".join(reasons): raise AssertionError(f"region control failed elsewhere: {expected}; {reasons}")
            if output.exists() and output.stat().st_size: raise AssertionError("unsupported region emitted usable IR")
        else:
            return next(item for item in json.loads(report.read_text())["functions"] if item["function"] == owner)

    missing = re.sub(r"(?m)^  [^\n]*call void @pyobf_native_contribution_site_v1\([^\n]*i32 (?:noundef )?80[123]\)[^\n]*\n", "", original)
    if missing == original: raise AssertionError("region missing-source control did not remove markers")
    transform("outside-only", missing, config, "require a source marker" if args.automatic else "zero eligible required sites")
    source_body = function_body(original, owner)
    blocks, members = region_inventory(source_body, "region.start", "region.out")
    prefix = next(text for label, text in blocks.items() if label not in members and "br label %region.start" in text)
    bypass = original.replace(prefix, prefix.replace("br label %region.start", "br label %region.body", 1), 1)
    transform("bypass", bypass, config, "external entry into a body block")
    budget = copy.deepcopy(config)
    budget["functions"][owner]["contribution"] = {"selection": "original-edges", "maximum_edges": 0}
    transform("quota", original, budget, "cannot satisfy minimum count/density")
    exact = copy.deepcopy(config)
    query_budget = 3
    if args.grouped:
        inputs = json.loads(private.read_text())
        query_budget *= len(inputs["bindings"][owner]["default"]["sources"])
    exact["functions"][owner]["budgets"] = {"max_contribution_sites": query_budget}
    exact["functions"][owner]["contribution"] = {"selection": "original-edges", "minimum_edges": 0, "minimum_percent": 0, "maximum_edges": 0}
    accepted = transform("inside-only-budget", original, exact)
    edges = accepted["runtime_contribution"]["original_edges"]
    if edges["explicit_points"] != 3 or edges["selected_edges"] != 0 or edges["density_verified"]:
        raise AssertionError("outside markers inflated the three-query budget or zero density")

    # A source optimizer may erase a named region; it must be refused, never widened.
    erased = re.sub(r"(?m)^  [^\n]*call void @contribution_region_(?:anchor|entered|tick|positive|negative)\([^\n]*\n", "", original)
    raw, optimized = directory / "region-erased-source.ll", directory / "region-erased-optimized.ll"
    raw.write_text(erased)
    run([args.opt, "-passes=default<O2>", "-verify-each", "-S", raw, "-o", optimized])
    transform("erased-boundary", optimized.read_text(), config, "distinct existing named entry and exit blocks")

    if args.automatic:
        for field, value in (("region_flow_contract_verified", False), ("region_entry", "other"), ("strategy", "relative-tree")):
            changed = copy.deepcopy(row); changed[field] = value
            try: check_contribution_evidence(changed, "")
            except SystemExit as error:
                if "region evidence differs" not in str(error): raise AssertionError("region report mutation failed outside scope proof")
            else: raise AssertionError("false regional final evidence survived")
    return 5
