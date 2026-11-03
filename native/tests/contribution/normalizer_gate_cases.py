"""Actual whole-function normalization composed with the existing source gate driver."""
import json
import re

from edge_policies import function_body
from cff_build import run


NORMALIZERS = ("common-exit", "deduplicate-blocks", "split-blocks")


def configure_normalizer_gates(args, configuration):
    if not args.normalizers:
        return ()
    selected = NORMALIZERS if args.normalizers == "all" else (args.normalizers,)
    config = json.loads(configuration.read_text())
    owner = config["functions"]["contribution_compute"]
    owner["components"].update({name: "optional" if args.optimization == "O2" else "required" for name in selected})
    if "split-blocks" in selected:
        owner.setdefault("budgets", {})["max_block_instructions"] = 2
    configuration.write_text(json.dumps(config))
    return selected


def check_normalizer_gates(rows, selected, optimization, source):
    row = next(row for row in rows if row["function"] == "contribution_compute")
    components = {item["component"]: item for item in row["components"]}
    for name in selected:
        item = components[name]
        if (optimization == "none" or name == "split-blocks") and item["applied"] == 0:
            raise AssertionError("retained normalizer/source composition lacks " + name)
        if item["unsupported"]:
            raise AssertionError("normalizer/source composition contains unsupported requests: " + name)
    if optimization == "none" and "split-blocks" in selected:
        # In the fixed source fixture, mul plus an ordinary call fill the two-work
        # budget. The closed point descriptor must not shift that cut from %h.
        text = source.read_text()
        body = function_body(text, "contribution_compute")
        marker = re.search(r"(?m)^\s+%h = xor [^\n]+!pyobf\.cff\.site !(\d+)", body)
        if marker is None:
            raise AssertionError("normalizer fixture lost its independently named cut")
        identity = re.search(r"(?m)^!" + marker[1] + r' = !\{!"([^"]+)"\}', text)[1]
        sites = components["split-blocks"]["sites"]
        site = next(site for site in sites if site["id"] == identity + ":split-blocks:0")
        if site["status"] != "applied":
            raise AssertionError("closed descriptor or ordinary call shifted the required split boundary")
    if optimization == "none" and "deduplicate-blocks" in selected and row["runtime_contribution"].get("original_edges"):
        check_normalizer_aliases(row, source)


def check_normalizer_aliases(row, source, *, shape="branch"):
    proof = row["runtime_contribution"]
    edges = proof["original_edges"]
    # Fixed source fixtures supply successor/point counts and safe duplicate pairs;
    # these expectations do not come from the report under test.
    actual = tuple(edges[name] for name in ("original_edges", "selected_edges", "bound_edges",
        "physical_selected_edges", "coalesced_selected_edges", "explicit_points"))
    total, physical, coalesced, dedup = {"branch": (6, 5, 1, 1), "return": (8, 7, 1, 2),
        "switch": (10, 7, 3, 1)}[shape]
    if actual != (total, total, total, physical, coalesced, 3):
        raise AssertionError("normalizer aliases changed original density or physical acquisition counts")
    components = {item["component"]: item for item in row["components"]}
    points = physical + 3
    if components["deduplicate-blocks"]["applied"] != dedup or \
            components["runtime-contribution"]["applied"] != points or \
            proof.get("query_count", points) != (physical * 2 + 5 if proof["scheme_version"] == 2 else points):
        raise AssertionError("normalizer aliases lost independently expected point/member queries")
    text = source.read_text(); body = function_body(text, "contribution_compute")
    pair = []
    for name in ("duplicate.a", "duplicate.b"):
        block = re.search(r"(?ms)^" + re.escape(name) + r":[^\n]*\n(.*?)(?=^[\w.$]+:|^})", body)[1]
        marker = re.search(r"(?ms)^\s+(?:br\b[^\n]*|switch\b.*?\])[^\n]*!pyobf\.cff\.site !(\d+)", block)[1]
        identity = re.search(r"(?m)^!" + marker + r' = !\{!"([^"]+)"\}', text)[1]
        pair.append({edge["successor"]: edge["id"] for edge in edges["edges"] if edge["id"].startswith(identity + ":instance:")})
    expected = {identity: pair[0][successor] for successor, identity in pair[1].items()}
    for edge in edges["edges"]:
        if edge["canonical"] != expected.get(edge["id"], edge["id"]):
            raise AssertionError("normalizer canonical map differs from the actual source duplicate pair")
    print(f"{total} original edges/{physical} physical acquisitions/{coalesced} exact {shape} aliases/{points} points verified")


def normalizer_loss_refusals(args, directory, transform, private, configuration, rows, *, owner_name="contribution_compute", selected=NORMALIZERS):
    config = json.loads(configuration.read_text())
    owner = next(row for row in rows if row["function"] == owner_name)
    lost = [item["component"] for item in owner["components"]
            if item["component"] in selected and item["optimized_away"]]
    for name in lost:
        changed = json.loads(json.dumps(config))
        changed["functions"][owner_name]["components"][name] = "required"
        recipe, report, output = [directory / ("strict-normalizer-" + name + suffix)
                                  for suffix in (".json", ".report.json", ".ll")]
        recipe.write_text(json.dumps(changed))
        command = [f"-pyobf-cff-config={recipe}" if str(arg).startswith("-pyobf-cff-config=") else arg for arg in transform]
        result = run([*command, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-o", output], succeeds=False)
        reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
        if "requested site did not survive ordinary optimization" not in result.stderr + "\n".join(reasons):
            raise AssertionError("required normalizer loss failed outside its original-request boundary: " + name)
        if output.exists() and output.stat().st_size:
            raise AssertionError("required normalizer loss emitted usable protected IR")
    return len(lost)
