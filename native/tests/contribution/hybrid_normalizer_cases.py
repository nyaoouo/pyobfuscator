"""Real EH semantics with authored duplicate work and pre-request return variants."""
import json
import re

from edge_policies import function_body
from preparation_cases import alternate
from cff_build import run, verify_image


NORMALIZERS = ("common-exit", "deduplicate-blocks", "split-blocks")


def configure_hybrid_normalizers(args, configuration):
    if not args.hybrid_normalizers:
        return ()
    selected = NORMALIZERS if args.hybrid_normalizers == "all" else (args.hybrid_normalizers,)
    config = json.loads(configuration.read_text())
    owner = config["functions"]["contribution_hybrid"]
    owner["components"].update({name: "optional" if args.optimization == "O2" else "required" for name in selected})
    if "split-blocks" in selected:
        owner.setdefault("budgets", {})["max_block_instructions"] = 2
    configuration.write_text(json.dumps(config))
    return selected


def prepare_hybrid_normalizer_input(path):
    text = path.read_text()
    body = function_body(text, "contribution_hybrid")
    value = re.findall(r"%[-\w.$]+", body.splitlines()[0])[-1]
    # Clang's O0 return funnel is valid but cannot exercise common-exit. These are
    # authored, executed return variants, collected before source optimization.
    changed, count = re.subn(r"(?m)^  ret i32 ([^\s,]+)\s*$", lambda match: (
        f"  %normalizer.choice = icmp eq i32 {value}, 0\n"
        "  br i1 %normalizer.choice, label %normalizer.return.a, label %normalizer.return.b\n"
        f"normalizer.return.a:\n  ret i32 {match[1]}\n"
        f"normalizer.return.b:\n  %normalizer.result = add i32 {match[1]}, 0\n"
        "  ret i32 %normalizer.result"), body)
    if count != 1:
        raise AssertionError("actual hybrid frontend fixture no longer has exactly one return funnel")
    path.write_text(text.replace(body, changed, 1))


def check_hybrid_normalizers(rows, selected, optimization, source):
    row = next(row for row in rows if row["function"] == "contribution_hybrid")
    components = {item["component"]: item for item in row["components"]}
    for name in selected:
        item = components[name]
        if (optimization == "none" or name == "split-blocks") and not item["applied"]:
            raise AssertionError("actual hybrid normalization lacks " + name)
        if item["unsupported"]:
            raise AssertionError("actual hybrid normalization has unsupported requests: " + name)
    if not row.get("hybrid_eh", {}).get("ir_flow_graph_verified"):
        raise AssertionError("hybrid normalizers escaped the original EH flow proof")
    if optimization == "none" and "deduplicate-blocks" in selected:
        proof = row["runtime_contribution"]
        if proof.get("original_edges"):
            check_hybrid_aliases(row, source)


def check_hybrid_aliases(row, source):
    text = source.read_text(); body = function_body(text, "contribution_hybrid")
    entries = row["runtime_contribution"]["original_edges"]["edges"]
    pair = []
    for name in ("if.then", "if.else"):
        block = re.search(r"(?ms)^" + re.escape(name) + r":[^\n]*\n(.*?)(?=^[\w.$]+:|^})", body)[1]
        marker = re.search(r"(?m)^\s+br\b[^\n]*!pyobf\.cff\.site !(\d+)", block)[1]
        identity = re.search(r"(?m)^!" + marker + r' = !\{!"([^"]+)"\}', text)[1]
        pair.append(next(edge for edge in entries if edge["id"].startswith(identity + ":instance:")))
    if pair[0]["canonical"] != pair[0]["id"] or pair[1]["canonical"] != pair[0]["id"]:
        raise AssertionError("hybrid alias map differs from its actual authored duplicate pair")
    print("actual hybrid duplicate pair retains original identities and one physical acquisition")


def hybrid_normalizer_limits(args, directory, transform, private, configuration, source, rows, checker, build_image):
    row = next(row for row in rows if row["function"] == "contribution_hybrid")
    body = function_body(source.read_text(), "contribution_hybrid")
    invokes = len(re.findall(r"(?m)^[ \t]+(?:%[^=\n]+ = )?invoke\b", body))
    pads = len(re.findall(r"(?m)^[ \t]+%[^=\n]+ = landingpad\b", body))
    if invokes != 1 or pads != 1 or re.search(r"(?m)^[ \t]+switch\b", body):
        raise AssertionError("hybrid exact-budget fixture lost its single invoke/pad and branch-only shape")
    # The reported pre-EH normal form is cross-checked against actual compilation:
    # one normal gateway plus one pad continuation; one less must refuse output.
    maximum = row["site_totals"]["normalized_blocks"] + invokes + pads
    recipe = json.loads(configuration.read_text())
    recipe["functions"]["contribution_hybrid"]["budgets"]["max_body_blocks"] = maximum
    output, _ = alternate(args, directory, transform, private, recipe, "hybrid-exact-budget")
    image = build_image("hybrid-exact-budget", output)
    if "gate-normal-completed" not in run([image]).stdout:
        raise AssertionError("exact hybrid normalizer body budget changed runtime semantics")
    verify_image(checker, image, directory / "hybrid-exact-budget.report.json", directory / "hybrid-exact-budget.final.json")
    recipe["functions"]["contribution_hybrid"]["budgets"]["max_body_blocks"] -= 1
    config_path, report, failed = [directory / ("hybrid-short-budget" + suffix) for suffix in (".json", ".report.json", ".ll")]
    config_path.write_text(json.dumps(recipe))
    command = [f"-pyobf-cff-config={config_path}" if str(arg).startswith("-pyobf-cff-config=") else arg for arg in transform]
    result = run([*command, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-o", failed], succeeds=False)
    reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
    if failed.exists() or "max_body_blocks" not in result.stderr + "\n".join(reasons):
        raise AssertionError("short hybrid normalizer budget failed outside actual body growth")
    print(f"actual hybrid normalizer body budget {maximum}/{maximum - 1} independently accepts/refuses compilation")
