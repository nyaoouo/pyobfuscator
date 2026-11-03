"""Independent input-edge counts and bounded automatic-selection acceptance."""
import json
import math
import re

from cff_build import run
from cff_contribution_evidence import check_contribution_evidence, check_original_edge_evidence


def function_body(source, owner):
    return re.search(r"(?ms)^define [^\n]*@" + re.escape(owner) + r"\([^\n]+\).*?^}", source)[0]


def region_inventory(body, entry, exit):
    labels = list(re.finditer(r"(?m)^([A-Za-z0-9_.$-]+):[^\n]*\n", body))
    blocks = {label[1]: body[label.end():labels[index + 1].start() if index + 1 < len(labels) else len(body)]
              for index, label in enumerate(labels)}
    pending, selected = [entry], set()
    while pending:
        label = pending.pop()
        if label == exit or label in selected: continue
        if label not in blocks: raise AssertionError("selected input region boundary did not survive")
        selected.add(label)
        pending.extend(re.findall(r"\blabel\s+%([A-Za-z0-9_.$-]+)", blocks[label]))
    return blocks, selected


def selected_body(source, owner, entry=None, exit=None):
    body = function_body(source, owner)
    if entry is None: return body
    blocks, selected = region_inventory(body, entry, exit)
    return "\n".join(blocks[label] for label in sorted(selected))


def input_edge_count(source, owner, entry=None, exit=None):
    body = selected_body(source, owner, entry, exit)
    # These source fixtures admit only br/switch normal successors. Count every
    # successor operand, including parallel switch destinations, before CFF runs.
    invokes = len(re.findall(r"(?m)^[ \t]+(?:%[^=\n]+ = )?invoke\b", body))
    return invokes + sum(len(re.findall(r"\blabel\s+%", term)) for term in
                         re.findall(r"(?m)^[ \t]+(?:br\b[^\n]*|switch\b[^\[]*\[[^]]*\])", body))


def check_input_density(source, rows):
    for row in rows:
        proof = row.get("runtime_contribution", {})
        if proof.get("acquisition") != "original-edges-and-explicit-points": continue
        edges = proof["original_edges"]
        actual = input_edge_count(source, row["function"], row.get("region_entry"), row.get("region_exit"))
        if edges["original_edges"] != actual:
            raise AssertionError(f"density denominator differs from actual retained input successors: {row['function']}; {edges['original_edges']}/{actual}")
        body = selected_body(source, row["function"], row.get("region_entry"), row.get("region_exit"))
        if edges["excluded_unwind_edges"] != len(re.findall(r"(?m)^[ \t]+(?:%[^=\n]+ = )?invoke\b", body)):
            raise AssertionError("original unwind exclusions differ from actual input invokes")
        count = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
        check_original_edge_evidence(proof, count, row["function"])


def report_refusals(rows):
    row = next(row for row in rows if row["function"] == "contribution_compute")
    original = row["runtime_contribution"]
    count = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
    cases = [("bound_edges", 0), ("original_edges", 999), ("selected_edges", 0), ("explicit_points", 0),
             ("generated_edges_in_denominator", 1), ("density_percent", 0), ("density_percent", float("nan")), ("density_verified", False),
             ("minimum_percent", 101), ("maximum_edges", 0), ("basis", "generated-cfg"), ("edges", []),
             ("physical_selected_edges", original["original_edges"]["physical_selected_edges"] + 1),
             ("coalesced_selected_edges", original["original_edges"]["coalesced_selected_edges"] + 1),
             ("alias_contract_verified", False)]
    for field, value in cases:
        changed = json.loads(json.dumps(original)); changed["original_edges"][field] = value
        try: check_original_edge_evidence(changed, count, row["function"])
        except SystemExit: continue
        raise AssertionError(f"false original-edge final report accepted: {field}")
    maps = []
    for field, value in (("canonical", "absent"), ("canonical", 1), ("canonical_point", 0), ("point", 0)):
        changed = json.loads(json.dumps(original)); changed["original_edges"]["edges"][0][field] = value
        maps.append(changed)
    changed = json.loads(json.dumps(original)); entries = changed["original_edges"]["edges"]
    if len(entries) > 1:
        entries[1]["point"] = entries[0]["point"]
        maps.append(changed)
        changed = json.loads(json.dumps(original)); entries = changed["original_edges"]["edges"]
        entries[0]["canonical"], entries[-1]["canonical"] = entries[-1]["id"], entries[0]["id"]
        maps.append(changed)
    changed = json.loads(json.dumps(original))
    aliases = [edge for edge in changed["original_edges"]["edges"] if edge["id"] != edge["canonical"]]
    if aliases:
        aliases[0]["successor"] += 1; maps.append(changed)
    for changed in maps:
        try: check_original_edge_evidence(changed, count, row["function"])
        except SystemExit: continue
        raise AssertionError("false original-to-canonical alias report accepted")
    for alter_recipe in (False, True):
        changed = json.loads(json.dumps(row))
        if alter_recipe: changed["effective_recipe"]["contribution"]["selection"] = "explicit-points"
        else: changed["runtime_contribution"]["acquisition"] = "explicit-source-point"
        try: check_contribution_evidence(changed, "")
        except SystemExit as error:
            if "acquisition differs" not in str(error): raise AssertionError("source scope drift failed another gate") from error
        else: raise AssertionError("original-edge acquisition bypassed alias checks through scope drift")
    changed = json.loads(json.dumps(row))
    next(item for item in changed["components"] if item["component"] == "runtime-contribution")["applied"] = 0
    try: check_contribution_evidence(changed, "")
    except SystemExit: pass
    else: raise AssertionError("automatic coverage survived zero applied queries")
    changed = json.loads(json.dumps(row))
    changed["runtime_contribution"]["original_edges"]["excluded_unwind_edges"] = 1
    try: check_contribution_evidence(changed, "")
    except SystemExit as error:
        if "unwind exclusions differ" not in str(error): raise AssertionError("unwind refusal failed at another gate")
        return len(cases) + len(maps) + 4
    raise AssertionError("unwind exclusion escaped its actual hybrid scope")


def policy_acceptance(args, directory):
    source = '''declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
define i32 @edge_policy(ptr %lease, i32 %x) {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101) nounwind
  %condition = icmp slt i32 %x, 0
  br i1 %condition, label %left, label %right
left:
  %a = add i32 %x, 5
  br label %merge
right:
  %b = sub i32 %x, 3
  br label %merge
merge:
  %value = phi i32 [ %a, %left ], [ %b, %right ]
  ret i32 %value
}
'''
    private = directory / "policy.private.json"
    private.write_text(json.dumps({"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 7,
        "domain": 11, "source": 17, "private_words": list(range(1, 9)), "owners": {"edge_policy": 13}}))
    sequence = 0

    def transform(options, *, seed=17, extra=None, text=source, failure=None):
        nonlocal sequence
        sequence += 1
        prefix = directory / f"edge-policy-{sequence}"
        input_path, config, output, report = [prefix.with_suffix(suffix) for suffix in (".ll", ".json", ".out.ll", ".report.json")]
        input_path.write_text(text)
        run([args.opt, "-passes=verify", "-disable-output", input_path])
        owner = {"components": {"runtime-contribution": "required"}, "contribution": options}
        if extra: owner.update(extra)
        config.write_text(json.dumps({"schema_version": 1, "functions": {"edge_policy": owner}}))
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", "-verify-each",
            f"-pyobf-cff-config={config}", f"-pyobf-cff-seed={seed}", f"-pyobf-cff-contribution-input={private}",
            f"-pyobf-cff-report={report}", "-S", input_path, "-o", output], succeeds=failure is None)
        if failure is not None:
            if failure not in result.stderr: raise AssertionError(f"policy refusal failed elsewhere: {result.stderr}")
            if output.exists() and output.stat().st_size: raise AssertionError("refused automatic policy emitted usable IR")
            return None
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "edge_policy")
        if row["status"] != "transformed": raise AssertionError(row)
        check_input_density(text, [row])
        return row["runtime_contribution"]["original_edges"]

    partial = {"selection": "original-edges", "minimum_edges": 0, "minimum_percent": 0, "maximum_edges": 2}
    baseline = transform(partial)
    if (baseline["original_edges"], baseline["bound_edges"], baseline["density_percent"]) != (4, 2, 50):
        raise AssertionError("partial policy received full-density credit")
    selected = lambda row: {edge["id"] for edge in row["edges"] if edge["selected"]}
    if selected(transform(partial)) != selected(baseline): raise AssertionError("same seed did not reproduce selected edge identities")
    if len({tuple(sorted(selected(transform(partial, seed=seed)))) for seed in (1, 2, 3, 41)}) < 2:
        raise AssertionError("selection ignored build diversity")
    padded = transform(partial, extra={"budgets": {"min_blocks": 64, "max_block_instructions": 1},
                                       "components": {"runtime-contribution": "required", "split-blocks": "optional"}})
    if padded["original_edges"] != 4 or selected(padded) != selected(baseline):
        raise AssertionError("generated splitting/padding entered the original-edge denominator")
    for percent in (1, 25, 26, 50, 51, 100):
        amount = math.ceil(4 * percent / 100)
        row = transform({**partial, "minimum_percent": percent, "maximum_edges": amount})
        if row["bound_edges"] != amount: raise AssertionError("density ceiling was rounded down")
        transform({**partial, "minimum_percent": percent, "maximum_edges": amount - 1}, failure="cannot satisfy minimum count/density")
    transform({**partial, "minimum_edges": 3}, failure="cannot satisfy minimum count/density")
    transform({**partial, "maximum_edges": 4}, extra={"budgets": {"max_contribution_sites": 4}}, failure="exceed max_contribution_sites")
    zero = transform({**partial, "maximum_edges": 0})
    if zero["density_verified"] or zero["density_percent"] != 0: raise AssertionError("zero selected edges claimed density")
    no_edges = source[:source.index("  %condition")] + "  ret i32 %x\n}\n"
    transform({"selection": "original-edges"}, text=no_edges, failure="cannot satisfy minimum count/density")
    zero = transform({**partial, "maximum_edges": 0}, text=no_edges)
    if zero["density_verified"] or zero["density_percent"] is not None: raise AssertionError("empty denominator claimed density")
    two_sources = source.replace("ptr %lease, i32 %x", "ptr %lease, ptr %other, i32 %x").replace(
        "  %condition =", "  call void @pyobf_native_contribution_site_v1(ptr %other, i32 102) nounwind\n  %condition =")
    transform(partial, text=two_sources, failure="one canonical argument/global lease reference")
    mutable = source.replace("  call void", "  %slot = alloca ptr\n  store ptr %lease, ptr %slot\n  store ptr %lease, ptr %slot\n  %read = load ptr, ptr %slot\n  call void", 1)
    mutable = mutable.replace("site_v1(ptr %lease, i32 101)", "site_v1(ptr %read, i32 101)")
    transform(partial, text=mutable, failure="one canonical argument/global lease reference")
    for options in ([], {"unknown": 1}, {"selection": "all"}, {"minimum_edges": -1}, {"maximum_edges": 65537},
                    {"minimum_percent": 101}, {"minimum_percent": True}, {"minimum_edges": 1.5}):
        transform(options, failure="native contribution options:")
    return sequence
