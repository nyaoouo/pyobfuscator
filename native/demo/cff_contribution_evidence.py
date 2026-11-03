"""Scoped final presence for the owned-context contribution adapter."""
import re
import math
from cff_contribution_groups import check_contribution_groups
from cff_grouped_owned_flow import check_grouped_owned_query_flow
from cff_source_mixed_site_map import check_two_site_map


def check_measured_query_flow(code, helper, count, owner, kind="measured"):
    # The admitted Windows x64 lowering passes current state in stack argument 7.
    # Follow each returned word to a write of that same local state slot; merely
    # retaining the call and mask coefficients would accept a detached body.
    instructions = []
    for line in code.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2 or not re.match(r"^[0-9a-f]+:", parts[0]):
            continue
        instructions.append((parts[1].strip(), parts[2].split("#", 1)[0].strip() if len(parts) > 2 else ""))
    calls = [index for index, (op, operands) in enumerate(instructions)
        if op in ("call", "callq") and f"<{helper}>" in operands]
    if len(calls) != count:
        raise SystemExit(f"linked image lost {kind} query return flow: {owner}")
    register = re.compile(r"^%[a-z][a-z0-9]*$")
    stack = re.compile(r"^(?:0x[0-9a-f]+|-?\d+)\(%rsp\)$")
    for ordinal, index in enumerate(calls, 1):
        state = None
        for before in range(index - 1, max(-1, index - 17), -1):
            op, operands = instructions[before]
            if op.startswith(("j", "ret", "call")):
                break
            if op != "movl": continue
            source, sep, target = operands.partition(", ")
            if sep and target == "0x30(%rsp)" and register.fullmatch(source):
                for origin in range(before - 1, max(-1, before - 15), -1):
                    earlier, values = instructions[origin]
                    if earlier.startswith(("j", "ret", "call")):
                        break
                    operands_before = [value.strip() for value in values.split(",")]
                    if len(operands_before) > 1 and operands_before[-1] == source and not earlier.startswith("cmp"):
                        if earlier == "movl" and stack.fullmatch(operands_before[0]) and operands_before[0] != "0x30(%rsp)":
                            state = operands_before[0]
                        break
                break
        if state is None:
            raise SystemExit(f"linked image lost {kind} query state origin: {owner}")
        tainted = {"%eax"}
        reached = False
        for op, operands in instructions[index + 1:]:
            if op.startswith(("j", "ret", "call")) or op in ("ud2", "int3", "hlt"):
                break
            values = [value.strip() for value in operands.split(",")]
            if op == "movl" and len(values) == 2:
                source, target = values
                if target == state:
                    reached = source in tainted
                if register.fullmatch(target):
                    if source in tainted: tainted.add(target)
                    else: tainted.discard(target)
            elif op == "imull" and len(values) == 3 and register.fullmatch(values[-1]):
                source, target = values[1:]
                if source in tainted: tainted.add(target)
                else: tainted.discard(target)
            elif op in ("cmpl", "testl"):
                continue
            elif len(values) == 2 and register.fullmatch(values[-1]):
                source, target = values
                if ((op in ("xorl", "subl") and source == target) or
                        (op in ("andl", "imull") and source in ("$0x0", "$0"))):
                    tainted.discard(target)
                elif op in ("xorl", "addl", "subl", "orl", "andl", "imull") or op.startswith("cmov"):
                    if source in tainted: tainted.add(target)
                elif op not in ("shrl", "shll", "roll", "rorl"):
                    raise SystemExit(f"unsupported {kind} query register lowering: {owner}")
            elif len(values) == 2 and values[-1] == state:
                raise SystemExit(f"unsupported {kind} query state write: {owner}")
            else:
                raise SystemExit(f"unsupported {kind} query instruction lowering: {owner} {op} {operands}")
        if not reached:
            raise SystemExit(f"linked image lost {kind} query return flow: {owner} call{ordinal}")


def check_source_mixed_query_flow(code, providers, owner, joint=False):
    # The current CLANG64 lowering spills an earlier result before the next
    # helper call. Trace each return through that spill to the actual CFF
    # state slot; a call count or a stack-argument check alone is insufficient.
    instructions = []
    for line in code.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and re.match(r"^[0-9a-f]+:", parts[0]):
            instructions.append((parts[1].strip(), parts[2].split("#", 1)[0].strip() if len(parts) > 2 else ""))
    helpers = (("<pyobf_native_mixed_owned_contribution_word_v1>",
        "<pyobf_native_mixed_measured_contribution_word_v1>") if joint else
        ("<pyobf_native_contribution_word_v1>", "<pyobf_native_measured_contribution_word_v1>"))
    calls = [index for index, (op, operands) in enumerate(instructions)
        if op in ("call", "callq") and any(helper in operands for helper in helpers)]
    if len(calls) != len(providers):
        raise SystemExit(f"linked image lost source-mixed query return flow: {owner}")
    for index, provider in zip(calls, providers):
        helper = helpers[1] if provider == "measured-scope-v1" else helpers[0]
        if helper not in instructions[index][1]:
            raise SystemExit(f"linked image changed source-mixed provider order: {owner}")
    register = re.compile(r"^%[a-z][a-z0-9]*$")
    stack = re.compile(r"^(?:(0x[0-9a-f]+|-?\d+))?\(%rsp\)$")

    def span(value, width):
        match = stack.fullmatch(value)
        if match is None: return None
        offset = int(match[1], 16 if match[1].startswith("0x") else 10) if match[1] else 0
        return offset, offset + width

    def overlaps(left, right):
        return left[0] < right[1] and right[0] < left[1]

    def state_slot(index):
        local = None
        for before in range(index - 1, max(-1, index - 17), -1):
            op, operands = instructions[before]
            if op.startswith(("j", "ret", "call")): break
            source, sep, target = operands.partition(", ")
            if op == "movl" and sep and target == "0x30(%rsp)" and register.fullmatch(source):
                for origin in range(before - 1, max(-1, before - 15), -1):
                    earlier, values = instructions[origin]
                    if earlier.startswith(("j", "ret", "call")): break
                    first, comma, last = values.partition(", ")
                    if earlier == "movl" and comma and last == source and stack.fullmatch(first):
                        local = first
                        break
                break
        if local is None: return None
        for write in range(index - 1, max(-1, index - 35), -1):
            op, operands = instructions[write]
            if op.startswith(("j", "ret")) or (op in ("call", "callq") and
                    not any(helper in operands for helper in helpers)): break
            source, sep, target = operands.partition(", ")
            if op != "movl" or not sep or target != local or not register.fullmatch(source): continue
            for origin in range(write - 1, max(-1, write - 18), -1):
                earlier, values = instructions[origin]
                if earlier.startswith(("j", "ret", "call")): break
                first, comma, last = values.partition(", ")
                if earlier == "movl" and comma and last == source and stack.fullmatch(first) and first != local:
                    return first
            break
        return local

    state_slots = set()
    for ordinal, index in enumerate(calls, 1):
        state = state_slot(index)
        if state is None:
            raise SystemExit(f"linked image lost source-mixed query state origin: {owner} call{ordinal}")
        state_slots.add(state)
        state_range = span(state, 4)
        registers, slots = {"%eax"}, set()
        reached = False
        wrote_state = False
        dispatch = False
        for op, operands in instructions[index + 1:]:
            if op in ("jmp", "jmpq"):
                dispatch = True
                break
            if op.startswith(("j", "ret")) or op in ("ud2", "int3", "hlt"):
                raise SystemExit(f"unsupported source-mixed query terminator: {owner} {op}")
            if op in ("call", "callq"):
                if not any(helper in operands for helper in helpers):
                    raise SystemExit(f"unsupported source-mixed intervening call: {owner} {operands}")
                registers.clear()
                continue
            values = [value.strip() for value in operands.split(",")]
            if values and op not in ("cmpl", "testl"):
                target_range = span(values[-1], {"b": 1, "w": 2, "l": 4, "q": 8}.get(op[-1:], 8))
                if target_range is not None and any(overlaps(target_range, protected)
                        for protected in (state_range, *(span(slot, 4) for slot in slots))):
                    if op != "movl" or (values[-1] != state and values[-1] not in slots):
                        raise SystemExit(f"unsupported source-mixed overlapping stack write: {owner} {op} {operands}")
            if op == "movl" and len(values) == 2:
                source, target = values
                tainted = source in registers or source in slots
                if target == state:
                    reached = tainted
                    wrote_state = True
                    continue
                target_set = registers if register.fullmatch(target) else slots if stack.fullmatch(target) else None
                if target_set is None:
                    raise SystemExit(f"unsupported source-mixed query write: {owner} {op} {operands}")
                if tainted: target_set.add(target)
                else: target_set.discard(target)
            elif op == "movq" and len(values) == 2:
                aliases = {"%rax": "%eax", "%rcx": "%ecx", "%rdx": "%edx",
                    "%r8": "%r8d", "%r9": "%r9d", "%r10": "%r10d", "%r11": "%r11d"}
                source, target = values
                if aliases.get(source) in registers:
                    raise SystemExit(f"unsupported source-mixed query wide move: {owner} {operands}")
                if target in aliases: registers.discard(aliases[target])
            elif op in ("cmpl", "testl"):
                continue
            elif len(values) == 2 and register.fullmatch(values[-1]):
                source, target = values
                if (op in ("xorl", "subl") and source == target) or (op == "andl" and source in ("$0", "$0x0")) or (
                        op == "orl" and source in ("$0xffffffff", "$-1")):
                    registers.discard(target)
                elif op in ("xorl", "addl", "subl", "orl", "andl", "imull"):
                    if source in registers or source in slots: registers.add(target)
                elif op not in ("shrl", "shll", "roll", "rorl"):
                    raise SystemExit(f"unsupported source-mixed query register lowering: {owner} {op} {operands}")
            elif op == "imull" and len(values) == 3 and register.fullmatch(values[-1]):
                source, target = values[1:]
                if values[0] in ("$0", "$0x0"): registers.discard(target)
                elif source in registers: registers.add(target)
                else: registers.discard(target)
            else:
                raise SystemExit(f"unsupported source-mixed query instruction lowering: {owner} {op} {operands}")
        if not dispatch or not wrote_state or not reached:
            raise SystemExit(f"linked image lost source-mixed query return flow: {owner} call{ordinal}")
    if len(state_slots) != 1:
        raise SystemExit(f"source-mixed queries do not reach one state slot: {owner}")


def check_original_edge_evidence(proof, count, owner, allow_source_mixed_original=False):
    edges = proof.get("original_edges", {})
    fields = ("original_blocks", "original_edges", "selected_edges", "bound_edges", "explicit_points",
              "minimum_edges", "minimum_percent", "maximum_edges", "generated_edges_in_denominator", "excluded_unwind_edges",
              "physical_selected_edges", "coalesced_selected_edges")
    invalid = any(type(edges.get(field)) is not int or edges[field] < 0 for field in fields)
    if not invalid:
        total, selected = edges["original_edges"], edges["selected_edges"]
        entries = edges.get("edges", [])
        density = selected > 0 and total > 0
        expected_percent = 100.0 * selected / total if total else None
        percent = edges.get("density_percent")
        invalid = (edges.get("basis") not in ("retained-cff-input-normal-successor-edges", "retained-cff-input-region-normal-successor-edges") or
            edges["original_blocks"] == 0 or (edges["explicit_points"] == 0 and not allow_source_mixed_original) or edges["excluded_unwind_edges"] > edges["original_blocks"] or
            edges["minimum_percent"] > 100 or edges["generated_edges_in_denominator"] != 0 or
            edges["bound_edges"] != selected or selected != min(total, edges["maximum_edges"]) or
            selected < max(edges["minimum_edges"], (total * edges["minimum_percent"] + 99) // 100) or
            (total == 0 and edges["minimum_percent"] != 0) or count != edges["physical_selected_edges"] + edges["explicit_points"] or
            edges["physical_selected_edges"] > selected or
            edges["coalesced_selected_edges"] != selected - edges["physical_selected_edges"] or
            edges.get("alias_contract_verified") is not True or
            edges.get("density_verified") is not density or proof.get("original_real_edge_density_verified") is not density or
            (percent is not None if total == 0 else type(percent) not in (int, float) or not math.isfinite(percent) or abs(percent - expected_percent) > 1e-9) or
            not isinstance(entries, list) or len(entries) != total)
        if edges.get("basis") == "retained-cff-input-region-normal-successor-edges":
            invalid |= (type(edges.get("region_entry")) is not str or not edges["region_entry"] or
                type(edges.get("region_exit")) is not str or not edges["region_exit"] or edges["region_entry"] == edges["region_exit"])
        if not invalid:
            identities = [edge.get("id") for edge in entries if isinstance(edge, dict)]
            invalid = (len(identities) != total or any(type(identity) is not str or not identity for identity in identities) or
                len(set(identities)) != total or sum(edge.get("selected") is True for edge in entries) != selected or any(
                    type(edge.get("selected")) is not bool or type(edge.get("successor")) is not int or edge["successor"] < 0 or
                    edge.get("status") != ("bound" if edge["selected"] else "unselected") for edge in entries))
            if not invalid:
                by_id = {edge["id"]: edge for edge in entries}
                invalid = any(type(edge.get("point")) is not int or not 0 < edge["point"] <= 0xffffffff or
                    type(edge.get("canonical_point")) is not int or not 0 < edge["canonical_point"] <= 0xffffffff or
                    type(edge.get("canonical")) is not str or edge["canonical"] not in by_id for edge in entries)
                if not invalid:
                    invalid = len({edge["point"] for edge in entries}) != total
                    for edge in entries:
                        root = by_id[edge["canonical"]]
                        invalid |= (root["canonical"] != root["id"] or root["selected"] != edge["selected"] or
                            root["point"] != edge["canonical_point"] or root["successor"] != edge["successor"])
                    roots = {edge["canonical"] for edge in entries if edge["selected"]}
                    invalid |= len(roots) != edges["physical_selected_edges"]
                    if proof.get("scheme_version") == 2:
                        labels = {site.get("label") for site in proof.get("sites", [])}
                        invalid |= any(by_id[root]["point"] not in labels for root in roots)
                        invalid |= any(edge["selected"] and edge["canonical"] != edge["id"] and edge["point"] in labels for edge in entries)
    if invalid:
        raise SystemExit(f"owned contribution original-edge evidence is incomplete: {owner}")


def check_contribution_evidence(row, code, image_bytes=None, helper_codes=None,
                                allow_source_mixed_original=False,
                                allow_source_mixed_bounded=False):
    component = next((item for item in row.get("components", [])
                      if item["component"] == "runtime-contribution"), None)
    count = 0 if component is None else component["applied"]
    proof = row.get("runtime_contribution", {})
    if proof:
        selection = row.get("effective_recipe", {}).get("contribution", {}).get("selection")
        expected = {"explicit-points": "explicit-source-point", "original-edges": "original-edges-and-explicit-points"}.get(selection)
        if expected is None or proof.get("acquisition") != expected:
            raise SystemExit(f"owned contribution acquisition differs from its selected recipe: {row['function']}")
    queries = check_contribution_groups(proof, count, row["function"]) if proof.get("scheme_version") in (2, 3, 4) else count
    if not count:
        if proof.get("acquisition") == "original-edges-and-explicit-points":
            check_original_edge_evidence(proof, count, row["function"])
        return
    provider = proof.get("provider")
    if (proof.get("scheme_version") not in (1, 2, 3, 4) or provider not in ("owned-context-v1", "measured-scope-v1", "site-mixed-v1", "source-mixed-v1") or
            proof.get("acquisition") not in ("explicit-source-point", "original-edges-and-explicit-points") or proof.get("source_bits") != 32 or
            proof.get("ir_binding_contract_verified") is not True):
        raise SystemExit(f"owned contribution IR evidence is incomplete: {row['function']}")
    if provider == "site-mixed-v1" and (proof.get("scheme_version") != 3 or proof.get("acquisition") != "explicit-source-point"):
        raise SystemExit(f"mixed contribution acquisition is unsupported: {row['function']}")
    if provider == "source-mixed-v1" and (proof.get("scheme_version") != 4 or
            (proof.get("acquisition") != "explicit-source-point" and not (
                allow_source_mixed_original and
                proof.get("acquisition") == "original-edges-and-explicit-points"))):
        raise SystemExit(f"source-mixed contribution acquisition is unsupported: {row['function']}")
    if proof.get("acquisition") == "original-edges-and-explicit-points":
        check_original_edge_evidence(proof, count, row["function"], allow_source_mixed_original)
        edges = proof["original_edges"]
        regional = edges["basis"] == "retained-cff-input-region-normal-successor-edges"
        if regional != (row.get("strategy") == "relative-tree-region") or (regional and (
                row.get("region_flow_contract_verified") is not True or
                edges["region_entry"] != row.get("region_entry") or edges["region_exit"] != row.get("region_exit"))):
            raise SystemExit(f"owned contribution region evidence differs from selected scope: {row['function']}")
        if proof["original_edges"]["excluded_unwind_edges"] != row.get("hybrid_eh", {}).get("preserved_exceptional_edges", 0):
            raise SystemExit(f"owned contribution unwind exclusions differ from hybrid scope: {row['function']}")
    if provider == "measured-scope-v1" and (proof.get("operation_scope") != "function-invocation" or
            proof.get("evidence_bits") != 256 or
            proof.get("generated_owner_independence_verified") is not False):
        raise SystemExit(f"measured contribution scope evidence is incomplete: {row['function']}")
    helpers = {"owned-context-v1": "pyobf_native_contribution_word_v1",
        "measured-scope-v1": "pyobf_native_measured_contribution_word_v1"}
    joint = provider == "source-mixed-v1" and proof.get("joint_helper_contract") == "source-mixed-context-v1"
    if joint:
        helpers = {"owned-context-v1": "pyobf_native_mixed_owned_contribution_word_v1",
            "measured-scope-v1": "pyobf_native_mixed_measured_contribution_word_v1"}
    expected = proof["helper_counts"] if provider in ("site-mixed-v1", "source-mixed-v1") else {provider: queries}
    calls = 0
    for source_provider, total in expected.items():
        helper = helpers[source_provider]
        actual = len(re.findall(r"\bcallq?\s+[^\n]*<" + helper + r">", code))
        if actual != total:
            if provider not in ("site-mixed-v1", "source-mixed-v1"):
                raise SystemExit(f"linked image lost owned contribution query/mask presence: {row['function']}; calls{actual}/{total}")
            raise SystemExit(f"linked image lost {source_provider} contribution queries: {row['function']}")
        calls += actual
    transitions = row.get("site_totals", {}).get("transition_sites", 0)
    first = len(re.findall(r"\bimull\s+\$0x7feb352d\b", code))
    second = len(re.findall(r"\bimull\s+\$0x846ca68b\b", code))
    if calls != queries or first < transitions + queries or second < transitions + queries:
        raise SystemExit(f"linked image lost owned contribution query/mask presence: {row['function']}; calls{calls}/{count}, masks{first}/{second}, transitions{transitions}")
    if provider == "measured-scope-v1":
        check_measured_query_flow(code, helpers[provider], queries, row["function"])
    elif provider == "owned-context-v1" and proof["scheme_version"] == 1:
        check_measured_query_flow(code, helpers[provider], queries, row["function"], "owned")
    elif (provider == "owned-context-v1" and proof["scheme_version"] == 2 and
          row.get("strategy") == "relative-tree" and
          row.get("coverage_kind") in ("decision-flow", "shape-only")):
        check_grouped_owned_query_flow(code, proof, row["function"])
    elif provider == "source-mixed-v1":
        if len(proof["sites"]) == 2:
            recipe = row.get("effective_recipe", {})
            if (row.get("strategy") != "relative-tree" or recipe.get("coverage") != "whole" or
                    row.get("hybrid_eh") or row.get("region_flow_contract_verified")):
                raise SystemExit(f"source-mixed two-site needs whole relative-tree coverage: {row['function']}")
            if image_bytes is None:
                raise SystemExit(f"source-mixed linked site map needs image bytes: {row['function']}")
            if not isinstance(helper_codes, dict) or set(helper_codes) != set(helpers.values()):
                raise SystemExit(f"source-mixed linked helper inputs are incomplete: {row['function']}")
            check_two_site_map(code, proof, row["function"], image_bytes, helper_codes)
        elif not (allow_source_mixed_bounded and
                  proof["acquisition"] == "original-edges-and-explicit-points" and
                  3 <= len(proof["sites"]) <= 8):
            check_source_mixed_query_flow(code, [source["provider"] for site in proof["sites"]
                for source in site["sources"]], row["function"], joint)
    elif provider == "site-mixed-v1":
        for source_provider, total in expected.items():
            check_measured_query_flow(code, helpers[source_provider], total, row["function"],
                "measured" if source_provider == "measured-scope-v1" else "owned")
