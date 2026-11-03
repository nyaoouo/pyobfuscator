"""Bounded exact-PE proof for three to eight planned schema4 successor edges."""

import hashlib
import json
import re

from cff_contribution_policy import check_source_mixed_private_policy
from cff_source_mixed_bounded_site_map import check_bounded_site_map
from cff_joint_machine_evidence import MEASURED, OWNED


def _invalid(reason):
    raise ValueError(f"source-mixed original edges: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON key")
        result[key] = value
    return result


def _document(raw, name):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _invalid("nonfinite JSON value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"source-mixed original edges: invalid {name} JSON") from error


def _number(value, minimum=0):
    return type(value) is int and minimum <= value <= 0xffffffff


def _plan(raw, owner, recipe):
    plan = _document(raw, "frozen plan")
    if (type(plan) is not dict or set(plan) != {"schema_version", "profile", "owners",
            "input_ir_encoding", "input_ir_sha256"} or
            type(plan["schema_version"]) is not int or plan["schema_version"] != 2 or
            plan["profile"] != "schema4-original-edges-bounded-v2" or
            type(plan["owners"]) is not list or len(plan["owners"]) != 1 or
            plan["input_ir_encoding"] != "llvm-module-print-v1" or
            type(plan["input_ir_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", plan["input_ir_sha256"]) is None):
        _invalid("frozen plan identity, recipe or retained IR is unsupported")
    item = plan["owners"][0]
    if (type(item) is not dict or set(item) != {"owner", "recipe", "edges"} or
            item["owner"] != owner or item["recipe"] != recipe):
        _invalid("frozen plan owner or recipe differs from compiler report")
    edges = item["edges"]
    if type(edges) is not list or not 3 <= len(edges) <= 8:
        _invalid("frozen plan needs three to eight ordered edges")
    labels = set()
    ids = set()
    for edge in edges:
        if (type(edge) is not dict or set(edge) != {"id", "label", "successor_index"} or
                type(edge["id"]) is not str or not edge["id"] or
                not _number(edge["label"], 1) or
                type(edge["successor_index"]) is not int or
                not 0 <= edge["successor_index"] <= 1 or
                edge["id"] in ids or edge["label"] in labels):
            _invalid("frozen plan edge identities are not distinct normal successors")
        ids.add(edge["id"])
        labels.add(edge["label"])
    return edges


def check_source_mixed_bounded_edges(image, code, row, report, private, plan, helper_codes):
    if type(helper_codes) is not dict or set(helper_codes) != {OWNED, MEASURED}:
        _invalid("exact linked helper bodies are required")
    document = _document(report, "compiler report")
    plan_sha256 = hashlib.sha256(plan).hexdigest()
    if (type(document) is not dict or
            type(document.get("original_edge_plan_sha256")) is not str or
            document["original_edge_plan_sha256"] != plan_sha256):
        _invalid("plan bytes differ from the compiler-verified frozen input")
    functions = document.get("functions") if type(document) is dict else None
    if type(row) is not dict or type(functions) is not list or row not in functions:
        _invalid("selected row differs from raw compiler report")
    selected = [item for item in functions if type(item) is dict and item.get("selected") is True]
    if len(selected) != 1 or selected[0] != row or row.get("status") != "transformed":
        _invalid("requires exactly one transformed selected owner")
    owner = row.get("function")
    recipe = row.get("effective_recipe")
    proof = row.get("runtime_contribution")
    if (type(owner) is not str or not owner or type(recipe) is not dict or
            recipe.get("strategy") != "relative-tree" or recipe.get("coverage") != "whole" or
            recipe.get("contribution") != {"selection": "original-edges", "minimum_edges": 3,
                                           "maximum_edges": 8, "minimum_percent": 100} or
            row.get("strategy") != "relative-tree" or row.get("coverage_kind") != "decision-flow" or
            row.get("hybrid_eh") or row.get("region_flow_contract_verified") or
            type(proof) is not dict or proof.get("scheme_version") != 4 or
            proof.get("provider") != "source-mixed-v1" or
            proof.get("acquisition") != "original-edges-and-explicit-points" or
            proof.get("joint_helper_contract") != "source-mixed-context-v1" or
            proof.get("ir_binding_contract_verified") is not True or
            proof.get("source_subset_contract_verified") is not True or
            proof.get("cross_provider_owner_binding_verified") is not False or
            proof.get("generated_owner_independence_verified") is not False or
            proof.get("individual_sites_verified") is not False):
        _invalid("owner scope or conservative binding boundary differs from frozen profile")
    planned = _plan(plan, owner, recipe)
    private_identity = check_source_mixed_private_policy(private, document, maximum_sites=8)
    if private_identity.owner != owner:
        _invalid("private owner differs from frozen plan")
    edges = proof.get("original_edges")
    count = len(planned)
    if (type(edges) is not dict or
            edges.get("basis") != "retained-cff-input-normal-successor-edges" or
            any(type(edges.get(key)) is not int or edges[key] != value for key, value in {
                "original_edges": count, "selected_edges": count, "bound_edges": count,
                "physical_selected_edges": count, "coalesced_selected_edges": 0,
                "explicit_points": 0, "minimum_edges": 3, "maximum_edges": 8,
                "minimum_percent": 100, "excluded_unwind_edges": 0,
                "generated_edges_in_denominator": 0}.items()) or
            type(edges.get("density_percent")) is not int or edges["density_percent"] != 100 or
            edges.get("density_verified") is not True or
            edges.get("alias_contract_verified") is not True or
            proof.get("original_real_edge_density_verified") is not True):
        _invalid("reported original-edge selection is not full bounded coverage")
    actual = edges.get("edges")
    if type(actual) is not list or len(actual) != count:
        _invalid("reported edge inventory differs from frozen plan")
    states = []
    for expected, edge in zip(planned, actual):
        if (type(edge) is not dict or edge.get("id") != expected["id"] or
                edge.get("canonical") != expected["id"] or
                type(edge.get("point")) is not int or edge["point"] != expected["label"] or
                type(edge.get("canonical_point")) is not int or
                edge["canonical_point"] != expected["label"] or
                type(edge.get("successor")) is not int or
                edge["successor"] != expected["successor_index"] or
                not _number(edge.get("dispatch_state")) or
                edge.get("selected") is not True or edge.get("status") != "bound"):
            _invalid("reported successor identity or generated site differs from frozen plan")
        states.append(edge["dispatch_state"])
    if len(set(states)) != count:
        _invalid("reported original edges share one dispatch state")
    sites = proof.get("sites")
    if (type(sites) is not list or len(sites) != count or
            [site.get("label") for site in sites] != sorted(edge["label"] for edge in planned)):
        _invalid("private source sites differ from planned edge labels")
    owned_subsets = []
    for site in sites:
        sources = site.get("sources")
        if type(sources) is not list:
            _invalid("site has no source group")
        owned = tuple(source.get("id") for source in sources
                      if type(source) is dict and source.get("provider") == "owned-context-v1")
        measured = [source for source in sources if type(source) is dict and
                    source.get("provider") == "measured-scope-v1"]
        if not owned or len(measured) != 1 or len(owned) + len(measured) != len(sources):
            _invalid("each edge needs owned material and one measured source")
        owned_subsets.append(owned)
    if len(set(owned_subsets)) != count:
        _invalid("planned edges reuse one owned source subset")
    component = next((item for item in row.get("components", [])
                      if item.get("component") == "runtime-contribution"), None)
    if (component is None or type(component.get("applied")) is not int or
            component["applied"] != count or type(proof.get("query_count")) is not int or
            proof["query_count"] != sum(len(site["sources"]) for site in sites)):
        _invalid("compiler contribution count differs from planned edges")
    # Decode the supplied PE and prove every ordered helper group feeds the
    # dispatcher. The outer finalizer separately checks the private ABI and
    # the linked helper writes and routes.
    intervals = check_bounded_site_map(code, proof, owner, image, helper_codes=helper_codes)
    for expected, state in zip(planned, states):
        matches = [label for lower, upper, label in intervals if lower <= state < upper]
        if matches != [expected["label"]]:
            _invalid("planned original edge state reaches a different linked helper group")
    return {"verified": True, "profile": "schema4-original-edges-bounded-v2",
            "planned_edges": count, "selected_edges": count, "bound_edges": count,
            "plan_sha256": plan_sha256}
