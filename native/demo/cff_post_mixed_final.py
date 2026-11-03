"""Strict two-owner POST source binding in the final linked child image."""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_contribution_policy import PrivateArgumentIdentity, _groups, _seed, _source_catalog
from cff_joint_machine_evidence import MEASURED, OWNED
from cff_source_mixed_arguments import check_private_arguments
from cff_source_mixed_bounded_site_map import check_bounded_site_map
from payload_binding import OWNER, WRAPPER, _same_typed
from post_mixed_binding import _plan, mixed_private_reference
from release_material import parse_material


OWNERS = (OWNER, WRAPPER)


def _invalid(reason):
    raise ValueError(f"mixed POST final: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON key")
        result[key] = value
    return result


def _document(raw, name, limit):
    if type(raw) is not bytes or len(raw) > limit:
        _invalid(f"{name} must be bounded bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _invalid("nonfinite JSON value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"mixed POST final: invalid {name} JSON") from error


def _sites(private, owner):
    """Project the full two-owner private source table without narrowing its root."""
    catalog = _source_catalog(private)
    rules = private["bindings"][owner]["sites"]
    sites = []
    for index, label in enumerate(sorted(int(key) for key in rules)):
        rule = rules[str(label)]
        sources = []
        for name in rule["sources"]:
            _, word, group, provider = catalog[name]
            measured = provider == "measured-scope-v1"
            sources.append({"id": name, "word_label": word, "encoding": 1,
                            "group": group, "provider": provider, "provider_version": 1,
                            "class": "referenced-evidence" if measured else "authenticated-material",
                            "sharing": "owner-independent" if measured else "context-material",
                            "use": "required-binding"})
        sites.append({"index": index, "label": label,
                      "mixing_domain": rule["mixing_domain"],
                      "mixing_domain_tag": _seed(private["domain"], owner, rule["mixing_domain"]),
                      "provider": "source-mixed-v1", "provider_version": 1,
                      "sources": sources, "groups": _groups(rule, sources)})
    return sites


def _edges(row, planned, sites, plan_hash):
    owner = row["function"]
    recipe = row.get("effective_recipe")
    proof = row.get("runtime_contribution")
    if (row.get("selected") is not True or row.get("status") != "transformed" or
            row.get("strategy") != "relative-tree" or row.get("coverage_kind") != "decision-flow" or
            row.get("hybrid_eh") or row.get("region_flow_contract_verified") or
            not _same_typed(recipe, planned["recipe"]) or type(proof) is not dict or
            type(proof.get("scheme_version")) is not int or proof["scheme_version"] != 4 or
            proof.get("provider") != "source-mixed-v1" or
            proof.get("acquisition") != "original-edges-and-explicit-points" or
            proof.get("joint_helper_contract") != "source-mixed-context-v1" or
            proof.get("ir_binding_contract_verified") is not True or
            proof.get("source_subset_contract_verified") is not True or
            proof.get("cross_provider_owner_binding_verified") is not False or
            proof.get("generated_owner_independence_verified") is not False or
            proof.get("individual_sites_verified") is not False):
        _invalid(f"owner scope or recipe differs from the frozen profile: {owner}")
    if proof.get("private_input_sha256") != plan_hash["private"] or not _same_typed(proof.get("sites"), sites):
        _invalid(f"private source projection differs from raw report: {owner}")
    count = len(planned["edges"])
    if (type(proof.get("query_count")) is not int or
            proof["query_count"] != sum(len(site["sources"]) for site in sites) or
            not _same_typed(proof.get("helper_counts"), {
                "owned-context-v1": sum(len(site["sources"]) - 1 for site in sites),
                "measured-scope-v1": count})):
        _invalid(f"source query totals differ from private policy: {owner}")
    subsets = [tuple(source["id"] for source in site["sources"][:-1]) for site in sites]
    if len(set(subsets)) != count or any(not subset for subset in subsets):
        _invalid(f"planned edges reuse an owned source subset: {owner}")
    components = row.get("components")
    matches = [item for item in components if type(item) is dict and
               item.get("component") == "runtime-contribution"] if type(components) is list else []
    if len(matches) != 1 or type(matches[0].get("applied")) is not int or matches[0]["applied"] != count:
        _invalid(f"compiler contribution count differs from planned edges: {owner}")
    edges = proof.get("original_edges")
    fields = {"original_edges": count, "selected_edges": count, "bound_edges": count,
              "physical_selected_edges": count, "coalesced_selected_edges": 0,
              "explicit_points": 0, "minimum_edges": 3, "maximum_edges": 8,
              "minimum_percent": 100, "excluded_unwind_edges": 0,
              "generated_edges_in_denominator": 0, "density_percent": 100}
    if (type(edges) is not dict or
            edges.get("basis") != "retained-cff-input-normal-successor-edges" or
            any(type(edges.get(key)) is not int or edges[key] != value for key, value in fields.items()) or
            edges.get("density_verified") is not True or
            edges.get("alias_contract_verified") is not True or
            proof.get("original_real_edge_density_verified") is not True):
        _invalid(f"original-edge count or coverage differs from frozen plan: {owner}")
    actual = edges.get("edges")
    if type(actual) is not list or len(actual) != count:
        _invalid(f"reported edge inventory differs from frozen plan: {owner}")
    states = []
    for expected, edge in zip(planned["edges"], actual):
        if (type(edge) is not dict or edge.get("id") != expected["id"] or
                edge.get("canonical") != expected["id"] or
                type(edge.get("point")) is not int or edge["point"] != expected["label"] or
                type(edge.get("canonical_point")) is not int or
                edge["canonical_point"] != expected["label"] or
                type(edge.get("successor")) is not int or
                edge["successor"] != expected["successor_index"] or
                type(edge.get("dispatch_state")) is not int or
                not 0 <= edge["dispatch_state"] < 1 << 32 or
                edge.get("selected") is not True or edge.get("status") != "bound"):
            _invalid(f"reported successor identity differs from frozen plan: {owner}")
        states.append(edge["dispatch_state"])
    if len(set(states)) != count:
        _invalid(f"original edges share a dispatch state: {owner}")
    return proof, states


def verify_post_mixed_child(image: bytes, report: dict, report_bytes: bytes,
                            private_bytes: bytes, plan_bytes: bytes, material_bytes: bytes,
                            scoped_material: bytes, codes: dict[str, str],
                            helper_codes: dict[str, str]) -> dict[str, dict]:
    """Verify both frozen POST owners against the same raw report and linked PE."""
    if (type(image) is not bytes or not image or type(codes) is not dict or
            set(codes) != set(OWNERS) or any(type(code) is not str or not code for code in codes.values()) or
            type(helper_codes) is not dict or set(helper_codes) != {OWNED, MEASURED} or
            any(type(code) is not str or not code for code in helper_codes.values())):
        _invalid("linked child image and exact owner/helper disassembly are required")
    document = _document(report_bytes, "compiler report", 8 << 20)
    if not _same_typed(report, document) or type(document) is not dict:
        _invalid("supplied report differs from full raw compiler bytes")
    plan = _plan(plan_bytes)
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    if document.get("original_edge_plan_sha256") != plan_sha256:
        _invalid("plan bytes differ from compiler-verified frozen input")
    private = _document(private_bytes, "private input", 16384)
    if type(private) is not dict or type(private.get("routing_tag")) is not int:
        _invalid("private routing identity is invalid")
    expected = mixed_private_reference(parse_material(material_bytes), private["routing_tag"],
                                       scoped_material, plan_bytes)
    if not _same_typed(private, expected):
        _invalid("private roots, owners, labels or source subsets differ from early material and plan")
    functions = document.get("functions")
    if type(functions) is not list or any(type(row) is not dict for row in functions):
        _invalid("raw compiler function inventory is invalid")
    names = [row.get("function") for row in functions]
    if any(type(name) is not str or not name for name in names) or len(set(names)) != len(names):
        _invalid("compiler function names are missing or repeated")
    rows = {row["function"]: row for row in functions}
    if not set(OWNERS) <= set(rows):
        _invalid("raw compiler report is missing a planned owner")
    selected_mixed = [row["function"] for row in functions if row.get("selected") is True and
                      type(row.get("runtime_contribution")) is dict and
                      type(row["runtime_contribution"].get("scheme_version")) is int and
                      row["runtime_contribution"]["scheme_version"] == 4 and
                      row["runtime_contribution"].get("provider") == "source-mixed-v1"]
    if set(selected_mixed) != set(OWNERS) or len(selected_mixed) != 2:
        _invalid("selected source-mixed owner inventory differs from frozen plan")
    hashes = {"private": hashlib.sha256(private_bytes).hexdigest()}
    result = {}
    for planned in plan["owners"]:
        owner = planned["owner"]
        row = rows[owner]
        sites = _sites(private, owner)
        if [site["label"] for site in sites] != sorted(edge["label"] for edge in planned["edges"]):
            _invalid(f"private sites differ from frozen original edges: {owner}")
        proof, states = _edges(row, planned, sites, hashes)
        identity = PrivateArgumentIdentity(owner, private["routing_tag"],
                                           private["domain"], private["owners"][owner])
        try:
            check_private_arguments(image, codes[owner], row, identity)
            intervals = check_bounded_site_map(codes[owner], proof, owner, image,
                                               helper_codes=helper_codes)
        except SystemExit as error:
            raise ValueError(f"mixed POST final: linked machine proof failed: {error}") from error
        for expected_edge, state in zip(planned["edges"], states):
            matches = [label for lower, upper, label in intervals if lower <= state < upper]
            if matches != [expected_edge["label"]]:
                _invalid(f"planned original edge reaches a different linked helper group: {owner}")
        count = len(planned["edges"])
        result[owner] = {"verified": True, "plan_sha256": plan_sha256,
                         "planned_edges": count, "selected_edges": count, "bound_edges": count}
    return result
