"""Private ordinary-payload source references and strict package consistency."""
import hashlib
import json
import struct

from release_material import _object, _unique, material_fold, validate_material
from release_plan import expected_fold

OWNER = "pyobf_demo_bound_compute"
DOMAIN = 0x5041594c
OWNER_ID = 0x50415931
SOURCE = 0x4d415431
WRAPPER = "pyobf_demo_protection_wrapper"
WRAPPER_ID = 0x50415932


def _routing(value):
    if type(value) is not int or not 0 < value < 1 << 32:
        raise ValueError("payload binding needs a nonzero unsigned32 routing tag")
    return value


def private_reference(material, routing, *, scoped_material=None):
    validate_material(material)
    measured = scoped_material is not None
    if measured and (type(scoped_material) is not bytes or len(scoped_material) != 32):
        raise ValueError("measured payload binding needs32 immutable early material bytes")
    result = {"schema_version": 2 if measured else 1, "provider": "measured-scope-v1" if measured else "owned-context-v1",
        "routing_tag": _routing(routing), "domain": DOMAIN, "source": SOURCE,
        "private_words": list(struct.unpack("<8I", scoped_material) if measured else material_fold(material)),
        "owners": {OWNER: OWNER_ID, **({WRAPPER: WRAPPER_ID} if measured else {})}}
    if measured:
        del result["source"]
        result["sources"] = [{"id": "post-owner-code", "word_label": SOURCE, "group": "post-code"}]
        result["bindings"] = {}
        for owner, site in ((WRAPPER, 702), (OWNER, 701)):
            rule = {"sources": ["post-owner-code"], "mixing_domain": "post:" + owner,
                "groups": [{"id": "post-code", "minimum": 1}]}
            result["bindings"][owner] = {"default": rule, "sites": {str(site): rule}}
    return result


def _same_typed(value, expected):
    if type(value) is not type(expected): return False
    if type(value) is dict:
        return set(value) == set(expected) and all(_same_typed(value[key], expected[key]) for key in expected)
    if type(value) is list:
        return len(value) == len(expected) and all(_same_typed(item, other) for item, other in zip(value, expected))
    return value == expected


def binding_recipe(configuration, *, measured=False, mixed=False):
    if mixed and not measured:
        raise ValueError("mixed payload binding needs a measured POST profile")
    if (type(configuration) is not dict or type(configuration.get("schema_version")) is not int or
            configuration["schema_version"] != 1):
        raise ValueError("payload binding needs a version1 recipe object")
    # Round-trip the caller's configuration without retaining mutable references.
    result = json.loads(json.dumps(configuration))
    functions = result.setdefault("functions", {})
    if type(functions) is not dict:
        raise ValueError("payload binding functions must be an object")
    for name in (OWNER, WRAPPER) if measured else (OWNER,):
        owner = functions.setdefault(name, json.loads(json.dumps(functions.get("pyobf_demo_compute", {}))))
        if type(owner) is not dict or type(owner.get("components", {})) is not dict:
            raise ValueError("payload binding owner/components must be objects")
        components = owner.setdefault("components", {})
        if components.get("runtime-contribution", "required") != "required":
            raise ValueError("strict payload binding cannot disable its required source")
        required = {"selection": "original-edges", "minimum_percent": 100}
        if mixed: required.update(minimum_edges=3, maximum_edges=8)
        contribution = owner.setdefault("contribution", {})
        if type(contribution) is not dict or any(name in contribution and contribution[name] != value
                for name, value in required.items()):
            raise ValueError("strict payload binding requires original-edge selection and100 percent density")
        components["runtime-contribution"] = "required"
        contribution.update(required)
    if measured:
        entry = functions.setdefault("pyobf_demo_post_payload", {})
        if type(entry) is not dict or entry.get("coverage", "hybrid-eh") != "hybrid-eh":
            raise ValueError("measured entry needs explicit hybrid EH ownership cleanup")
        entry["coverage"] = "hybrid-eh"
    return result


def validate_bound_child(plan, private_bytes, report_bytes, *, provider="owned-context-v1", scoped_material=None):
    if provider not in ("owned-context-v1", "measured-scope-v1") or (provider == "measured-scope-v1") != (scoped_material is not None):
        raise ValueError("payload binding provider and early material differ from the required profile")
    if type(private_bytes) is not bytes or len(private_bytes) > 16384:
        raise ValueError("payload binding private reference must be bounded JSON bytes")
    reference = json.loads(private_bytes, object_pairs_hook=_unique)
    measured = scoped_material is not None
    fields = ("schema_version", "provider", "routing_tag", "domain", "private_words", "owners")
    fields += ("sources", "bindings") if measured else ("source",)
    _object(reference, fields, "payload binding")
    if (type(reference["schema_version"]) is not int or reference["schema_version"] != (2 if measured else 1) or
            type(reference["private_words"]) is not list or len(reference["private_words"]) != 8 or
            any(type(word) is not int or not 0 <= word < 1 << 32 for word in reference["private_words"]) or
            type(reference["owners"]) is not dict or
            set(reference["owners"]) != ({OWNER, WRAPPER} if scoped_material is not None else {OWNER}) or
            any(type(value) is not int for value in reference["owners"].values())):
        raise ValueError("payload binding private reference has malformed words/owner/version")
    _routing(reference["domain"])
    if not measured: _routing(reference["source"])
    expected = private_reference({"schema_version": plan["schema_version"], "seed": plan["seed"],
        "events": plan["events"]}, reference["routing_tag"], scoped_material=scoped_material)
    if (not _same_typed(reference, expected) or reference["provider"] != provider or
            provider == "owned-context-v1" and reference["private_words"] != list(expected_fold(plan))):
        raise ValueError("payload binding reference differs from the early release fold")
    document = json.loads(report_bytes, object_pairs_hook=_unique)
    rows = document.get("functions", []) if type(document) is dict else []
    if type(rows) is not list: raise ValueError("payload child function inventory is malformed")
    for owner in expected["owners"]:
        matches = [row for row in rows if type(row) is dict and row.get("function") == owner and row.get("selected") is True]
        proof = matches[0].get("runtime_contribution", {}) if len(matches) == 1 else {}
        if (type(proof) is not dict or len(matches) != 1 or matches[0].get("final_binary_verified") is not True or
                proof.get("private_input_sha256") != hashlib.sha256(private_bytes).hexdigest() or
                proof.get("provider") != provider or proof.get("ir_binding_contract_verified") is not True or
                proof.get("final_query_presence_verified") is not True or
                proof.get("original_real_edge_density_verified") is not True):
            raise ValueError("payload child lacks its exact private-reference binding proof")
        if provider == "measured-scope-v1":
            sites = proof.get("sites")
            rule = expected["bindings"][owner]["default"]
            source = expected["sources"][0]
            reported_source = {"id": source["id"], "word_label": source["word_label"], "encoding": 1,
                "group": source["group"], "class": "referenced-evidence", "sharing": "owner-independent",
                "use": "required-binding"}
            if (proof.get("scheme_version") != 2 or proof.get("operation_scope") != "function-invocation" or
                    proof.get("evidence_bits") != 256 or proof.get("source_subset_contract_verified") is not True or
                    proof.get("generated_owner_independence_verified") is not False or
                    type(sites) is not list or not sites or type(proof.get("query_count")) is not int or
                    proof["query_count"] != len(sites) or
                    sum(type(site) is dict and site.get("label") == (702 if owner == WRAPPER else 701)
                        for site in sites) != 1 or
                    any(type(site) is not dict or not _same_typed(site.get("sources"), [reported_source]) or
                        site.get("mixing_domain") != rule["mixing_domain"] or
                        not _same_typed(site.get("groups"), [{**rule["groups"][0], "independent_evidence": False}])
                        for site in sites)):
                raise ValueError("payload child lacks its invocation measured-source contract")
        edges = proof.get("original_edges", {})
        if (type(edges) is not dict or any(type(edges.get(name)) is not int for name in
                ("original_edges", "selected_edges", "bound_edges", "minimum_percent")) or
                edges["original_edges"] <= 0 or edges["minimum_percent"] != 100 or
                edges["selected_edges"] != edges["original_edges"] or edges["bound_edges"] != edges["original_edges"]):
            raise ValueError("payload child lacks complete original-edge source coverage")


def render_post_profile(reference):
    if reference.get("provider") != "measured-scope-v1":
        raise ValueError("post profile requires a measured source")
    values = {"routing": reference["routing_tag"], "domain": reference["domain"],
        "source": reference["sources"][0]["word_label"],
        "compute_owner": reference["owners"][OWNER], "wrapper_owner": reference["owners"][WRAPPER]}
    return ("#pragma once\n#include <cstdint>\nnamespace pyobfuscator::native::demo::post_profile {\n" +
        "".join(f"inline constexpr std::uint32_t {name} = {value}u;\n" for name, value in values.items()) + "}\n")


def requires_bound_child(report_bytes):
    document = json.loads(report_bytes, object_pairs_hook=_unique)
    rows = document.get("functions") if type(document) is dict else None
    if type(rows) is not list: raise ValueError("payload child function inventory is malformed")
    return any(type(row) is dict and row.get("function") == OWNER for row in rows)
