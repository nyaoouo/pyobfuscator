"""Generate the private two-owner POST source policy from a frozen edge plan."""

import hashlib
import json
import re
import struct

from payload_binding import DOMAIN, OWNER, OWNER_ID, SOURCE, WRAPPER, WRAPPER_ID, _routing, _same_typed
from release_material import material_fold, parse_material, validate_material


PROFILE = "schema4-original-edges-post-two-v1"
OWNED = (("post-owned-1", 0x4f574e31), ("post-owned-2", 0x4f574e32),
         ("post-owned-3", 0x4f574e33), ("post-owned-4", 0x4f574e34))
MEASURED = {"id": "post-owner-code", "word_label": SOURCE, "group": "post-code",
            "provider": "measured-scope-v1", "provider_version": 1}


def _invalid(reason):
    raise ValueError(f"mixed POST private binding: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: _invalid("duplicate plan field")
        result[key] = value
    return result


def _plan(raw):
    if type(raw) is not bytes or len(raw) > 262144:
        _invalid("frozen plan must be bounded JSON bytes")
    try:
        plan = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("mixed POST private binding: malformed plan JSON") from error
    if (type(plan) is not dict or set(plan) != {"schema_version", "profile", "owners",
            "input_ir_encoding", "input_ir_sha256"} or
            type(plan["schema_version"]) is not int or plan["schema_version"] != 2 or
            plan["profile"] != PROFILE or plan["input_ir_encoding"] != "llvm-module-print-v1" or
            type(plan["input_ir_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", plan["input_ir_sha256"]) is None or
            type(plan["owners"]) is not list or len(plan["owners"]) != 2):
        _invalid("unsupported frozen plan identity")
    labels, identities = set(), set()
    for expected_owner, row in zip((OWNER, WRAPPER), plan["owners"]):
        if type(row) is not dict or set(row) != {"owner", "recipe", "edges"} or row["owner"] != expected_owner:
            _invalid("owner order or row shape differs from the frozen contract")
        recipe, edges = row["recipe"], row["edges"]
        if (type(recipe) is not dict or recipe.get("strategy") != "relative-tree" or
                recipe.get("coverage") != "whole" or
                recipe.get("contribution") != {"selection": "original-edges", "minimum_edges": 3,
                                               "maximum_edges": 8, "minimum_percent": 100} or
                type(recipe.get("components")) is not list or
                len([component for component in recipe["components"] if type(component) is dict and
                     component.get("component") == "runtime-contribution" and
                     component.get("requirement") == "required"]) != 1 or
                type(edges) is not list or not 3 <= len(edges) <= 8):
            _invalid("owner recipe or edge budget is unsupported")
        for edge in edges:
            if (type(edge) is not dict or set(edge) != {"id", "label", "successor_index"} or
                    type(edge["id"]) is not str or not edge["id"] or len(edge["id"]) > 512 or
                    type(edge["label"]) is not int or not 0 < edge["label"] < 1 << 32 or
                    type(edge["successor_index"]) is not int or edge["successor_index"] not in (0, 1) or
                    (expected_owner, edge["id"]) in identities or edge["label"] in labels):
                _invalid("edge identity, successor or label is invalid or repeated")
            identities.add((expected_owner, edge["id"]))
            labels.add(edge["label"])
    return plan


def mixed_private_reference(material, routing, scoped_material, plan_bytes):
    validate_material(material)
    if type(scoped_material) is not bytes or len(scoped_material) != 32:
        _invalid("measured root needs exactly 32 immutable early bytes")
    plan = _plan(plan_bytes)
    owned_words = list(material_fold(material))
    measured_words = list(struct.unpack("<8I", scoped_material))
    if owned_words == measured_words:
        _invalid("owned and measured roots must differ")
    sources = [{"id": name, "word_label": label, "group": "post-owned",
                "provider": "owned-context-v1", "provider_version": 1} for name, label in OWNED]
    sources.append(MEASURED.copy())
    bindings = {}
    for row in plan["owners"]:
        sites = {}
        for index, edge in enumerate(row["edges"]):
            subset = [name for bit, (name, _) in enumerate(OWNED) if (index + 1) & (1 << bit)]
            sites[str(edge["label"])] = {
                "sources": subset + [MEASURED["id"]],
                "mixing_domain": f"post-mixed:{row['owner']}:{edge['label']}",
                "groups": [{"id": "post-owned", "minimum": 1}, {"id": "post-code", "minimum": 1}]}
        bindings[row["owner"]] = {"sites": sites}
    return {"schema_version": 4, "provider": "source-mixed-v1", "root_scheme": "provider-split-v1",
            "routing_tag": _routing(routing), "domain": DOMAIN,
            "private_words": owned_words, "measured_private_words": measured_words,
            "owners": {OWNER: OWNER_ID, WRAPPER: WRAPPER_ID}, "sources": sources, "bindings": bindings}


def validate_mixed_private(material, scoped_material, plan_bytes, private_bytes):
    if type(private_bytes) is not bytes or not 0 < len(private_bytes) <= 32768:
        _invalid("private source must be bounded JSON bytes")
    try:
        reference = json.loads(private_bytes.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("mixed POST private binding: malformed private JSON") from error
    if type(reference) is not dict:
        _invalid("private source is not an object")
    expected = mixed_private_reference(material, reference.get("routing_tag"), scoped_material, plan_bytes)
    if not _same_typed(reference, expected):
        _invalid("private source differs from immutable roots or frozen plan")
    return reference


def validate_mixed_bound_child(release_plan, private_bytes, report_bytes, *,
                               material_bytes, scoped_material, mixed_plan_bytes):
    """Require both linked owner proofs before releasing a mixed POST child."""
    material = parse_material(material_bytes)
    if material != {key: release_plan[key] for key in ("schema_version", "seed", "events")}:
        _invalid("release material belongs to another child plan")
    private = validate_mixed_private(material, scoped_material, mixed_plan_bytes, private_bytes)
    plan = _plan(mixed_plan_bytes)
    if type(report_bytes) is not bytes or not 0 < len(report_bytes) <= 8 << 20:
        _invalid("final child report must be bounded JSON bytes")
    try:
        report = json.loads(report_bytes.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("mixed POST private binding: malformed final child report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or any(type(row) is not dict for row in rows):
        _invalid("final child function inventory is invalid")
    plan_hash = hashlib.sha256(mixed_plan_bytes).hexdigest()
    private_hash = hashlib.sha256(private_bytes).hexdigest()
    owners = (OWNER, WRAPPER)
    mixed_rows = [row for row in rows if row.get("selected") is True and
                  type(row.get("runtime_contribution")) is dict and
                  row["runtime_contribution"].get("provider") == "source-mixed-v1"]
    if len(mixed_rows) != 2 or {row.get("function") for row in mixed_rows} != set(owners):
        _invalid("final child has a missing or extra mixed owner")
    for owner, planned in zip(owners, plan["owners"]):
        matches = [row for row in rows if row.get("function") == owner]
        if len(matches) != 1:
            _invalid(f"final child owner inventory is ambiguous: {owner}")
        row = matches[0]
        proof = row.get("runtime_contribution")
        count = len(planned["edges"])
        expected = {"verified": True, "plan_sha256": plan_hash,
                    "planned_edges": count, "selected_edges": count, "bound_edges": count}
        machine = proof.get("original_edge_machine") if type(proof) is dict else None
        if (row.get("final_binary_verified") is not True or
                row.get("status") != "final-binary-verified" or
                proof.get("scheme_version") != 4 or
                proof.get("provider") != "source-mixed-v1" or
                proof.get("private_input_sha256") != private_hash or
                proof.get("final_query_presence_verified") is not True or
                proof.get("original_real_edge_density_verified") is not True or
                not _same_typed(machine, expected) or
                set(private["bindings"][owner]["sites"]) !=
                {str(edge["label"]) for edge in planned["edges"]}):
            _invalid(f"final child lacks its exact linked original-edge proof: {owner}")
    return {"plan_sha256": plan_hash, "private_input_sha256": private_hash,
            "owners": {owner: len(planned["edges"]) for owner, planned in zip(owners, plan["owners"])}}


def render_post_mixed_sites(reference):
    if reference.get("provider") != "source-mixed-v1" or set(reference.get("owners", {})) != {OWNER, WRAPPER}:
        _invalid("cannot render a non-mixed POST site table")
    labels = {source["id"]: source["word_label"] for source in reference["sources"]}
    rows = []
    for owner in (OWNER, WRAPPER):
        for site, rule in reference["bindings"][owner]["sites"].items():
            for name in rule["sources"][:-1]:
                rows.append((reference["owners"][owner], int(site), labels[name]))
    if not rows or len(set(rows)) != len(rows):
        _invalid("mixed POST site table is empty or duplicated")
    return ("#pragma once\n#include <cstdint>\nnamespace pyobfuscator::native::demo::post_mixed_sites {\n"
            "struct Site { std::uint32_t owner, label, source; };\n"
            "inline constexpr Site sites[] = {\n" +
            "".join(f"    {{{owner}u, {site}u, {source}u}},\n" for owner, site, source in rows) +
            "};\n}\n")
