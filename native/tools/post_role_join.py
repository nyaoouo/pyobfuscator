"""Join exact parent POST role producers to the released child CFF consumers."""

import hashlib
import json

from payload_binding import OWNER, WRAPPER, validate_bound_child
from post_mixed_binding import _plan as mixed_edge_plan, validate_mixed_bound_child, validate_mixed_private
from release_material import parse_material
from reference_slots import storage
from release_material import _unique
from release_plan import parse_plan as parse_release_plan, validate_child


def _sha(data): return hashlib.sha256(data).hexdigest()


def _object(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError(f"post role join has malformed {label}")
    return value


def _integer(value, maximum): return type(value) is int and 0 <= value <= maximum


def verify_post_role_join(parent_report_bytes, parent_final, parent_plan, parent_image,
        release_report_bytes, release_plan_bytes, child_image, child_final_bytes,
        child_report_bytes, private_bytes, scoped_material):
    parent_report = json.loads(parent_report_bytes, object_pairs_hook=_unique)
    if type(parent_report) is not dict or type(parent_final) is not dict:
        raise ValueError("post role join needs actual parent compiler/final reports")
    release = json.loads(release_report_bytes, object_pairs_hook=_unique)
    child_final = json.loads(child_final_bytes, object_pairs_hook=_unique)
    child_report = json.loads(child_report_bytes, object_pairs_hook=_unique)
    private = json.loads(private_bytes, object_pairs_hook=_unique)
    release_plan = parse_release_plan(release_plan_bytes)
    validate_child(release_plan, child_image, child_final_bytes)
    validate_bound_child(release_plan, private_bytes, child_final_bytes,
        provider="measured-scope-v1", scoped_material=scoped_material)
    if (type(release) is not dict or type(release.get("schema_version")) is not int or
            release["schema_version"] != 1 or release.get("binding") != "post-release-invocation-scope-v1" or
            release.get("executable_bytes_verified_unchanged") is not True or
            release.get("layout_verified_unchanged") is not True or
            type(release.get("idempotent")) is not bool or
            release.get("plan_sha256") != parent_plan.digest.hex() or
            release.get("image_after_sha256") != _sha(parent_image) or
            release.get("child_image_sha256") != _sha(child_image) or
            release.get("child_report_sha256") != _sha(child_final_bytes) or
            release.get("private_input_sha256") != _sha(private_bytes) or
            child_final.get("image_sha256") != _sha(child_image) or
            child_final.get("input_report_sha256") != _sha(child_report_bytes) or
            parent_final.get("image_sha256") != _sha(parent_image) or
            parent_final.get("input_report_sha256") != _sha(parent_report_bytes)):
        raise ValueError("post role join received swapped or stale release artifacts")
    flow = _object(parent_report.get("post_role_flow"),
        ("schema_version", "plan_sha256", "roles"), "parent compiler flow")
    child_flow = _object(child_report.get("post_child_flow"),
        ("schema_version", "scheme", "roles"), "child compiler flow")
    if (type(flow["schema_version"]) is not int or flow["schema_version"] != 1 or
            flow["plan_sha256"] != parent_plan.digest.hex() or type(flow["roles"]) is not list or
            len(flow["roles"]) != 2 or type(child_flow["schema_version"]) is not int or
            child_flow["schema_version"] != 1 or child_flow["scheme"] != "post-scope-flow-v1" or
            type(child_flow["roles"]) is not list or len(child_flow["roles"]) != 2):
        raise ValueError("post role compiler inventories do not match the frozen plan")
    creators = _object(parent_final.get("owner_creators"),
        ("schema_version", "verification_scope", "object_sha256", "compiler_report_sha256",
            "plan_sha256", "entries"), "final creator proof")
    if (creators["plan_sha256"] != parent_plan.digest.hex() or
            creators["compiler_report_sha256"] != _sha(parent_report_bytes) or
            type(creators["entries"]) is not list or len(creators["entries"]) != len(parent_plan.records)):
        raise ValueError("post role creator final proof differs from its plan")
    parent_rows = {row.get("function"): row for row in parent_final.get("functions", []) if type(row) is dict}
    child_rows = {row.get("function"): row for row in child_final.get("functions", []) if type(row) is dict}
    slots = storage(parent_plan)
    first = len(parent_plan.records) - 2
    if first not in (0, 1) or len(slots.material_offsets) != len(parent_plan.records):
        raise ValueError("post role join needs exactly two trailing measured owners")
    joined = []
    producers = set()
    for role, consumer, site in ((0, WRAPPER, 702), (1, OWNER, 701)):
        row = _object(flow["roles"][role], ("role", "creator_index", "owner", "producer", "creator",
            "creator_result_to_owner_verified", "owner_to_lease_verified", "lease_to_handoff_verified",
            "spec_identity_material_verified", "routing_tag", "domain", "source", "code_offset",
            "material_offset"), f"parent role {role}")
        child = _object(child_flow["roles"][role], ("role", "consumer", "site",
            "role_to_scope_verified", "scope_forwarding_verified", "site_scope_binding_verified"),
            f"child role {role}")
        index = first + role
        creator = creators["entries"][index]
        expected_owner = parent_plan.records[index].identity.owner
        if (type(row["role"]) is not int or row["role"] != role or
                type(row["creator_index"]) is not int or row["creator_index"] != index or
                not _integer(row["owner"], (1 << 32) - 1) or row["owner"] != expected_owner or
                type(row["producer"]) is not str or not row["producer"] or
                row["producer"] in producers or type(row["creator"]) is not str or
                any(row[key] is not True for key in ("creator_result_to_owner_verified",
                    "owner_to_lease_verified", "lease_to_handoff_verified", "spec_identity_material_verified")) or
                any(not _integer(row[key], (1 << 32) - 1) for key in ("routing_tag", "domain", "source")) or
                row["routing_tag"] != private["routing_tag"] or row["domain"] != private["domain"] or
                row["source"] != private["sources"][0]["word_label"] or
                any(not _integer(row[key], (1 << 64) - 1) for key in ("code_offset", "material_offset")) or
                row["code_offset"] != slots.offsets[index] or
                row["material_offset"] != slots.material_offsets[index] or
                private["owners"][consumer] != row["owner"] or
                type(creator) is not dict or creator.get("index") != index or
                creator.get("owner") != row["owner"] or creator.get("function") != row["creator"] or
                parent_rows.get(row["producer"], {}).get("final_binary_verified") is not True or
                sum(type(item) is dict and item.get("function") == row["producer"]
                    for item in parent_final.get("functions", [])) != 1):
            raise ValueError(f"post role {role} parent producer differs from its exact owner slot")
        producers.add(row["producer"])
        if (type(child["role"]) is not int or type(child["site"]) is not int or
                child != {"role": role, "consumer": consumer, "site": site,
                "role_to_scope_verified": True, "scope_forwarding_verified": True,
                "site_scope_binding_verified": True} or
                child_rows.get(consumer, {}).get("final_binary_verified") is not True or
                sum(type(item) is dict and item.get("function") == consumer
                    for item in child_final["functions"]) != 1):
            raise ValueError(f"post role {role} child Scope/site path is not certified")
        proof = child_rows[consumer].get("runtime_contribution")
        markers = [entry for entry in proof.get("sites", []) if entry.get("label") == site] if type(proof) is dict else []
        if (len(markers) != 1 or proof.get("generated_owner_independence_verified") is not False or
                proof.get("final_query_presence_verified") is not True or
                markers[0].get("sources") != [{"id": private["sources"][0]["id"],
                    "word_label": private["sources"][0]["word_label"], "encoding": 1,
                    "group": private["sources"][0]["group"], "class": "referenced-evidence",
                    "sharing": "owner-independent", "use": "required-binding"}]):
            raise ValueError(f"post role {role} final child source site differs")
        joined.append({"role": role, "creator_index": index, "owner": row["owner"],
            "producer": row["producer"], "creator": row["creator"],
            "consumer": consumer, "site": site})
    return {"schema_version": 1,
        "verification_scope": "cross-artifact-compiler-role-flow-and-function-final-presence",
        "individual_site_machine_verified": False,
        "plan_sha256": parent_plan.digest.hex(), "parent_image_sha256": _sha(parent_image),
        "child_image_sha256": _sha(child_image), "child_report_sha256": _sha(child_final_bytes),
        "private_input_sha256": _sha(private_bytes),
        "release_plan_sha256": _sha(release_plan_bytes), "roles": joined}


def verify_post_mixed_role_join(parent_report_bytes, parent_final, parent_plan, parent_image,
        release_report_bytes, release_plan_bytes, child_image, child_final_bytes,
        child_report_bytes, private_bytes, scoped_material, material_bytes, mixed_plan_bytes):
    """Join the two final POST roles to their frozen, independently proved sites."""
    material = parse_material(material_bytes)
    private = validate_mixed_private(material, scoped_material, mixed_plan_bytes, private_bytes)
    edges = mixed_edge_plan(mixed_plan_bytes)
    parent_report = json.loads(parent_report_bytes, object_pairs_hook=_unique)
    release = json.loads(release_report_bytes, object_pairs_hook=_unique)
    child_report = json.loads(child_report_bytes, object_pairs_hook=_unique)
    child_final = json.loads(child_final_bytes, object_pairs_hook=_unique)
    release_plan = parse_release_plan(release_plan_bytes)
    validate_child(release_plan, child_image, child_final_bytes)
    validate_mixed_bound_child(release_plan, private_bytes, child_final_bytes,
        material_bytes=material_bytes, scoped_material=scoped_material, mixed_plan_bytes=mixed_plan_bytes)
    if (type(parent_report) is not dict or type(parent_final) is not dict or
            type(release) is not dict or type(release.get("schema_version")) is not int or
            release["schema_version"] != 1 or
            release.get("binding") != "post-release-invocation-scope-v1" or
            release.get("executable_bytes_verified_unchanged") is not True or
            release.get("layout_verified_unchanged") is not True or
            release.get("plan_sha256") != parent_plan.digest.hex() or
            release.get("image_after_sha256") != _sha(parent_image) or
            release.get("child_image_sha256") != _sha(child_image) or
            release.get("child_report_sha256") != _sha(child_final_bytes) or
            release.get("private_input_sha256") != _sha(private_bytes) or
            parent_final.get("image_sha256") != _sha(parent_image) or
            parent_final.get("input_report_sha256") != _sha(parent_report_bytes) or
            child_final.get("image_sha256") != _sha(child_image) or
            child_final.get("input_report_sha256") != _sha(child_report_bytes)):
        raise ValueError("mixed POST role join received swapped or stale release artifacts")
    flow = _object(parent_report.get("post_role_flow"),
        ("schema_version", "plan_sha256", "roles"), "mixed parent compiler flow")
    child_flow = _object(child_report.get("post_child_flow"),
        ("schema_version", "scheme", "roles"), "mixed child compiler flow")
    if (type(flow["schema_version"]) is not int or flow["schema_version"] != 1 or
            flow["plan_sha256"] != parent_plan.digest.hex() or
            type(flow["roles"]) is not list or len(flow["roles"]) != 2 or
            type(child_flow["schema_version"]) is not int or child_flow["schema_version"] != 2 or
            child_flow["scheme"] != "post-mixed-scope-flow-v1" or
            type(child_flow["roles"]) is not list or len(child_flow["roles"]) != 2):
        raise ValueError("mixed POST role flow differs from its compiler inventories")
    creators = _object(parent_final.get("owner_creators"),
        ("schema_version", "verification_scope", "object_sha256", "compiler_report_sha256",
         "plan_sha256", "entries"), "mixed final creator proof")
    if (creators["plan_sha256"] != parent_plan.digest.hex() or
            creators["compiler_report_sha256"] != _sha(parent_report_bytes) or
            type(creators["entries"]) is not list or len(creators["entries"]) != len(parent_plan.records)):
        raise ValueError("mixed POST creator proof differs from its exact parent plan")
    parent_rows = {row.get("function"): row for row in parent_final.get("functions", []) if type(row) is dict}
    child_rows = {row.get("function"): row for row in child_final.get("functions", []) if type(row) is dict}
    slots = storage(parent_plan)
    first = len(parent_plan.records) - 2
    if first not in (0, 1) or len(slots.material_offsets) != len(parent_plan.records):
        raise ValueError("mixed POST role join needs two trailing measured owners")
    joined = []
    producers = set()
    for role, consumer in enumerate((WRAPPER, OWNER)):
        row = _object(flow["roles"][role], ("role", "creator_index", "owner", "producer", "creator",
            "creator_result_to_owner_verified", "owner_to_lease_verified", "lease_to_handoff_verified",
            "spec_identity_material_verified", "routing_tag", "domain", "source", "code_offset",
            "material_offset"), f"mixed parent role {role}")
        child = _object(child_flow["roles"][role], ("role", "consumer", "site",
            "role_to_scope_verified", "scope_forwarding_verified", "site_scope_binding_verified"),
            f"mixed child role {role}")
        index = first + role
        creator = creators["entries"][index]
        site_labels = {edge["label"] for planned in edges["owners"] if planned["owner"] == consumer
                       for edge in planned["edges"]}
        proof = child_rows.get(consumer, {}).get("runtime_contribution")
        actual_labels = {site.get("label") for site in proof.get("sites", [])} if type(proof) is dict else set()
        if (type(row["role"]) is not int or row["role"] != role or
                type(row["creator_index"]) is not int or row["creator_index"] != index or
                type(row["owner"]) is not int or
                row["owner"] != parent_plan.records[index].identity.owner or
                row["owner"] != private["owners"][consumer] or
                type(row["producer"]) is not str or not row["producer"] or row["producer"] in producers or
                type(row["creator"]) is not str or not row["creator"] or
                any(row[key] is not True for key in ("creator_result_to_owner_verified",
                    "owner_to_lease_verified", "lease_to_handoff_verified", "spec_identity_material_verified")) or
                row["routing_tag"] != private["routing_tag"] or row["domain"] != private["domain"] or
                row["source"] != private["sources"][-1]["word_label"] or
                any(type(row[key]) is not int for key in
                    ("routing_tag", "domain", "source", "code_offset", "material_offset")) or
                row["code_offset"] != slots.offsets[index] or
                row["material_offset"] != slots.material_offsets[index] or
                type(creator) is not dict or creator.get("index") != index or
                creator.get("owner") != row["owner"] or creator.get("function") != row["creator"] or
                parent_rows.get(row["producer"], {}).get("final_binary_verified") is not True or
                child_rows.get(consumer, {}).get("final_binary_verified") is not True or
                type(child["role"]) is not int or type(child["site"]) is not int or
                child != {"role": role, "consumer": consumer, "site": 0,
                    "role_to_scope_verified": True, "scope_forwarding_verified": True,
                    "site_scope_binding_verified": True} or
                actual_labels != site_labels or len(proof["sites"]) != len(site_labels)):
            raise ValueError(f"mixed POST role {role} does not join its exact producer, Scope and sites")
        producers.add(row["producer"])
        joined.append({"role": role, "creator_index": index, "owner": row["owner"],
            "producer": row["producer"], "creator": row["creator"], "consumer": consumer,
            "sites": sorted(site_labels)})
    return {"schema_version": 2,
        "verification_scope": "cross-artifact-compiler-role-flow-and-final-original-edge-machine",
        "individual_site_machine_verified": True, "plan_sha256": parent_plan.digest.hex(),
        "mixed_plan_sha256": _sha(mixed_plan_bytes), "parent_image_sha256": _sha(parent_image),
        "child_image_sha256": _sha(child_image), "child_report_sha256": _sha(child_final_bytes),
        "private_input_sha256": _sha(private_bytes),
        "release_plan_sha256": _sha(release_plan_bytes), "roles": joined}
