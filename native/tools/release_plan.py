"""Private per-child-build event descriptors; never distribute this input plan."""

from __future__ import annotations

import hashlib
import json
import re
from release_material import (ROLES, _object, _unique, create_material, material_fold,
    render_material_header, validate_material)


def validate_plan(plan):
    _object(plan, ("schema_version", "child_image_sha256", "child_report_sha256", "seed", "events"), "plan")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("private release plan version is unsupported")
    for name in ("child_image_sha256", "child_report_sha256"):
        if type(plan[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", plan[name]) is None:
            raise ValueError("private release child identity is malformed")
    validate_material(_material(plan))
    return plan


def _material(plan):
    return {"schema_version": plan["schema_version"], "seed": plan["seed"], "events": plan["events"]}


def parse_plan(source: bytes):
    if type(source) is not bytes or len(source) > 16384:
        raise ValueError("private release plan must be bounded JSON bytes")
    return validate_plan(json.loads(source, object_pairs_hook=_unique))


def child_identity(image: bytes, report: bytes) -> tuple[str, str]:
    if type(image) is not bytes or not image or type(report) is not bytes:
        raise ValueError("private release needs child image/report bytes")
    document = json.loads(report, object_pairs_hook=_unique)
    rows = document.get("functions") if type(document) is dict else None
    if (type(document) is not dict or document.get("verification_scope") != "function-shape-and-component-presence" or
            document.get("strategy") != "relative-tree" or type(rows) is not list or
            any(type(row) is not dict or type(row.get("selected")) is not bool for row in rows)):
        raise ValueError("private release needs a supported final child coverage report")
    selected = [row for row in rows if row["selected"]]
    if not selected or any(row.get("final_binary_verified") is not True or
                           row.get("status") != "final-binary-verified" for row in selected):
        raise ValueError("private release child final coverage is incomplete")
    digest = hashlib.sha256(image).hexdigest()
    if document.get("image_sha256") != digest:
        raise ValueError("private release child image/report identity differs")
    return digest, hashlib.sha256(report).hexdigest()


def _bound_plan(material, identity):
    validate_material(material)
    image_hash, report_hash = identity
    return validate_plan({"schema_version": 1, "child_image_sha256": image_hash,
        "child_report_sha256": report_hash, "seed": material["seed"],
        "events": {role: dict(material["events"][role]) for role in ROLES}})


def bind_material(material, image: bytes, report: bytes):
    validate_material(material)
    return _bound_plan(material, child_identity(image, report))


def create_plan(image: bytes, report: bytes):
    identity = child_identity(image, report)
    return _bound_plan(create_material(), identity)


def validate_child(plan, image: bytes, report: bytes) -> None:
    validate_plan(plan)
    if child_identity(image, report) != (plan["child_image_sha256"], plan["child_report_sha256"]):
        raise ValueError("private release plan belongs to another child image/report")


def render_header(plan, namespace="path_events") -> str:
    validate_plan(plan)
    return render_material_header(_material(plan), namespace)


def expected_fold(plan) -> tuple[int, ...]:
    validate_plan(plan)
    return material_fold(_material(plan))
