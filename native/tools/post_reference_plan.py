"""Freeze the two post-release roles without a parent-hash/child-code dependency."""
import argparse
import hashlib
import json
from pathlib import Path

from atomic_artifact import atomic_write
from bootstrap_reference_plan import create as bootstrap_plan
from payload_binding import OWNER, WRAPPER, private_reference
from post_mixed_binding import validate_mixed_private
from prepare_scope_material import read_material
from post_subjects import selectors
from reference_plan import parse_plan
from release_material import _unique, parse_material

INNER_ROLE = "pyobf_native_demo_inner"


def create(material_bytes, role, private_bytes, scoped_material, *, pre_release, subjects=None, mixed_plan=None):
    if type(pre_release) is not bool: raise ValueError("post reference pre-release selector must be Boolean")
    material = parse_material(material_bytes)
    if type(private_bytes) is not bytes or not 0 < len(private_bytes) <= (32768 if mixed_plan is not None else 16384):
        raise ValueError("post source must be bounded immutable private JSON")
    reference = json.loads(private_bytes, object_pairs_hook=_unique)
    if (type(reference) is not dict or type(reference.get("routing_tag")) is not int or
            type(reference.get("schema_version")) is not int or type(reference.get("private_words")) is not list or
            any(type(value) is not int for value in reference["private_words"])):
        raise ValueError("post reference needs an exact measured private source")
    if mixed_plan is None:
        if reference != private_reference(material, reference["routing_tag"], scoped_material=scoped_material):
            raise ValueError("post reference differs from its early measured source/material")
    else:
        validate_mixed_private(material, scoped_material, mixed_plan, private_bytes)
    base = bootstrap_plan(material_bytes, role)
    document = json.loads(base.canonical)
    document["schema_version"] = 2
    document["build_seed"] = hashlib.sha256(b"pyobf.native.post.reference.seed.v1\0" +
        hashlib.sha256(material_bytes).digest() + hashlib.sha256(private_bytes).digest()).digest()[:16].hex()
    document["records"] = document["records"] if pre_release else []
    inner = bootstrap_plan(material_bytes, INNER_ROLE).container
    roles = ((WRAPPER, base.container, 1), (OWNER, inner, 2))
    for (name, image, subject), selection in zip(roles, selectors(subjects)):
        document["records"].append({"image": image.hex(), "owner": reference["owners"][name],
            "subject": subject, "stage": 2, "capacity": 4096, **selection})
    document["scope_materials"] = [len(document["records"]) - 2, len(document["records"]) - 1]
    return parse_plan(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("material", "role", "private", "scoped", "output"):
        parser.add_argument(name, type=str if name == "role" else Path)
    parser.add_argument("--pre-release", action="store_true")
    parser.add_argument("--subjects", type=Path, help="early exact parent/child section or function selectors")
    parser.add_argument("--mixed-plan", type=Path, help="frozen retained-IR plan for opt-in mixed POST")
    args = parser.parse_args()
    try:
        paths = (args.material, args.private, args.scoped, args.output,
                 *((args.subjects,) if args.subjects else ()),
                 *((args.mixed_plan,) if args.mixed_plan else ()))
        if len({path.resolve() for path in paths}) != len(paths):
            raise ValueError("post reference inputs/output must be distinct")
        atomic_write(args.output, create(args.material.read_bytes(), args.role, args.private.read_bytes(),
            read_material(args.scoped), pre_release=args.pre_release,
            subjects=args.subjects.read_bytes() if args.subjects else None,
            mixed_plan=args.mixed_plan.read_bytes() if args.mixed_plan else None).canonical)
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
