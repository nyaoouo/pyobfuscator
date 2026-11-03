"""Complete post-role references/materials and the existing release record in one data domain."""
import argparse
import hashlib
import json
from pathlib import Path

from atomic_artifact import atomic_write
from code_observation import reference_digest
from code_subject import text_subject
from finalize_references import _bindings, finalize as references
from function_inventory import Ownership
from measured_release import bind_draft
from payload_binding import validate_bound_child
from post_mixed_binding import validate_mixed_bound_child
from pe_data_patch import Write, apply_writes
from pe_layout import parse_image
from pe_release_record import finalize_image, locate_record
from post_reference_plan import INNER_ROLE, create as create_plan
from bootstrap_reference_plan import create as bootstrap_plan
from prepare_scope_material import read_material
from reference_plan import parse_plan
from reference_slots import MATERIAL_BYTES, locate
from release_material import material_fold, parse_material
from release_plan import parse_plan as release_plan, validate_child


def finalize(image, plan, material_bytes, draft, private_bytes, scoped_material, child, child_report,
        child_plan, role, *, pre_release, subjects=None, mixed_plan=None, objects=None, ownership=None, packages=None, material_packages=None):
    material = parse_material(material_bytes)
    if plan != create_plan(material_bytes, role, private_bytes, scoped_material,
                          pre_release=pre_release, subjects=subjects, mixed_plan=mixed_plan):
        raise ValueError("post completion differs from its early role/source binding")
    if material != {key: child_plan[key] for key in ("schema_version", "seed", "events")}:
        raise ValueError("post completion uses another release fold")
    validate_child(child_plan, child, child_report)
    if mixed_plan is None:
        validate_bound_child(child_plan, private_bytes, child_report,
                             provider="measured-scope-v1", scoped_material=scoped_material)
    else:
        validate_mixed_bound_child(child_plan, private_bytes, child_report,
                                   material_bytes=material_bytes, scoped_material=scoped_material,
                                   mixed_plan_bytes=mixed_plan)
    words = material_fold(material)
    targets = {bootstrap_plan(material_bytes, INNER_ROLE).container: child}
    _, section, slots = locate(image, plan)
    record_version = 2 if pre_release else 1
    _, release_offset = locate_record(image, version=record_version)
    completed, reference_proof = references(image, plan, words, targets=targets, objects=objects, ownership=ownership, packages=packages,
        materials={index: scoped_material for index in plan.scope_materials}, material_packages=material_packages)
    record = draft
    if pre_release:
        identity = plan.records[0].identity
        subject = text_subject(parse_image(image), identity.subject)
        record = bind_draft(draft, words, identity, reference_digest(image, parse_image(image), subject, identity.owner))
    completed, release_proof = finalize_image(completed, record, version=record_version)
    writes = [Write(section.raw_offset + offset, completed[section.raw_offset + offset:
        section.raw_offset + offset + selection.identity.capacity]) for selection, offset in zip(plan.records, slots.offsets)]
    writes += [Write(section.raw_offset + slots.material_offsets[index], completed[section.raw_offset + slots.material_offsets[index]:
        section.raw_offset + slots.material_offsets[index] + MATERIAL_BYTES]) for index in plan.scope_materials]
    writes.append(Write(release_offset + 24, completed[release_offset + 24:release_offset + 56]))
    exact, proof = apply_writes(image, tuple(writes))
    if exact != completed: raise AssertionError("post/release composition changed bytes beyond its declared slots")
    return completed, {"schema_version": 1, "format": "amd64-pe32+", "record_version": record_version,
        "binding": "post-release-invocation-scope-v1", "plan_sha256": plan.digest.hex(),
        "private_input_sha256": hashlib.sha256(private_bytes).hexdigest(),
        "child_image_sha256": hashlib.sha256(child).hexdigest(), "child_report_sha256": hashlib.sha256(child_report).hexdigest(),
        "draft_sha256": hashlib.sha256(draft).hexdigest(), "record_sha256": hashlib.sha256(record).hexdigest(),
        "idempotent": completed == image, "reference": reference_proof, "release": release_proof, **proof}


def verify(image, completed, *arguments, **options):
    plan = arguments[0]
    _, section, slots = locate(completed, plan)
    packages = {index: completed[section.raw_offset + offset:section.raw_offset + offset + record.identity.capacity]
        for index, (record, offset) in enumerate(zip(plan.records, slots.offsets))}
    materials = {index: completed[section.raw_offset + slots.material_offsets[index]:
        section.raw_offset + slots.material_offsets[index] + MATERIAL_BYTES] for index in plan.scope_materials}
    expected, proof = finalize(image, *arguments, packages=packages, material_packages=materials, **options)
    if expected != completed: raise ValueError("post image differs from its exact authenticated data-only completion")
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "plan", "material", "draft", "output"): parser.add_argument(name, type=Path)
    for name in ("private", "scoped", "child", "child-report", "release-plan", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--role", required=True)
    parser.add_argument("--pre-release", action="store_true")
    parser.add_argument("--subjects", type=Path)
    parser.add_argument("--mixed-plan", type=Path)
    parser.add_argument("--object", action="append", default=[], help="function record index=actual final compiler object")
    parser.add_argument("--ownership", action="append", default=[], help="helper record index=private emission manifest")
    parser.add_argument("--ownership-report", action="append", default=[], help="helper record index=actual CFF compiler report")
    args = parser.parse_args()
    try:
        objects = _bindings(args.object, objects=True)
        manifests, reports = _bindings(args.ownership, objects=True), _bindings(args.ownership_report, objects=True)
        if set(manifests) != set(reports): raise ValueError("ownership manifests and compiler reports need identical record indices")
        paths = [value.resolve() for value in (*vars(args).values(), *objects.values(), *manifests.values(), *reports.values())
            if isinstance(value, Path)]
        if len(set(paths)) != len(paths): raise ValueError("post completion inputs/outputs must be distinct")
        completed, proof = finalize(args.image.read_bytes(), parse_plan(args.plan.read_bytes()), args.material.read_bytes(),
            args.draft.read_bytes(), args.private.read_bytes(), read_material(args.scoped), args.child.read_bytes(),
            args.child_report.read_bytes(), release_plan(args.release_plan.read_bytes()), args.role, pre_release=args.pre_release,
            subjects=args.subjects.read_bytes() if args.subjects else None,
            mixed_plan=args.mixed_plan.read_bytes() if args.mixed_plan else None,
            objects={index: path.read_bytes() for index, path in objects.items()},
            ownership={index: Ownership(path.read_bytes(), reports[index].read_bytes()) for index, path in manifests.items()})
        atomic_write(args.output, completed)
        atomic_write(args.report, (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode())
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
