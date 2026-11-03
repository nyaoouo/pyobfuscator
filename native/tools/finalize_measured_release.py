"""Compose authenticated self-reference and measured release mask without changing code."""
import argparse
import hashlib
import json
from pathlib import Path

from atomic_artifact import atomic_write
from code_observation import reference_digest
from code_reference import plaintext, verify_reference
from code_subject import text_subject
from finalize_references import finalize as finalize_references
from measured_release import bind_draft, record_mask as measured_mask
from pe_data_patch import Write, apply_writes
from pe_layout import parse_image
from pe_release_record import finalize_image, locate_record
from reference_plan import parse_plan
from reference_slots import locate
from release_material import material_fold, parse_material


def finalize(image, plan, material, draft, *, packages=None):
    if len(plan.records) != 1:
        raise ValueError("pre-release bootstrap currently requires one exact self-text observation")
    selection = plan.records[0]; identity = selection.identity
    if identity.image != plan.container or identity.kind != 1 or identity.stage != 1:
        raise ValueError("pre-release observation must name this container's pre-release text")
    words = material_fold(material)
    subject = text_subject(parse_image(image), identity.subject)
    observed = reference_digest(image, parse_image(image), subject, identity.owner)
    record = bind_draft(draft, words, identity, observed)
    _, section, slots = locate(image, plan)
    _, release_offset = locate_record(image, version=2)
    referenced, reference_proof = finalize_references(image, plan, words, packages=packages)
    completed, release_proof = finalize_image(referenced, record, version=2)
    start = section.raw_offset + slots.offsets[0]
    result, proof = apply_writes(image, (Write(start, referenced[start:start + identity.capacity]),
        Write(release_offset + 24, measured_mask(record))))
    if result != completed or reference_digest(result, parse_image(result), subject, identity.owner) != observed:
        raise AssertionError("composed measured release changed code or produced different completion bytes")
    verify_reference(result[start:start + identity.capacity], plaintext(result, subject, identity), identity, words)
    return result, {"schema_version": 1, "format": "amd64-pe32+", "record_version": 2,
        "binding": "pre-release-complete-observation-v1", "plan_sha256": plan.digest.hex(),
        "draft_sha256": hashlib.sha256(draft).hexdigest(), "record_sha256": hashlib.sha256(record).hexdigest(),
        "idempotent": result == image, "reference": reference_proof, "release": release_proof, **proof}


def verify(image, completed, plan, material, draft):
    _, section, slots = locate(completed, plan)
    packages = {index: completed[section.raw_offset + offset:section.raw_offset + offset + record.identity.capacity]
        for index, (record, offset) in enumerate(zip(plan.records, slots.offsets))}
    expected, report = finalize(image, plan, material, draft, packages=packages)
    if expected != completed:
        raise ValueError("measured release differs from authenticated reference/mask data-only completion")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "plan", "material", "draft", "output"): parser.add_argument(name, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        inputs = {path.resolve() for path in (args.image, args.plan, args.material, args.draft)}
        outputs = (args.output.resolve(), args.report.resolve())
        if len(inputs) != 4 or outputs[0] == outputs[1] or any(path in inputs for path in outputs):
            raise ValueError("measured finalizer inputs and outputs must be distinct")
        result, proof = finalize(args.image.read_bytes(), parse_plan(args.plan.read_bytes()),
            parse_material(args.material.read_bytes()), args.draft.read_bytes())
        atomic_write(args.output, result)
        atomic_write(args.report, (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode())
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
