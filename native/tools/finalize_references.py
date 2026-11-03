"""Fill reserved data only, after final code and compiler ownership are fixed."""
import argparse
import hashlib
import json
from pathlib import Path

from atomic_artifact import atomic_write
from code_observation import reference_digest
from code_reference import build_reference, plaintext, verify_reference
from code_subject import text_subject, unwind_interval
from coff_symbols import image_symbols
from function_subject import function_subject
from function_inventory import Ownership
from generated_function_subject import generated_function_subject
from measured_scope import build_material, verify_material
from pe_data_patch import Write, apply_writes
from pe_layout import parse_image
from reference_plan import _role, parse_plan
from reference_slots import MATERIAL_BYTES, locate
from release_material import material_fold, parse_material


def _subject(data, selection, object_data, ownership=None):
    image = parse_image(data); identity = selection.identity
    if identity.kind == 1: return text_subject(image, identity.subject)
    if identity.kind == 3:
        if selection.generated_helpers:
            return generated_function_subject(object_data, data, image, identity.subject, selection.symbol, ownership,
                aliases=selection.aliases, fragments=selection.fragments)
        return function_subject(object_data, data, image, identity.subject, selection.symbol,
            aliases=selection.aliases, fragments=selection.fragments)
    matches = [symbol for symbol in image_symbols(data, image) if
        symbol.name == selection.symbol and symbol.type == 0x20 and symbol.section > 0]
    if len(matches) != 1: raise ValueError("unwind selector needs one exact final function symbol")
    symbol = matches[0]
    return unwind_interval(data, image, identity.subject, image.layout.sections[symbol.section - 1].rva + symbol.value)


def _packages(values, indices, label):
    if values is not None and (type(values) is not dict or any(type(index) is not int for index in values) or
            set(values) != set(indices) or any(type(value) is not bytes for value in values.values())):
        raise ValueError(f"presealed {label} must exactly cover the frozen record indices")


def finalize(image, plan, private_words, *, targets=None, objects=None, ownership=None, packages=None,
        materials=None, material_packages=None):
    targets = {} if targets is None else targets
    objects = {} if objects is None else objects
    ownership = {} if ownership is None else ownership
    materials = {} if materials is None else materials
    required = {record.identity.image for record in plan.records} - {plan.container}
    function_indices = {index for index, record in enumerate(plan.records) if record.identity.kind == 3}
    owned_indices = {index for index, record in enumerate(plan.records) if record.generated_helpers}
    if type(targets) is not dict or set(targets) != required or type(objects) is not dict or set(objects) != function_indices:
        raise ValueError("reference targets/objects must exactly match the frozen selection")
    if (type(ownership) is not dict or any(type(index) is not int for index in ownership) or
            set(ownership) != owned_indices or any(type(value) is not Ownership for value in ownership.values())):
        raise ValueError("generated ownership inputs must exactly cover the frozen helper policy")
    if any(type(data) is not bytes for data in (*targets.values(), *objects.values())):
        raise ValueError("reference artifacts must be immutable byte snapshots")
    _packages(packages, range(len(plan.records)), "references")
    _packages(material_packages, plan.scope_materials, "scope materials")
    if (type(materials) is not dict or any(type(index) is not int for index in materials) or
            set(materials) != set(plan.scope_materials) or
            any(type(value) is not bytes or len(value) != 32 for value in materials.values())):
        raise ValueError("scope material inputs must exactly cover selected slots with32 immutable bytes each")
    _, section, slots = locate(image, plan)
    artifacts = {plan.container: image, **targets}
    # Cross-module reference stores need their own admitted DAG/batch contract, not iteration.
    for data in targets.values():
        if any(part.name == b".pyobm" for part in parse_image(data).layout.sections):
            raise ValueError("cross-module reference storage needs an explicit finalization dependency contract")
    writes, records, expected = [], [], []
    for index, (record, offset) in enumerate(zip(plan.records, slots.offsets)):
        identity = record.identity; data = artifacts[identity.image]
        subject = _subject(data, record, objects.get(index), ownership.get(index))
        body = plaintext(data, subject, identity)
        start = section.raw_offset + offset
        current = image[start:start + identity.capacity]
        if packages is not None:
            sealed = packages[index]
            verify_reference(sealed, body, identity, private_words)
            if any(current) and current != sealed:
                raise ValueError("presealed reference differs from already finalized storage")
        elif any(current):
            verify_reference(current, body, identity, private_words)
            sealed = current
        else:
            sealed = build_reference(data, subject, identity, private_words)
        writes.append(Write(start, sealed)); expected.append(body)
        row = {"index": index, "image": identity.image.hex(), "owner": identity.owner,
            "subject": identity.subject, "kind": identity.kind, "stage": identity.stage,
            "offset": start, "capacity": identity.capacity,
            "ranges": [{"rva": span.rva, "size": span.size} for span in subject.ranges],
            "target_sha256": hashlib.sha256(data).hexdigest(),
            "object_sha256": hashlib.sha256(objects[index]).hexdigest() if index in objects else None,
            "ciphertext_sha256": hashlib.sha256(sealed).hexdigest()}
        if index in ownership:
            row["ownership_sha256"] = hashlib.sha256(ownership[index].manifest).hexdigest()
            row["compiler_report_sha256"] = hashlib.sha256(ownership[index].report).hexdigest()
        if index in plan.scope_materials:
            digest = reference_digest(data, parse_image(data), subject, identity.owner)
            material_start = section.raw_offset + slots.material_offsets[index]
            current_material = image[material_start:material_start + MATERIAL_BYTES]
            if material_packages is not None:
                encrypted = material_packages[index]
                verify_material(encrypted, materials[index], private_words, identity, digest)
                if any(current_material) and current_material != encrypted:
                    raise ValueError("presealed scope material differs from already finalized storage")
            elif any(current_material):
                verify_material(current_material, materials[index], private_words, identity, digest)
                encrypted = current_material
            else:
                encrypted = build_material(materials[index], private_words, identity, digest)
            writes.append(Write(material_start, encrypted))
            row["material"] = {"offset": material_start, "capacity": MATERIAL_BYTES,
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest()}
        records.append(row)
    finalized, proof = apply_writes(image, tuple(writes))
    locate(finalized, plan)
    for index, record in enumerate(plan.records):
        if record.identity.image != plan.container: continue
        subject = _subject(finalized, record, objects.get(index), ownership.get(index))
        if plaintext(finalized, subject, record.identity) != expected[index]:
            raise AssertionError("reference fill fed back into measured code")
    return finalized, {"schema_version": 2 if plan.scope_materials else 1, "scheme": "pe-amd64-dir64-owner-sha256-v1",
        "plan_sha256": plan.digest.hex(), "container": plan.container.hex(),
        "idempotent": finalized == image, "records": records, **proof}


def _bindings(values, *, objects=False, label="object"):
    result = {}
    for value in values:
        key, separator, path = value.partition("=")
        if not separator or not path: raise ValueError("artifact binding needs identity=path")
        if objects:
            if not key.isascii() or not key.isdecimal() or str(int(key)) != key:
                raise ValueError(f"{label} binding needs a canonical record index")
            key = int(key)
        else: key = _role(key)
        if key in result: raise ValueError("duplicate artifact binding")
        result[key] = Path(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "plan", "material", "output"): parser.add_argument(name, type=Path)
    parser.add_argument("--target", action="append", default=[], help="frozen external image-role hex=path")
    parser.add_argument("--object", action="append", default=[], help="function record index=actual final compiler object")
    parser.add_argument("--scope-material", action="append", default=[], help="selected record index=early32-byte material file")
    parser.add_argument("--ownership", action="append", default=[], help="generated function record index=private emission manifest")
    parser.add_argument("--ownership-report", action="append", default=[], help="generated function record index=actual CFF compiler report")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        targets, objects = _bindings(args.target), _bindings(args.object, objects=True)
        materials = _bindings(args.scope_material, objects=True, label="scope material")
        manifests, reports = _bindings(args.ownership, objects=True), _bindings(args.ownership_report, objects=True)
        if set(manifests) != set(reports): raise ValueError("ownership manifests and compiler reports need identical record indices")
        inputs = [args.image, args.plan, args.material, *targets.values(), *objects.values(), *materials.values(),
            *manifests.values(), *reports.values()]
        outputs = [args.output.resolve(), args.report.resolve()]
        if outputs[0] == outputs[1] or any(output in {path.resolve() for path in inputs} for output in outputs):
            raise ValueError("reference outputs must not alias any input or each other")
        result, report = finalize(args.image.read_bytes(), parse_plan(args.plan.read_bytes()),
            material_fold(parse_material(args.material.read_bytes())),
            targets={key: path.read_bytes() for key, path in targets.items()},
            objects={key: path.read_bytes() for key, path in objects.items()},
            ownership={key: Ownership(path.read_bytes(), reports[key].read_bytes()) for key, path in manifests.items()},
            materials={key: path.read_bytes() for key, path in materials.items()})
        atomic_write(args.output, result)
        atomic_write(args.report, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
