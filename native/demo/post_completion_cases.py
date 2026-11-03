"""Post-role finalization refusals reuse the existing exact composer and CLI."""
import copy
import json
from pathlib import Path
import sys

from finalize_post_release import finalize, verify
from payload_binding import private_reference
from post_mixed_binding import mixed_private_reference
from post_reference_plan import create as create_plan
from code_observation import reference_digest
from finalize_references import _subject
from function_inventory import Ownership
from measured_scope import verify_material
from pe_layout import parse_image, rva_section
from reference_plan import parse_plan
from reference_slots import locate, MATERIAL_BYTES
from release_material import parse_material, material_fold
from post_subjects import read_artifacts


def rejects(function):
    try: function()
    except ValueError: return
    raise AssertionError("invalid post completion received authority")


def completion_cases(args, directory, raw, final, inputs, options, run):
    plan = inputs[0]
    for index, proof in options.get("ownership", {}).items():
        if plan.records[index].identity.image != plan.container: continue
        rejects(lambda: read_artifacts(args, plan, parent_object=args.object))
        rejects(lambda: read_artifacts(args, plan, parent_object=args.object, parent_ownership=object()))
        replacement = read_artifacts(args, plan, parent_object=args.object, parent_ownership=proof)
        if replacement != {key: options[key] for key in ("subjects", "objects", "ownership")}:
            raise AssertionError("actual same-object replacement lost its independent ownership snapshot")
        changed = {**options["ownership"], index: Ownership(proof.manifest, proof.report + b" ")}
        rejects(lambda: finalize(raw, *inputs, **{**options, "ownership": changed}))
    _, section, slots = locate(final, plan)
    positions = [section.raw_offset + slots.offsets[index] + record.identity.capacity - 1
        for index, record in enumerate(plan.records)]
    positions += [section.raw_offset + slots.material_offsets[index] + MATERIAL_BYTES - 1 for index in plan.scope_materials]
    image = parse_image(final)
    for index, record in enumerate(plan.records):
        if record.identity.image != plan.container: continue
        subject = _subject(final, record, options["objects"].get(index), options.get("ownership", {}).get(index))
        for span in subject.ranges:
            part = rva_section(image, span.rva, span.size)
            positions.append(part.raw_offset + span.rva - part.rva)
    for position in positions:
        changed = bytearray(final); changed[position] ^= 1
        rejects(lambda changed=changed: verify(raw, bytes(changed), *inputs, **options))
        rejects(lambda changed=changed: finalize(bytes(changed), *inputs, **options))
    for index in range(1, len(inputs)):
        changed = list(inputs)
        if isinstance(changed[index], bytes): changed[index] = changed[index] + b"x"
        elif isinstance(changed[index], str): changed[index] += "-foreign"
        else:
            changed[index] = copy.deepcopy(changed[index]); changed[index]["seed"] ^= 1
        rejects(lambda changed=changed: finalize(raw, *changed, **options))
    changed = json.loads(plan.canonical)
    changed["records"][-1]["owner"] ^= 1
    rejects(lambda: finalize(raw, parse_plan(json.dumps(changed).encode()), *inputs[1:], **options))
    rejects(lambda: finalize(raw, *inputs, pre_release=not args.pre_release))
    root = bytes([inputs[4][0] ^ 1]) + inputs[4][1:]
    material = parse_material(inputs[1])
    replacement = (mixed_private_reference(material, json.loads(inputs[3])["routing_tag"], root, options["mixed_plan"])
        if options.get("mixed_plan") is not None else
        private_reference(material, json.loads(inputs[3])["routing_tag"], scoped_material=root))
    private = (json.dumps(replacement,
        sort_keys=True, indent=2) + "\n").encode()
    rotated = create_plan(inputs[1], args.role, private, root, pre_release=args.pre_release,
                          subjects=options["subjects"], mixed_plan=options.get("mixed_plan"))
    if rotated.digest == plan.digest: raise AssertionError("root rotation retained the old parent plan")
    changed = list(inputs); changed[0], changed[3], changed[4] = rotated, private, root
    rejects(lambda: finalize(raw, *changed, **options))
    index = plan.scope_materials[0]
    identity, replacement = plan.records[index].identity, rotated.records[index].identity
    image = parse_image(final)
    # Hold final code/geometry constant and transplant the old envelope into a rotated build identity.
    subject = _subject(final, plan.records[index], options["objects"].get(index), options.get("ownership", {}).get(index))
    digest = reference_digest(final, image, subject, identity.owner)
    start = section.raw_offset + slots.material_offsets[index]
    package = final[start:start + MATERIAL_BYTES]
    verify_material(package, inputs[4], material_fold(material), identity, digest)
    rejects(lambda: verify_material(package, root, material_fold(material), replacement, digest))

    names = ("image", "plan", "material", "draft", "private", "scoped", "child", "child_report", "release_plan")
    paths = {name: directory / ("cli-" + name) for name in names}
    originals = {name: getattr(args, "raw_image" if name == "image" else name).read_bytes() for name in names}
    if options["subjects"] is not None:
        paths["subjects"] = directory / "cli-subjects"
        originals["subjects"] = options["subjects"]
    if options.get("mixed_plan") is not None:
        paths["mixed-plan"] = directory / "cli-mixed-plan"
        originals["mixed-plan"] = options["mixed_plan"]
    for index, data in options["objects"].items():
        name = "object" + str(index); paths[name] = directory / ("cli-" + name); originals[name] = data
    for index, source in options.get("ownership", {}).items():
        for field, data in (("ownership", source.manifest), ("ownership-report", source.report)):
            name = field + str(index); paths[name] = directory / ("cli-" + name); originals[name] = data
    for name, path in paths.items(): path.write_bytes(originals[name])
    output, report = directory / "cli-output.dll", directory / "cli-output.json"
    output.write_bytes(b"preserve-image"); report.write_bytes(b"preserve-report")
    def command():
        result = [sys.executable, Path(__file__).resolve().parents[1] / "tools/finalize_post_release.py",
            *(paths[name] for name in names[:4]), output, "--private", paths["private"], "--scoped", paths["scoped"],
            "--child", paths["child"], "--child-report", paths["child_report"], "--release-plan", paths["release_plan"],
            "--role", args.role, "--report", report, *(["--pre-release"] if args.pre_release else [])]
        if "subjects" in paths: result.extend(("--subjects", paths["subjects"]))
        if "mixed-plan" in paths: result.extend(("--mixed-plan", paths["mixed-plan"]))
        for index in options["objects"]: result.extend(("--object", f"{index}={paths['object' + str(index)]}"))
        for index in options.get("ownership", {}):
            for field in ("ownership", "ownership-report"):
                result.extend(("--" + field, f"{index}={paths[field + str(index)]}"))
        return result
    def preserved():
        if output.read_bytes() != b"preserve-image" or report.read_bytes() != b"preserve-report":
            raise AssertionError("post CLI refusal replaced existing outputs")
    for name, path in paths.items():
        path.write_bytes(b"")
        run(command(), succeeds=False); preserved(); path.write_bytes(originals[name])
    for name in paths:
        invocation = command(); invocation[invocation.index(output)] = paths[name]
        run(invocation, succeeds=False); preserved()
        invocation = command(); invocation[invocation.index(report)] = paths[name]
        run(invocation, succeeds=False); preserved()
    invocation = command(); invocation[invocation.index(report)] = output
    run(invocation, succeeds=False); preserved()
    if any(path.read_bytes() != originals[name] for name, path in paths.items()):
        raise AssertionError("rejected post output alias changed an input")
    run(command())
    if verify(raw, output.read_bytes(), *inputs, **options) != json.loads(report.read_text()):
        raise AssertionError("actual post CLI proof differs from exact recomputation")
