"""Real host completion with early function selectors and exact final COFF inputs."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools")); sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run, verify_image
from coff_layout import parse_object
from finalize_post_release import finalize, verify
from function_inventory import Ownership, create as inventory
from function_subject import function_subject
from generated_function_subject import generated_function_subject
from pe_layout import parse_image
from post_reference_plan import create
from prepare_scope_material import read_material
from post_subjects import artifact_paths, ownership_paths, read_artifacts
from reference_slots import render_header, render_source
from release_material import parse_material
from release_plan import bind_material


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def refuses(callback, message):
    try: callback()
    except ValueError as error:
        if message not in str(error): raise AssertionError(f"wrong post selector refusal: {error}") from error
    else: raise AssertionError("invalid post function selection/completion was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "objdump", "material", "private", "scoped", "child_ir", "child_coverage", "draft", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--cmake", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    material, private, scoped, draft = (args.material.read_bytes(), args.private.read_bytes(),
        read_material(args.scoped), args.draft.read_bytes())
    role = "post_function_host"
    section = {"kind": 1, "selector": {"section": ".text"}}
    function = lambda name: {"kind": 3, "selector": {"symbol": name, "aliases": [], "fragments": []}}
    document = {"schema_version": 1, "parent": function("extent_data_target"), "child": function("pyobf_demo_bound_compute")}
    expected = encoded(document)
    plan = create(material, role, private, scoped, pre_release=False, subjects=expected)
    default = create(material, role, private, scoped, pre_release=False)
    explicit = encoded({"schema_version": 1, "parent": section, "child": section})
    if default != create(material, role, private, scoped, pre_release=False, subjects=explicit):
        raise AssertionError("explicit default selectors changed the existing plan")
    invalid = []
    for field, value in (("schema_version", True), ("schema_version", 2), ("extra", 1)):
        changed = copy.deepcopy(document); changed[field] = value; invalid.append(encoded(changed))
    for change in ({"kind": 2, "selector": {"symbol": "extent_data_target"}},
            {"kind": True, "selector": {"section": ".text"}},
            {"kind": 3, "selector": {"symbol": "extent_data_target", "aliases": []}},
            function(""), {"kind": 1, "selector": {"section": ".data"}},
            {"kind": 3, "selector": {"symbol": "extent_data_target", "aliases": ["extent_data_target"], "fragments": []}}):
        changed = copy.deepcopy(document); changed["parent"] = change; invalid.append(encoded(changed))
    invalid += [b"", b"[]", b'{"schema_version":1,"schema_version":1,"parent":{},"child":{}}']
    for source in invalid:
        refuses(lambda source=source: create(material, role, private, scoped, pre_release=False, subjects=source), "")
    for field, value in (("symbol", "extent_data_target2"), ("aliases", ["declared_alias"]), ("fragments", ["declared_cold"])):
        changed = copy.deepcopy(document); changed["parent"]["selector"][field] = value
        other = create(material, role, private, scoped, pre_release=False, subjects=encoded(changed))
        if other.digest == plan.digest or other.records[0].identity.build == plan.records[0].identity.build:
            raise AssertionError("late selector/alias/fragment change retained its compiled identity")

    with tempfile.TemporaryDirectory(prefix="post-subjects-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        check_configuration(args.cmake, directory, expected, run)
        parent_object, child_object, child = (directory / name for name in ("parent.obj", "child.obj", "child.dll"))
        run([args.compiler, "-O2", "-fno-lto", "-ffunction-sections", "-c",
            ROOT / "tests/measurement/function_data_fixture.cpp", "-o", parent_object])
        run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", args.child_ir, "-o", child_object])
        run([args.compiler, "-shared", "-fno-lto", child_object, "-lbcrypt", "-o", child])
        child_report = directory / "child.final.json"
        verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump], child, args.child_coverage, child_report)
        child_bytes, report_bytes = child.read_bytes(), child_report.read_bytes()
        child_plan = bind_material(parse_material(material), child_bytes, report_bytes)
        ownership = Ownership(inventory(child_object.read_bytes(), args.child_ir.read_bytes(), args.child_coverage.read_bytes()),
            args.child_coverage.read_bytes())
        record_objects = []
        for version, source in ((1, "release_record.cpp"), (2, "measured_release_record.cpp")):
            obj = directory / f"record{version}.obj"; record_objects.append(obj)
            run([args.compiler, "-std=c++17", "-O0", "-fno-lto", "-I", ROOT / "src", "-c",
                ROOT / "backends/windows_user" / source, "-o", obj])
        cases = 0
        for pre_release in (False, True):
            for parent_function, child_function, generated in ((False, True, False), (True, False, False),
                    (True, True, False), (True, True, True)):
                child_selector = copy.deepcopy(document["child"] if child_function else section)
                if generated: child_selector["selector"]["generated_helpers"] = True
                selection = encoded({"schema_version": 1,
                    "parent": document["parent"] if parent_function else section,
                    "child": child_selector})
                plan = create(material, role, private, scoped, pre_release=pre_release, subjects=selection)
                work = directory / str(cases); work.mkdir(); cases += 1
                (work / "reference_slots.hpp").write_text(render_header(plan), encoding="utf-8")
                store = work / "store.cpp"; store.write_text(render_source(plan), encoding="utf-8")
                raw = work / "raw.dll"
                run([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-shared", "-I", ROOT / "src", "-I", work,
                    parent_object, store, record_objects[int(pre_release)], "-o", raw])
                objects = {index: (parent_object if record.identity.image == plan.container else child_object).read_bytes()
                    for index, record in enumerate(plan.records) if record.identity.kind == 3}
                parameters = (plan, material, draft, private, scoped, child_bytes, report_bytes, child_plan, role)
                options = {"pre_release": pre_release, "subjects": selection, "objects": objects}
                if generated: options["ownership"] = {len(plan.records) - 1: ownership}
                original = raw.read_bytes()
                completed, proof = finalize(original, *parameters, **options)
                for part in parse_image(original).layout.sections:
                    if part.flags & 0x20000000 and original[part.raw_offset:part.raw_offset + part.raw_size] != \
                            completed[part.raw_offset:part.raw_offset + part.raw_size]:
                        raise AssertionError("late function reference fill changed executable bytes")
                if proof != verify(original, completed, *parameters, **options):
                    raise AssertionError("function completion proof differs from exact independent reconstruction")
                repeated, again = finalize(completed, *parameters, **options)
                if repeated != completed or not again["idempotent"]:
                    raise AssertionError("function references regenerated code or changed finalized records")
                for index, record in enumerate(plan.records):
                    if record.identity.kind != 3: continue
                    target = original if record.identity.image == plan.container else child_bytes
                    arguments = (objects[index], target, parse_image(target), record.identity.subject, record.symbol)
                    subject = generated_function_subject(*arguments, ownership, aliases=record.aliases, fragments=record.fragments) \
                        if record.generated_helpers else function_subject(*arguments, aliases=record.aliases, fragments=record.fragments)
                    evidence = proof["reference"]["records"][index]
                    if evidence["ranges"] != [{"rva": span.rva, "size": span.size} for span in subject.ranges] or \
                            evidence["object_sha256"] != hashlib.sha256(objects[index]).hexdigest():
                        raise AssertionError("post proof omitted actual complete contribution/object identity")
                refuses(lambda: finalize(original, *parameters, **{**options, "subjects": None}), "early role/source binding")
                refuses(lambda: finalize(original, *parameters, **{**options, "objects": {}}), "targets/objects")
                extra = {**objects, len(plan.records): parent_object.read_bytes()}
                refuses(lambda: finalize(original, *parameters, **{**options, "objects": extra}), "targets/objects")
                if generated:
                    refuses(lambda: finalize(original, *parameters, **{**options, "ownership": {}}), "exactly cover")
                for index in objects:
                    foreign = dict(objects)
                    foreign[index] = child_object.read_bytes() if plan.records[index].identity.image == plan.container else parent_object.read_bytes()
                    refuses(lambda: finalize(original, *parameters, **{**options, "objects": foreign}), "offset-zero root")
                    damaged = bytearray(objects[index]); obj = parse_object(bytes(damaged))
                    root = next(symbol for symbol in obj.symbols if symbol.name == plan.records[index].symbol and symbol.type == 0x20)
                    damaged[obj.sections[root.section - 1].offset] ^= 1
                    changed = {**objects, index: bytes(damaged)}
                    refuses(lambda: finalize(original, *parameters, **{**options, "objects": changed}), "exact relocation evaluation")
                cli_cases(work, original, parameters, options, parent_object, child_object)
    print(f"{cases} real pre/post section/function combinations: frozen selectors, actual CFF child, exact objects, data-only/idempotent proof and CLI/mutation refusals pass; production runtime wiring remains separate")


def check_configuration(cmake, directory, selection, run):
    script = directory / "configure.cmake"
    source = directory / "subjects.json"
    source.write_bytes(selection)
    script.write_text('set(PROJECT_SOURCE_DIR "' + ROOT.as_posix() + '")\n' +
        'include("' + (ROOT / 'demo/cmake/PostSubjects.cmake').as_posix() + '")\n' +
        'if(NOT PYOBF_DEMO_POST_PARENT_KIND EQUAL 3 OR NOT PYOBF_DEMO_POST_CHILD_KIND EQUAL 3)\n' +
        'message(FATAL_ERROR "exact function selectors were lost")\nendif()\n', encoding="utf-8")
    command = [cmake, f"-DPython3_EXECUTABLE={sys.executable}", "-DPYOBF_NATIVE_DEMO_POST_CODE_HASH=ON",
        f"-DPYOBF_NATIVE_DEMO_POST_SUBJECTS={source}", "-P", script]
    run(command)
    invalid = list(command); invalid[2] = "-DPYOBF_NATIVE_DEMO_POST_CODE_HASH=OFF"
    if "requires post-release code measurement" not in run(invalid, succeeds=False).stderr:
        raise AssertionError("CMake admitted subjects without the actual runtime feature")
    for data in (b"", b"[]", selection.replace(b'"kind":3', b'"kind":2')):
        source.write_bytes(data)
        if "Invalid post-release subjects" not in run(command, succeeds=False).stderr:
            raise AssertionError("CMake failed outside exact subject validation")
    source.unlink()
    if "Invalid post-release subjects" not in run(command, succeeds=False).stderr:
        raise AssertionError("CMake silently dropped a missing subject file")


def cli_cases(work, raw, parameters, options, parent_object, child_object):
    names = ("plan", "material", "draft", "private", "scoped", "child", "child-report", "release-plan")
    values = (parameters[0].canonical, *parameters[1:7], encoded(parameters[7]))
    paths = {name: work / name for name in names}
    for name, value in zip(names, values): paths[name].write_bytes(value)
    image, subjects, output, report = (work / name for name in ("input.dll", "subjects", "output.dll", "proof.json"))
    image.write_bytes(raw); subjects.write_bytes(options["subjects"])
    bindings = [f"{index}={parent_object if record.identity.image == parameters[0].container else child_object}"
        for index, record in enumerate(parameters[0].records) if record.identity.kind == 3]
    owned_paths = {}
    for index, proof in options.get("ownership", {}).items():
        for name, data in (("ownership", proof.manifest), ("ownership-report", proof.report)):
            path = work / (name + str(index)); path.write_bytes(data); owned_paths[name, index] = path
    consumer = SimpleNamespace(post_subjects=subjects, post_object=bindings,
        post_ownership=[f"{index}={path}" for (name, index), path in owned_paths.items() if name == "ownership"],
        post_ownership_report=[f"{index}={path}" for (name, index), path in owned_paths.items() if name == "ownership-report"])
    expected = {name: options[name] for name in ("subjects", "objects", "ownership") if name in options}
    if read_artifacts(consumer, parameters[0]) != expected:
        raise AssertionError("consumer lost its exact selected object snapshots")
    if owned_paths:
        missing = copy.copy(consumer); missing.post_ownership_report = []
        refuses(lambda: ownership_paths(missing, parameters[0]), "exactly cover")
        duplicate = copy.copy(consumer); duplicate.post_ownership = [*consumer.post_ownership, consumer.post_ownership[0]]
        refuses(lambda: ownership_paths(duplicate, parameters[0]), "duplicate artifact")
    for invalid, reason in (([], "exactly cover"), (bindings + [bindings[0]], "duplicate artifact binding"),
            (bindings + ["01=missing.obj"], "canonical record index"),
            (bindings + [f"{len(parameters[0].records)}={child_object}"], "exactly cover")):
        malformed = SimpleNamespace(post_subjects=subjects, post_object=invalid)
        refuses(lambda malformed=malformed: artifact_paths(malformed, parameters[0]), reason)
    for name in ("post_object", "post_ownership", "post_ownership_report"):
        setattr(consumer, name, [["actual", binding] for binding in getattr(consumer, name)] + [["sibling", f"0={subjects}"]])
    if read_artifacts(consumer, parameters[0], target="actual") != expected:
        raise AssertionError("another target supplied a selected function object")
    if owned_paths:
        omitted = copy.copy(consumer)
        omitted.post_ownership = [["sibling", binding] for name, binding in consumer.post_ownership if name == "actual"]
        refuses(lambda: ownership_paths(omitted, parameters[0], target="actual"), "exactly cover")
    planned = work / "planned.json"
    plan_command = [sys.executable, ROOT / "tools/post_reference_plan.py", paths["material"], parameters[-1],
        paths["private"], paths["scoped"], planned, "--subjects", subjects]
    if options["pre_release"]: plan_command.append("--pre-release")
    run(plan_command)
    if planned.read_bytes() != parameters[0].canonical:
        raise AssertionError("plan CLI differs from its frozen pre-codegen selection")
    invocation = list(plan_command); invocation[invocation.index(planned)] = subjects
    run(invocation, succeeds=False)
    if subjects.read_bytes() != options["subjects"]: raise AssertionError("plan output alias replaced the early selectors")
    command = [sys.executable, ROOT / "tools/finalize_post_release.py", image, paths["plan"], paths["material"], paths["draft"], output]
    for name in names[3:]: command.extend(("--" + name, paths[name]))
    command.extend(("--role", parameters[-1], "--report", report, "--subjects", subjects))
    if options["pre_release"]: command.append("--pre-release")
    for index, record in enumerate(parameters[0].records):
        if record.identity.kind == 3:
            command.extend(("--object", f"{index}={parent_object if record.identity.image == parameters[0].container else child_object}"))
    for (name, index), path in owned_paths.items(): command.extend(("--" + name, f"{index}={path}"))
    run(command)
    # Verification extracts this run's ciphertext instead of comparing random envelopes.
    verify(raw, output.read_bytes(), *parameters, **options)
    output.write_bytes(b"keep-image"); report.write_bytes(b"keep-report")
    invalid = [command + ["--object", "01=missing.obj"], command + ["--object", command[-1]],
        command[:command.index("--subjects")] + command[command.index("--subjects") + 2:]]
    bound_objects = {parent_object if record.identity.image == parameters[0].container else child_object
        for record in parameters[0].records if record.identity.kind == 3}
    for target in (subjects, *bound_objects, *owned_paths.values()):
        invocation = list(command); invocation[invocation.index(output)] = target; invalid.append(invocation)
    for target in owned_paths.values():
        invocation = list(command); invocation[invocation.index(report)] = target; invalid.append(invocation)
    originals = {target: target.read_bytes() for target in (subjects, parent_object, child_object, *owned_paths.values())}
    for (name, index), path in owned_paths.items():
        invocation = list(command)
        position = invocation.index("--" + name)
        invalid.append(invocation[:position] + invocation[position + 2:])
        invalid.append(command + ["--" + name, f"{index}={path}"])
    for invocation in invalid:
        run(invocation, succeeds=False)
        if output.read_bytes() != b"keep-image" or report.read_bytes() != b"keep-report":
            raise AssertionError("refused function CLI replaced prior outputs")
        if any(target.read_bytes() != data for target, data in originals.items()):
            raise AssertionError("refused function output alias replaced a trusted selector/object")
    for (name, index), path in owned_paths.items():
        if name != "ownership-report": continue
        try:
            path.write_bytes(originals[path] + b" ")
            failed = run(command, succeeds=False)
            if "stale" not in failed.stderr or output.read_bytes() != b"keep-image" or report.read_bytes() != b"keep-report":
                raise AssertionError("post CLI stale compiler report failed outside its exact preserved-output boundary")
        finally: path.write_bytes(originals[path])


if __name__ == "__main__": main()
