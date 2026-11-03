"""Explicit production measured inputs for existing outer failure and cost consumers."""
from pathlib import Path

from pe_release_record import finalize_image
from post_subjects import artifact_arguments, artifact_paths, read_artifacts


def arguments(parser):
    artifact_arguments(parser, targeted=True)
    parser.add_argument("--measured-material", type=Path)
    parser.add_argument("--measured-reference", nargs=3, action="append", default=[], metavar=("TARGET", "PLAN", "OBJECT"))
    parser.add_argument("--measured-reader", nargs=3, action="append", default=[], metavar=("TARGET", "OBJECT", "INVENTORY"))
    for name in ("material", "private", "child", "child-report", "release-plan"):
        parser.add_argument("--post-" + name, type=Path)
    parser.add_argument("--post-pre-release", action="store_true")


def bind(args, parser, names):
    args.measured_inputs = None
    args.post_inputs = None
    args.reader_inputs = {}
    post = (args.post_material, args.post_private, args.post_child, args.post_child_report, args.post_release_plan)
    bindings = [*args.post_object, *args.post_ownership, *args.post_ownership_report]
    if (args.post_subjects or bindings) and not all(post): parser.error("function subjects need exact post inputs")
    if any(name not in names for name, binding in bindings): parser.error("unknown post function-object/ownership target")
    if any(post) and (not all(post) or not args.measured_material): parser.error("post completion needs all exact early/child inputs")
    if args.post_pre_release and not all(post): parser.error("post pre-release selector needs the explicit post profile")
    if not args.measured_material and not args.measured_reference:
        if args.measured_reader: parser.error("owner reader inputs need measured references")
        return
    if not args.measured_material: parser.error("measured reference inputs need independent early material")
    from reference_plan import parse_plan
    from release_material import parse_material
    records = {}
    try:
        for name, plan, obj in args.measured_reference:
            if name in records or name not in names: raise ValueError("duplicate or unknown measured target")
            path = Path(obj)
            if not path.is_file(): raise ValueError("measured reference needs its actual native storage object")
            records[name] = (parse_plan(Path(plan).read_bytes()), path)
        if set(records) != set(names): raise ValueError("measured references must exactly cover consuming targets")
        plans = {name: Path(plan) for name, plan, obj in args.measured_reference}
        for name, obj, manifest in args.measured_reader:
            if name not in records or name in args.reader_inputs: raise ValueError("duplicate or unknown owner reader target")
            if not Path(obj).is_file() or not Path(manifest).is_file(): raise ValueError("owner reader needs its actual object/inventory")
            args.reader_inputs[name] = (Path(obj), Path(manifest), plans[name])
        if args.reader_inputs and set(args.reader_inputs) != set(names): raise ValueError("owner readers must exactly cover consuming targets")
        args.measured_inputs = (parse_material(args.measured_material.read_bytes()), records, args.record.read_bytes())
        if all(post):
            from prepare_scope_material import read_material
            from release_plan import parse_plan as release_plan
            args.post_inputs = (args.measured_material.read_bytes(), args.post_private.read_bytes(), read_material(args.post_material),
                args.post_child.read_bytes(), args.post_child_report.read_bytes(), release_plan(args.post_release_plan.read_bytes()))
            for name in names: read_artifacts(args, records[name][0], target=name)
    except (OSError, ValueError) as error: parser.error(str(error))


def record_source(args, root):
    measured = args.measured_inputs and (not args.post_inputs or args.post_pre_release)
    return root / "backends/windows_user" / ("measured_release_record.cpp" if measured else "release_record.cpp")


def objects(args, name):
    return [args.measured_inputs[1][name][1]] if args.measured_inputs else []


def function_sections(args, name):
    if name in args.reader_inputs: return True
    if not args.post_inputs: return False
    plan = args.measured_inputs[1][name][0]
    return any(record.identity.kind == 3 and record.identity.image == plan.container for record in plan.records)


def function_object_digests(args, name, parent_object):
    import hashlib
    if not args.post_inputs: return {}
    plan = args.measured_inputs[1][name][0]
    return {str(index): hashlib.sha256(path.read_bytes()).hexdigest() for index, path in
        artifact_paths(args, plan, target=name, parent_object=parent_object).items()}


def emission_ownership(args, name, native_object, source, report, run):
    if not args.post_inputs and name not in args.reader_inputs: return None
    plan = args.measured_inputs[1][name][0]
    if name not in args.reader_inputs and not any(record.generated_helpers and record.identity.image == plan.container for record in plan.records):
        return None
    from function_inventory import Ownership, create
    if report is None:
        report = Path(str(native_object) + ".untransformed-ownership.json")
        run(list(map(str, [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-untransformed-ownership",
            f"-pyobf-cff-report={report}", "-disable-output", source])))
    compiler_report = report.read_bytes()
    return Ownership(create(native_object.read_bytes(), source.read_bytes(), compiler_report), compiler_report)


def reader_arguments(args, name, *, native_object=None, inventory_path=None):
    if name not in args.reader_inputs: return []
    from owner_reader_image import checker_arguments
    obj, manifest, plan = args.reader_inputs[name]
    return checker_arguments(obj if native_object is None else native_object,
        manifest if inventory_path is None else inventory_path, plan)


def function_ownership_digests(args, name, parent_object, parent_ownership):
    import hashlib
    if not args.post_inputs: return {}
    from function_inventory import helpers
    plan = args.measured_inputs[1][name][0]
    artifacts = read_artifacts(args, plan, target=name, parent_object=parent_object, parent_ownership=parent_ownership)
    return {str(index): {"manifest_sha256": hashlib.sha256(proof.manifest).hexdigest(),
        "compiler_report_sha256": hashlib.sha256(proof.report).hexdigest(),
        "helper_count": len(helpers(artifacts["objects"][index], proof, plan.records[index].symbol))}
        for index, proof in artifacts.get("ownership", {}).items()}


def complete(args, raw, name, *, parent_object=None, parent_ownership=None):
    if not args.measured_inputs: return finalize_image(raw, args.record.read_bytes())[0]
    from finalize_measured_release import finalize
    material, references, draft = args.measured_inputs
    if args.post_inputs:
        from finalize_post_release import finalize as finalize_post
        raw_material, private, scoped, child, report, child_plan = args.post_inputs
        return finalize_post(raw, references[name][0], raw_material, draft, private, scoped, child, report,
            child_plan, name + "_unfinalized", pre_release=args.post_pre_release,
            **read_artifacts(args, references[name][0], target=name, parent_object=parent_object,
                parent_ownership=parent_ownership))[0]
    return finalize(raw, references[name][0], material, draft)[0]
