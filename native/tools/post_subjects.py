"""Early exact post-role selectors; ownership is proven later against actual objects."""
import json
from pathlib import Path

from reference_plan import MAX_PLAN, _object, _unique, parse_plan


def selectors(source):
    if source is None:
        return tuple({"kind": 1, "selector": {"section": ".text"}} for _ in range(2))
    if type(source) is not bytes or not 0 < len(source) <= MAX_PLAN:
        raise ValueError("post subjects need bounded immutable JSON bytes")
    document = json.loads(source, object_pairs_hook=_unique)
    _object(document, ("schema_version", "parent", "child"))
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("post subject version is unsupported")
    result = []
    for role in ("parent", "child"):
        selection = document[role]
        _object(selection, ("kind", "selector"))
        if type(selection["kind"]) is not int or selection["kind"] not in (1, 3):
            raise ValueError("post subjects require a whole section or complete function contribution")
        result.append(selection)
    # Validate through the existing schema without inventing a second selector parser.
    parse_plan(json.dumps({"schema_version": 1, "build_seed": "01" * 16, "container": "02" * 16,
        "records": [{"image": "02" * 16, "owner": index + 1, "subject": index + 1, "stage": 2,
            "capacity": 4096, **selection} for index, selection in enumerate(result)]}).encode())
    return tuple(result)


def artifact_arguments(parser, *, targeted=False):
    parser.add_argument("--post-subjects", type=Path)
    for name in ("object", "ownership", "ownership-report"):
        parser.add_argument("--post-" + name, action="append", default=[], **({"nargs": 2} if targeted else {}))


def _paths(args, field, target):
    from finalize_references import _bindings
    values = getattr(args, field, ())
    bindings = values if target is None else [binding for name, binding in values if name == target]
    return _bindings(bindings, objects=True)


def artifact_paths(args, plan, *, target=None, parent_object=None):
    paths = _paths(args, "post_object", target)
    if set(paths) != {index for index, record in enumerate(plan.records) if record.identity.kind == 3}:
        raise ValueError("post function objects must exactly cover the frozen function records")
    if parent_object is not None:
        for index in paths:
            if plan.records[index].identity.image == plan.container: paths[index] = parent_object
    return paths


def ownership_paths(args, plan, *, target=None):
    manifests = _paths(args, "post_ownership", target)
    reports = _paths(args, "post_ownership_report", target)
    required = {index for index, record in enumerate(plan.records) if record.generated_helpers}
    if set(manifests) != required or set(reports) != required:
        raise ValueError("post ownership and compiler reports must exactly cover the frozen helper records")
    return {index: (path, reports[index]) for index, path in manifests.items()}


def read_artifacts(args, plan, *, target=None, parent_object=None, parent_ownership=None):
    from function_inventory import Ownership
    result = {"subjects": args.post_subjects.read_bytes() if args.post_subjects else None,
        "objects": {index: path.read_bytes() for index, path in
            artifact_paths(args, plan, target=target, parent_object=parent_object).items()}}
    owned = ownership_paths(args, plan, target=target)
    parent_indices = {index for index in owned if plan.records[index].identity.image == plan.container}
    if parent_ownership is not None and (parent_object is None or not parent_indices or type(parent_ownership) is not Ownership):
        raise ValueError("replacement ownership requires an actual selected parent object")
    if parent_object is not None and parent_indices and parent_ownership is None:
        raise ValueError("replacement parent object needs its own fresh compiler ownership")
    if owned:
        result["ownership"] = {index: parent_ownership if parent_object is not None and index in parent_indices else
            Ownership(manifest.read_bytes(), report.read_bytes())
            for index, (manifest, report) in owned.items()}
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--properties", action="store_true", help="include early parent/child helper-policy bits")
    args = parser.parse_args()
    try:
        selected = selectors(args.config.read_bytes())
        values = [selection["kind"] for selection in selected]
        if args.properties: values.extend(int(selection["selector"].get("generated_helpers", False)) for selection in selected)
        print(";".join(map(str, values)))
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
