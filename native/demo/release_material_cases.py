"""Early/late artifact boundaries exercised through the actual release CLIs."""
import copy
import json
from pathlib import Path
import sys

from release_material import create_material, material_fold, parse_material, render_material_header
from release_plan import bind_material, expected_fold, parse_plan, render_header, validate_child

ROOT = Path(__file__).resolve().parents[1]


def check_early_material(args, directory, image, report, current, run, rejects):
    built = parse_material((args.build_dir / "release-material.private.json").read_bytes())
    if bind_material(built, image, report) != current:
        raise AssertionError("current child plan was not bound to its actual early material")
    sample = create_material()
    rejects(lambda: parse_plan(json.dumps(sample).encode()))
    rejects(lambda: parse_material(json.dumps(current).encode()))
    rejects(lambda: parse_material(b"x" * 16385))
    rejects(lambda: parse_material(b'{"seed":1,' + json.dumps(sample).encode()[1:]))
    for path, value in ((("schema_version",), True), (("seed",), -1), (("events",), {}),
            (("events", "environment", "word"), 1 << 32),
            (("events", "support", "tag"), sample["events"]["environment"]["tag"])):
        bad = copy.deepcopy(sample)
        target = bad
        for name in path[:-1]: target = target[name]
        target[path[-1]] = value
        rejects(lambda bad=bad: parse_material(json.dumps(bad).encode()))
    extra = copy.deepcopy(sample); extra["child_image_sha256"] = "0" * 64
    rejects(lambda: parse_material(json.dumps(extra).encode()))
    bound = bind_material(sample, image, report)
    sample["events"]["environment"]["word"] ^= 1
    if bound["events"] == sample["events"]:
        raise AssertionError("late plan retained mutable references into caller material")

    roots = []
    for namespace in ("path_events", "decoy_events"):
        material, header, plan = [directory / (namespace + suffix) for suffix in (".material.json", ".early.hpp", ".bound.json")]
        run([sys.executable, ROOT / "tools/prepare_release_material.py", material, header, "--event-namespace", namespace])
        early = parse_material(material.read_bytes())
        roots.append(early)
        if header.read_text(encoding="ascii") != render_material_header(early, namespace):
            raise AssertionError("early CLI header differs from its independent descriptors")
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (material, header)}
        command = [sys.executable, ROOT / "tools/prepare_release.py", args.child_image, args.child_report,
            plan, header, "--material", material, "--event-namespace", namespace]
        for _ in range(2):
            run(command)
            late = parse_plan(plan.read_bytes())
            validate_child(late, image, report)
            if (late != bind_material(early, image, report) or render_header(late, namespace) != header.read_text(encoding="ascii") or
                    expected_fold(late) != material_fold(early)):
                raise AssertionError("late child binding changed independent early material")
        if any((path.read_bytes(), path.stat().st_mtime_ns) != state for path, state in before.items()):
            raise AssertionError("late binding rewrote an upstream input and permits a build cycle")
        unchanged = plan.read_bytes()
        header.write_bytes(header.read_bytes() + b"\n")
        run(command, succeeds=False)
        if plan.read_bytes() != unchanged: raise AssertionError("header mismatch replaced a bound plan")
        header.write_bytes(before[header][0])
        material.write_text(json.dumps(create_material()), encoding="utf-8")
        run(command, succeeds=False)
        if plan.read_bytes() != unchanged: raise AssertionError("foreign early material replaced a bound plan")
        material.write_bytes(before[material][0])
        invalid_report = directory / (namespace + ".invalid-report.json")
        invalid_report.write_bytes(report + b"invalid")
        invalid = [invalid_report if item == args.child_report else item for item in command]
        run(invalid, succeeds=False)
        if plan.read_bytes() != unchanged: raise AssertionError("invalid child report replaced a bound plan")
        missing = [directory / "missing-material.json" if item == material else item for item in command]
        run(missing, succeeds=False)
        alias = [header if item == material else item for item in command]
        run(alias, succeeds=False)
        if plan.read_bytes() != unchanged: raise AssertionError("missing/aliased material replaced a bound plan")
    if roots[0] == roots[1] or material_fold(roots[0]) == material_fold(roots[1]):
        raise AssertionError("independent material generation reused a fixed root")
    collision = directory / "early-collision.json"
    collision.write_bytes(b"preserve")
    run([sys.executable, ROOT / "tools/prepare_release_material.py", collision, collision], succeeds=False)
    if collision.read_bytes() != b"preserve": raise AssertionError("early output alias replaced existing data")
