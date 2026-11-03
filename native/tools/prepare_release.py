"""Bind an exact child to early material, or prepare legacy child-first events."""

import argparse
import json
from pathlib import Path

from atomic_artifact import atomic_write
from release_material import parse_material, render_material_header
from release_plan import bind_material, create_plan, render_header


def main():
    parser = argparse.ArgumentParser()
    for name in ("image", "report", "plan_output", "header_output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--event-namespace", choices=("path_events", "decoy_events"), default="path_events")
    parser.add_argument("--material", type=Path,
        help="bind existing early material/header; write only the late plan")
    args = parser.parse_args()
    if len({getattr(args, name).resolve() for name in ("image", "report", "plan_output", "header_output")}) != 4:
        parser.error("private release inputs and outputs must have distinct paths")
    if args.material and args.material.resolve() in {
            getattr(args, name).resolve() for name in ("image", "report", "plan_output", "header_output")}:
        parser.error("private release early material must have a distinct path")
    try:
        if args.material:
            material = parse_material(args.material.read_bytes())
            header = render_material_header(material, args.event_namespace).encode("ascii")
            if args.header_output.read_bytes() != header:
                parser.error("private release early header differs from its material")
            plan = bind_material(material, args.image.read_bytes(), args.report.read_bytes())
        else:
            plan = create_plan(args.image.read_bytes(), args.report.read_bytes())
            header = render_header(plan, args.event_namespace).encode("ascii")
        document = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
        if not args.material: atomic_write(args.header_output, header)
        atomic_write(args.plan_output, document)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
