"""Generate private release material/header without reading a child image."""
import argparse
import json
from pathlib import Path

from atomic_artifact import atomic_write
from release_material import create_material, render_material_header


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("material_output", type=Path)
    parser.add_argument("header_output", type=Path)
    parser.add_argument("--event-namespace", choices=("path_events", "decoy_events"), default="path_events")
    args = parser.parse_args()
    if args.material_output.resolve() == args.header_output.resolve():
        parser.error("private release material/header outputs must have distinct paths")
    try:
        material = create_material()
        header = render_material_header(material, args.event_namespace).encode("ascii")
        document = (json.dumps(material, indent=2, sort_keys=True) + "\n").encode()
        atomic_write(args.header_output, header)
        atomic_write(args.material_output, document)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
