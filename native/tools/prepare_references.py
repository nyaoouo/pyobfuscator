"""Emit independent expected identities and fixed-size storage before codegen."""
import argparse
from pathlib import Path

from atomic_artifact import atomic_write
from reference_plan import parse_plan
from reference_slots import render_header, render_source


def write_if_changed(path, data):
    if not path.exists() or path.read_bytes() != data:
        atomic_write(path, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("header", type=Path)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    try:
        if len({path.resolve() for path in (args.plan, args.header, args.source)}) != 3:
            raise ValueError("reference plan/header/source paths must differ")
        if args.header.name != "reference_slots.hpp":
            raise ValueError("generated source includes reference_slots.hpp")
        plan = parse_plan(args.plan.read_bytes())
        write_if_changed(args.header, render_header(plan).encode())
        write_if_changed(args.source, render_source(plan).encode())
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
