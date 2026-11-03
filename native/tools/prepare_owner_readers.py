"""Generate owner-specific source before CFF/codegen from the existing early plan."""
import argparse
from pathlib import Path

from owner_reader_plan import render_header, render_source
from prepare_references import write_if_changed
from reference_plan import parse_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "header", "source"): parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        if len({path.resolve() for path in vars(args).values()}) != 3:
            raise ValueError("owner-reader plan/header/source must be distinct")
        if args.header.name != "owner_readers.hpp": raise ValueError("owner-reader source includes owner_readers.hpp")
        plan = parse_plan(args.plan.read_bytes())
        write_if_changed(args.header, render_header(plan).encode())
        write_if_changed(args.source, render_source(plan).encode())
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
