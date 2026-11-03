"""Fill a linked PE's reserved release mask without recompiling executable code."""

import argparse
import json
from pathlib import Path

from atomic_artifact import atomic_write
from pe_release_record import finalize_image


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("image", "record", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.report is not None and args.report.resolve() in {args.image.resolve(), args.record.resolve(), args.output.resolve()}:
        parser.error("release report must not replace an input or output artifact")
    if args.output.resolve() == args.record.resolve():
        parser.error("release output must not replace the input record")
    try:
        finalized, report = finalize_image(args.image.read_bytes(), args.record.read_bytes())
        atomic_write(args.output, finalized)
        if args.report is not None:
            atomic_write(args.report, (json.dumps(report, indent=2) + "\n").encode())
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
