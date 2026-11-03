"""Reject unsupported source entry/init contracts before collecting CFF requests."""

import argparse
from pathlib import Path

from decoy_contract import validate_ir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        validate_ir(args.input.read_text())
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
