"""Create an independent early scoped root once; preserve an existing valid build input."""
import argparse
from pathlib import Path
import secrets

from atomic_artifact import atomic_write


def read_material(path):
    with path.open("rb") as stream: value = stream.read(33)
    if len(value) != 32: raise ValueError("scoped material needs exactly32 early bytes")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists(): read_material(args.output)
        else: atomic_write(args.output, secrets.token_bytes(32))
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
