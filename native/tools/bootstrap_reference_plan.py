"""Early self-text selection for the concrete pre-release bootstrap consumer."""
import argparse
import hashlib
import json
from pathlib import Path

from atomic_artifact import atomic_write
from reference_plan import parse_plan
from release_material import parse_material


def create(material, role):
    parse_material(material)
    if type(role) is not str or not 0 < len(role) <= 128 or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in role):
        raise ValueError("bootstrap observation role must be a bounded target identity")
    seed = hashlib.sha256(b"pyobf.native.bootstrap.reference.seed.v1\0" + material).digest()[:16]
    container = hashlib.sha256(b"pyobf.native.bootstrap.reference.role.v1\0" + role.encode()).digest()[:16]
    document = {"schema_version": 1, "build_seed": seed.hex(), "container": container.hex(), "records": [
        {"image": container.hex(), "owner": 1, "subject": 1, "kind": 1, "stage": 1,
         "capacity": 4096, "selector": {"section": ".text"}}]}
    return parse_plan(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("material", type=Path); parser.add_argument("role"); parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.material.resolve() == args.output.resolve(): raise ValueError("bootstrap plan must not replace its early material")
        atomic_write(args.output, create(args.material.read_bytes(), args.role).canonical)
    except (OSError, ValueError) as error: parser.error(str(error))


if __name__ == "__main__": main()
