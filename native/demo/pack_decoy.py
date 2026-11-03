"""Seal a separately finalized decoy without exporting real or decoy content keys."""

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from atomic_artifact import atomic_write
from decoy_contract import authenticated_data, validate_child
from release_format import build_record
from release_plan import parse_plan, render_header, validate_child as validate_plan_child, expected_fold
from pack_payload import array


def main():
    parser = argparse.ArgumentParser()
    for name in ("image", "coverage", "report", "plan", "events", "output", "manifest"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    if len({value.resolve() for value in vars(args).values()}) != 7:
        parser.error("decoy inputs and outputs must have distinct paths")
    try:
        image, coverage, report = args.image.read_bytes(), args.coverage.read_bytes(), args.report.read_bytes()
        identity = validate_child(image, coverage, report)
        plan_bytes = args.plan.read_bytes()
        plan = parse_plan(plan_bytes)
        validate_plan_child(plan, image, report)
        if args.events.read_text(encoding="ascii") != render_header(plan, "decoy_events"):
            raise ValueError("decoy event header differs from its private plan/namespace")
        aad = authenticated_data(identity)
        key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        sealed = AESGCM(key).encrypt(nonce, image, aad)
        record = build_record(key, expected_fold(plan))
        source = "#pragma once\n\nnamespace pyobfuscator::native::demo::packed_decoy {\n"
        for name, data in (("nonce", nonce), ("tag", sealed[-16:]), ("ciphertext", sealed[:-16]),
                           ("aad", aad), ("record", record)):
            source += array(name, data)
        source += "}\n"
        header = source.encode("ascii")
        manifest = {"schema_version": 1, "kind": "decoy", "image_sha256": identity[0],
            "report_sha256": identity[1], "coverage_sha256": hashlib.sha256(coverage).hexdigest(),
            "private_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "header_sha256": hashlib.sha256(header).hexdigest()}
        atomic_write(args.output, header)
        atomic_write(args.manifest, (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
