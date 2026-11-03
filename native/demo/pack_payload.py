"""Embed an already linked DLL as an authenticated demo payload."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from atomic_artifact import atomic_write
from release_format import build_record
from release_plan import expected_fold, parse_plan, render_header, validate_child
from payload_binding import requires_bound_child, validate_bound_child
from post_mixed_binding import validate_mixed_bound_child
from prepare_scope_material import read_material


AAD = b"pyobf-native-demo-v1"


def array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{value:02x}" for value in data[index : index + 12])
            for index in range(0, len(data), 12)]
    return f"inline constexpr unsigned char {name}[] = {{\n    " + ",\n    ".join(rows) + "\n};\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("record", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("event_header", type=Path)
    parser.add_argument("child_report", type=Path)
    parser.add_argument("--contribution-input", type=Path)
    parser.add_argument("--binding-provider", choices=("owned-context-v1", "measured-scope-v1"), default="owned-context-v1")
    parser.add_argument("--scope-material", type=Path)
    parser.add_argument("--mixed-plan", type=Path)
    parser.add_argument("--release-material", type=Path)
    args = parser.parse_args()
    mixed = args.mixed_plan is not None or args.release_material is not None
    if mixed != (args.mixed_plan is not None and args.release_material is not None):
        parser.error("mixed POST packaging needs both frozen edge plan and early release material")
    if mixed and (args.binding_provider != "measured-scope-v1" or not args.scope_material or
                  not args.contribution_input):
        parser.error("mixed POST packaging needs measured scope and its private source")
    if (args.binding_provider == "measured-scope-v1") != bool(args.scope_material):
        parser.error("payload binding profile requires its exact early material input")
    if args.scope_material and not args.contribution_input: parser.error("measured payload requires its private source reference")

    payload = args.input.read_bytes()
    if not payload:
        parser.error("the linked payload is empty")
    paths = [value for value in vars(args).values() if isinstance(value, Path)]
    if len({value.resolve() for value in paths}) != len(paths):
        parser.error("payload inputs and outputs must have distinct paths")
    try:
        plan = parse_plan(args.plan.read_bytes())
        child_report = args.child_report.read_bytes()
        validate_child(plan, payload, child_report)
        if requires_bound_child(child_report) and not args.contribution_input:
            parser.error("strict payload packaging requires its actual contribution reference")
        if args.contribution_input:
            if mixed:
                validate_mixed_bound_child(plan, args.contribution_input.read_bytes(), child_report,
                    material_bytes=args.release_material.read_bytes(),
                    scoped_material=read_material(args.scope_material),
                    mixed_plan_bytes=args.mixed_plan.read_bytes())
            else:
                validate_bound_child(plan, args.contribution_input.read_bytes(), child_report,
                    provider=args.binding_provider, scoped_material=read_material(args.scope_material) if args.scope_material else None)
        if args.event_header.read_text(encoding="ascii") != render_header(plan):
            parser.error("private event header differs from its input plan")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(nonce, payload, AAD)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    source = "#pragma once\n\nnamespace pyobfuscator::native::demo::packed {\n"
    source += array("nonce", nonce)
    source += array("tag", tag)
    source += array("ciphertext", ciphertext)
    source += "}  // namespace pyobfuscator::native::demo::packed\n"
    record = build_record(key, expected_fold(plan))
    atomic_write(args.output, source.encode("ascii"))
    atomic_write(args.record, record)


if __name__ == "__main__":
    main()
