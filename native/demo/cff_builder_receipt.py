"""Freeze exact builder inputs before final linked-image verification."""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile


PROFILE = "builder-fixed-mixed-post-v1"
SOURCE_PROFILE = "builder-fixed-source-mixed-v1"
REPLAY_PROFILE = "builder-replayed-mixed-post-v1"
OUTER_REPLAY_PROFILE = "builder-replayed-outer-post-v1"
ROLES = ("image", "report", "private", "plan", "input_ir", "object")
SOURCE_ROLES = ("image", "report", "private", "input_ir", "object")
REPLAY_ROLES = ROLES + ("transformed_ir", "request_manifest", "recipe",
                        "opt_exe", "clang_exe", "pass_plugin", "replay_record")
OUTER_REPLAY_ROLES = (
    "image", "report", "combined_ir", "requested_ir", "request_manifest",
    "input_ir", "transformed_ir", "object", "inventory", "unfinalized_image",
    "release_report", "recipe", "opt_exe", "clang_exe", "pass_plugin",
    "owner_plan", "release_plan", "private", "scoped", "child_final",
    "child_image", "release_material", "mixed_plan", "replay_record",
)
PROFILE_ROLES = {PROFILE: ROLES, SOURCE_PROFILE: SOURCE_ROLES,
                 REPLAY_PROFILE: REPLAY_ROLES,
                 OUTER_REPLAY_PROFILE: OUTER_REPLAY_ROLES}
ALL_ROLES = tuple(dict.fromkeys(REPLAY_ROLES + SOURCE_ROLES + OUTER_REPLAY_ROLES))
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _invalid(reason):
    raise ValueError(f"builder receipt: {reason}")


def _roles(profile):
    if type(profile) is not str or profile not in PROFILE_ROLES:
        _invalid("unsupported closed profile")
    return PROFILE_ROLES[profile]


def _inputs(inputs, profile):
    roles = _roles(profile)
    if type(inputs) is not dict or set(inputs) != set(roles):
        _invalid("exact profile input roles are required")
    if any(type(inputs[role]) is not bytes for role in roles):
        _invalid("all inputs must be bytes")
    return {role: hashlib.sha256(inputs[role]).hexdigest() for role in roles}


def _canonical(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON key")
        result[key] = value
    return result


def create_receipt(inputs: dict[str, bytes], *, profile: str = PROFILE) -> bytes:
    """Record builder-fixed input digests without reading or changing build files."""
    return _canonical({"schema_version": 1, "profile": profile,
                       "inputs": _inputs(inputs, profile)})


def verify_receipt(receipt: bytes, inputs: dict[str, bytes], *, profile: str = PROFILE) -> dict:
    """Reject any changed byte input relative to a separately frozen receipt."""
    actual = _inputs(inputs, profile)
    roles = _roles(profile)
    limit = 4096 if profile == OUTER_REPLAY_PROFILE else 2048 if profile == REPLAY_PROFILE else 1024
    if type(receipt) is not bytes or len(receipt) > limit:
        _invalid("receipt must be bounded bytes")
    try:
        document = json.loads(receipt.decode("utf-8"), object_pairs_hook=_unique,
                              parse_constant=lambda _: _invalid("nonfinite JSON value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("builder receipt: invalid JSON") from error
    if (type(document) is not dict or set(document) != {"schema_version", "profile", "inputs"} or
            type(document["schema_version"]) is not int or document["schema_version"] != 1 or
            document["profile"] != profile or type(document["inputs"]) is not dict or
            set(document["inputs"]) != set(roles) or
            any(type(document["inputs"][role]) is not str or
                _DIGEST.fullmatch(document["inputs"][role]) is None for role in roles)):
        _invalid("schema, profile or input digests differ from the closed builder profile")
    if receipt != _canonical(document):
        _invalid("receipt is not canonical JSON")
    for role in roles:
        if not hmac.compare_digest(document["inputs"][role], actual[role]):
            _invalid(f"{role} bytes differ from the frozen builder input")
    return {"verified": True, "profile": profile,
            "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "inputs": document["inputs"]}


def _path_inputs(args):
    roles = _roles(args.profile)
    if any(getattr(args, role) is None for role in roles) or any(
            getattr(args, role) is not None for role in ALL_ROLES if role not in roles):
        _invalid("exact profile input paths are required")
    return {role: getattr(args, role) for role in roles}


def _atomic_write(output: Path, data: bytes):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--profile", choices=tuple(PROFILE_ROLES), default=PROFILE)
        for role in ALL_ROLES:
            command.add_argument(f"--{role.replace('_', '-')}", type=Path)
        command.add_argument("--output" if name == "create" else "--receipt",
                             type=Path, required=True)
    args = parser.parse_args()
    try:
        paths = _path_inputs(args)
        if args.command == "create":
            if args.output.resolve() in {path.resolve() for path in paths.values()}:
                _invalid("output path must differ from every input path")
            args.output.unlink(missing_ok=True)
            _atomic_write(args.output, create_receipt(
                {role: path.read_bytes() for role, path in paths.items()}, profile=args.profile))
        else:
            print(json.dumps(verify_receipt(args.receipt.read_bytes(),
                {role: path.read_bytes() for role, path in paths.items()}, profile=args.profile),
                             sort_keys=True))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
