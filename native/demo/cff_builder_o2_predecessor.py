"""Replay the fixed O2 IR predecessor before accepting an archive-origin input."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from cff_archive_origin_contract import ROLES as ARCHIVE_ROLES
from cff_builder_receipt import _atomic_write


ROLES = ("requested_ir", "optimized_ir", "opt_exe")
PROFILE = "g3-o2-predecessor-selected-v1"
SCOPE = "trusted-builder-o2-predecessor-v1"
COMMAND_OPTIONS = ("-passes=default<O2>", "-verify-each", "-S")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _invalid(reason: str) -> None:
    raise ValueError(f"builder O2 predecessor: {reason}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON key")
        result[key] = value
    return result


def _json(data: bytes, label: str) -> dict:
    if type(data) is not bytes or not 0 < len(data) <= 16384:
        _invalid(f"{label} exceeds its byte budget")
    try:
        result = json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _invalid("nonfinite JSON value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"builder O2 predecessor: malformed {label} JSON") from error
    if type(result) is not dict or data != _canonical(result):
        _invalid(f"{label} is not canonical JSON")
    return result


def _same_path(left: Path, right: Path) -> bool:
    return (left.resolve() == right.resolve() or
            left.exists() and right.exists() and left.samefile(right))


def _paths(paths: dict[str, Path]) -> dict[str, Path]:
    if (type(paths) is not dict or set(paths) != set(ROLES) or
            any(not isinstance(path, Path) or not path.is_absolute()
                for path in paths.values())):
        _invalid("exact absolute role paths are required")
    resolved = {role: paths[role].resolve() for role in ROLES}
    if any(_same_path(resolved[left], resolved[right])
           for index, left in enumerate(ROLES) for right in ROLES[index + 1:]):
        _invalid("role paths alias an input")
    if any(len(path.as_posix()) > 1024 or "'" in path.as_posix()
           for path in resolved.values()):
        _invalid("role paths are not bounded LLVM module paths")
    return resolved


def _inputs(inputs: dict[str, bytes]) -> dict[str, bytes]:
    if (type(inputs) is not dict or set(inputs) != set(ROLES) or
            any(type(inputs[role]) is not bytes for role in ROLES)):
        _invalid("exact byte inputs are required")
    return inputs


def _values(paths: dict[str, Path]) -> dict[str, str]:
    return {role: paths[role].as_posix() for role in ROLES}


def _command(values: dict[str, str]) -> list[str]:
    return [values["opt_exe"], *COMMAND_OPTIONS, values["requested_ir"],
            "-o", values["optimized_ir"]]


def _record(paths: dict[str, Path], inputs: dict[str, bytes]) -> bytes:
    values = _values(paths)
    return _canonical({"schema_version": 1, "profile": PROFILE, "scope": SCOPE,
                       "paths": values, "role_sha256": {role: _sha(inputs[role])
                                                        for role in ROLES},
                       "command": _command(values)})


def _check_record(record_bytes: bytes, paths: dict[str, Path],
                  inputs: dict[str, bytes]) -> dict:
    record = _json(record_bytes, "record")
    if (set(record) != {"schema_version", "profile", "scope", "paths",
                        "role_sha256", "command"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile"] != PROFILE or record["scope"] != SCOPE or
            type(record["paths"]) is not dict or set(record["paths"]) != set(ROLES) or
            type(record["role_sha256"]) is not dict or
            set(record["role_sha256"]) != set(ROLES) or
            type(record["command"]) is not list or
            record["command"] != _command(_values(paths))):
        _invalid("record differs from the closed O2 profile")
    for role in ROLES:
        value = record["paths"][role]
        digest = record["role_sha256"][role]
        if (type(value) is not str or value != paths[role].as_posix() or
                type(digest) is not str or _DIGEST.fullmatch(digest) is None or
                digest != _sha(inputs[role])):
            _invalid(f"{role} differs from the fixed record")
    return record


def _archive_join(archive_record_bytes: bytes, archive_paths: dict[str, Path],
                  paths: dict[str, Path], inputs: dict[str, bytes]) -> None:
    record = _json(archive_record_bytes, "archive record")
    if (set(record) != {"schema_version", "profile", "scope", "role_sha256",
                        "replayed_sha256", "paths", "plan_opt_options",
                        "record_count"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile"] != "g3-archive-origin-pre-post-o2-v1" or
            record["scope"] != "trusted-builder-archive-origin-v1" or
            type(record["paths"]) is not dict or
            set(record["paths"]) != set(ARCHIVE_ROLES) or
            type(record["role_sha256"]) is not dict or
            set(record["role_sha256"]) != set(ARCHIVE_ROLES) or
            type(archive_paths) is not dict or set(archive_paths) != set(ARCHIVE_ROLES)):
        _invalid("archive record or CLI roles differ from the closed profile")
    for role in ARCHIVE_ROLES:
        actual = archive_paths[role]
        value = record["paths"][role]
        if (not isinstance(actual, Path) or not actual.is_absolute() or
                type(value) is not str or value != actual.resolve().as_posix()):
            _invalid(f"archive {role} path differs from the fixed record")
    for role in ("optimized_ir", "opt_exe"):
        if (archive_paths[role].resolve() != paths[role] or
                record["role_sha256"][role] != _sha(inputs[role])):
            _invalid(f"{role} differs from the archive-origin input")


def _replay(paths: dict[str, Path], inputs: dict[str, bytes]) -> None:
    with TemporaryDirectory(dir=paths["optimized_ir"].parent) as directory:
        scratch = Path(directory)
        requested = scratch / "payload.requested.ll"
        optimized = scratch / "payload.optimized.ll"
        requested.write_bytes(inputs["requested_ir"])
        command = [paths["opt_exe"].as_posix(), *COMMAND_OPTIONS,
                   requested.as_posix(), "-o", optimized.as_posix()]
        try:
            result = subprocess.run(command, cwd=paths["requested_ir"].parent,
                                    capture_output=True, text=True, timeout=120,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"builder O2 predecessor: optimizer could not finish: {error}") from error
        if result.returncode:
            detail = result.stderr.splitlines()[0] if result.stderr else "no error text"
            _invalid(f"optimizer failed ({result.returncode}): {detail[:200]}")
        output = optimized.read_bytes()
        marker = b"; ModuleID = '" + requested.as_posix().encode("utf-8") + b"'"
        if output.startswith(marker + b"\r\n"):
            ending = b"\r\n"
        elif output.startswith(marker + b"\n"):
            ending = b"\n"
        else:
            _invalid("unexpected replayed LLVM module identifier")
        expected = (b"; ModuleID = '" + paths["requested_ir"].as_posix().encode("utf-8") +
                    b"'" + ending + output[len(marker + ending):])
        if expected != inputs["optimized_ir"]:
            _invalid("optimized IR differs from deterministic O2 replay")


def verify_o2_predecessor_record(record_bytes: bytes, paths: dict[str, Path],
                                 inputs: dict[str, bytes], archive_record_bytes: bytes,
                                 archive_paths: dict[str, Path]) -> dict:
    """Bind fixed requested IR and optimizer bytes to the archive O2 input."""
    paths = _paths(paths)
    inputs = _inputs(inputs)
    _check_record(record_bytes, paths, inputs)
    _archive_join(archive_record_bytes, archive_paths, paths, inputs)
    if any(paths[role].read_bytes() != inputs[role] for role in ROLES):
        _invalid("live role bytes differ from the fixed inputs")
    _replay(paths, inputs)
    if any(paths[role].read_bytes() != inputs[role] for role in ROLES):
        _invalid("role bytes changed during optimizer replay")
    return {"verified": True, "optimizer_replay_verified": True,
            "archive_input_join_verified": True,
            "cpp_source_provenance_verified": False,
            "publisher_signature_verified": False, "scope": SCOPE,
            "record_sha256": _sha(record_bytes),
            **{role + "_sha256": _sha(inputs[role]) for role in ROLES}}


def freeze(paths: dict[str, Path], record_path: Path) -> None:
    """Explicitly freeze a record only after the selected optimizer replay."""
    if (type(paths) is not dict or set(paths) != set(ROLES) or
            any(not isinstance(path, Path) or not path.is_absolute()
                for path in paths.values())):
        _invalid("exact absolute role paths are required")
    if not isinstance(record_path, Path) or not record_path.is_absolute():
        _invalid("record path must be absolute")
    if record_path.is_symlink():
        _invalid("record path must not be a symlink")
    if any(_same_path(record_path, path) for path in paths.values()):
        _invalid("record path aliases an input")
    record_path.unlink(missing_ok=True)
    try:
        paths = _paths(paths)
        inputs = {role: paths[role].read_bytes() for role in ROLES}
        _replay(paths, inputs)
        if any(paths[role].read_bytes() != inputs[role] for role in ROLES):
            _invalid("role bytes changed before record freeze")
        record = _record(paths, inputs)
        _check_record(record, paths, inputs)
        _atomic_write(record_path, record)
    except Exception:
        record_path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    frozen = commands.add_parser("freeze")
    frozen.add_argument("--record", type=Path, required=True)
    for role in ROLES:
        frozen.add_argument("--" + role.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    try:
        freeze({role: getattr(args, role) for role in ROLES}, args.record)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
