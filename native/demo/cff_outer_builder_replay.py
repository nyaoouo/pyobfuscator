"""Replay the outer CFF compiler chain before freezing final build bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from cff_builder_receipt import (OUTER_REPLAY_PROFILE, OUTER_REPLAY_ROLES,
                                 _atomic_write, create_receipt)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from function_inventory import create as create_inventory  # noqa: E402


RECORD_SCOPE = "trusted-outer-compiler-replay-record-v1"
INPUT_ROLES = OUTER_REPLAY_ROLES[:-1]
REPLAYED_ROLES = ("requested_ir", "request_manifest", "input_ir",
                  "transformed_ir", "report", "object", "inventory")
PATH_ROLES = ("opt_exe", "clang_exe", "pass_plugin", "recipe",
              "combined_ir", "requested_ir", "request_manifest", "input_ir",
              "transformed_ir", "report", "object", "inventory")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _invalid(reason):
    raise ValueError(f"outer builder replay: {reason}")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _canonical(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            _invalid("duplicate record key")
        values[key] = value
    return values


def _options(opt_options, clang_options, source_opt, recipe_path):
    if source_opt not in ("none", "O2"):
        _invalid("source optimization must be none or O2")
    for kind, values in (("opt", opt_options), ("Clang", clang_options)):
        if (type(values) is not list or not 0 < len(values) <= 64 or
                any(type(value) is not str or not value or len(value) > 1024
                    for value in values)):
            _invalid(f"{kind} needs bounded ordered options")
    if (len(opt_options) != 3 or
            opt_options[0] != "-pyobf-cff-config=" + recipe_path or
            not re.fullmatch(r"-pyobf-cff-seed=[0-9]{1,20}", opt_options[1]) or
            opt_options[2] != "-pyobf-cff-markers=true"):
        _invalid("opt options differ from the closed outer CFF selection")
    if (clang_options[-3:] != ["-ffunction-sections", "-O0", "-fno-lto"] or
            any(value == "-c" or value == "-o" or value.startswith("-o") or
                value.startswith("@") for value in clang_options[:-3])):
        _invalid("Clang options differ from function-section object emission")


def _record(inputs, paths, opt_options, clang_options, source_opt):
    return _canonical({
        "schema_version": 1, "profile": OUTER_REPLAY_PROFILE,
        "scope": RECORD_SCOPE, "source_opt": source_opt,
        "input_sha256": {role: _sha(inputs[role]) for role in INPUT_ROLES},
        "replayed_sha256": {role: _sha(inputs[role]) for role in REPLAYED_ROLES},
        "opt_options": opt_options, "clang_options": clang_options,
        "paths": {role: paths[role].resolve().as_posix() for role in PATH_ROLES},
    })


def verify_outer_replay_record(record_bytes: bytes,
                               inputs: dict[str, bytes]) -> dict:
    """Check the fixed replay record against exact outer finalizer bytes."""
    if (type(record_bytes) is not bytes or not 0 < len(record_bytes) <= 16384 or
            type(inputs) is not dict or set(inputs) != set(OUTER_REPLAY_ROLES) or
            any(type(value) is not bytes for value in inputs.values()) or
            inputs["replay_record"] != record_bytes):
        _invalid("record and exact byte inputs are required")
    try:
        record = json.loads(record_bytes.decode("ascii"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _invalid("nonfinite record value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("outer builder replay: malformed record JSON") from error
    if (type(record) is not dict or set(record) != {
            "schema_version", "profile", "scope", "source_opt",
            "input_sha256", "replayed_sha256", "opt_options",
            "clang_options", "paths"} or
            type(record["schema_version"]) is not int or
            record["schema_version"] != 1 or
            record["profile"] != OUTER_REPLAY_PROFILE or
            record["scope"] != RECORD_SCOPE or
            type(record["input_sha256"]) is not dict or
            set(record["input_sha256"]) != set(INPUT_ROLES) or
            type(record["replayed_sha256"]) is not dict or
            set(record["replayed_sha256"]) != set(REPLAYED_ROLES) or
            type(record["paths"]) is not dict or
            set(record["paths"]) != set(PATH_ROLES)):
        _invalid("record shape differs from the closed outer replay profile")
    if record_bytes != _canonical(record):
        _invalid("record is not canonical JSON")
    paths = record["paths"]
    if any(type(path) is not str or not 0 < len(path) <= 1024 or
           "\\" in path or not Path(path).is_absolute()
           for path in paths.values()):
        _invalid("record paths must be bounded absolute forward-slash paths")
    _options(record["opt_options"], record["clang_options"],
             record["source_opt"], paths["recipe"])
    for role in INPUT_ROLES:
        digest = record["input_sha256"][role]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None or digest != _sha(inputs[role]):
            _invalid(f"{role} differs from the replay record")
    for role in REPLAYED_ROLES:
        digest = record["replayed_sha256"][role]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None or digest != _sha(inputs[role]):
            _invalid(f"{role} differs from deterministic compiler replay")
    if record["source_opt"] == "none" and inputs["input_ir"] != inputs["requested_ir"]:
        _invalid("none input IR differs from requested IR")
    return {"verified": True, "record_consistency_verified": True,
            "scope": RECORD_SCOPE, "source_opt": record["source_opt"],
            "record_sha256": _sha(record_bytes),
            "replayed_roles": list(REPLAYED_ROLES)}


def _same_path(left, right):
    if left.resolve() == right.resolve():
        return True
    return left.exists() and right.exists() and left.samefile(right)


def _run(command, cwd, name):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"outer builder replay: {name} could not finish: {error}") from error
    if result.returncode:
        detail = result.stderr.splitlines()[0] if result.stderr else "no error text"
        _invalid(f"{name} failed ({result.returncode}): {detail[:200]}")


def _module_id_from_snapshot(output, snapshot, original):
    """Restore only opt's input-path header after replaying immutable IR bytes."""
    marker = b"; ModuleID = '"
    stem = marker + snapshot.as_posix().encode("utf-8") + b"'"
    ending = b"\r\n" if output.startswith(stem + b"\r\n") else b"\n"
    snapshot_header = stem + ending
    if not output.startswith(snapshot_header):
        _invalid("unexpected replayed LLVM module identifier")
    original_header = marker + original.as_posix().encode("utf-8") + b"'" + ending
    return original_header + output[len(snapshot_header):]


def _json_module_from_snapshot(output, snapshot, original):
    needle = b'"module":' + json.dumps(snapshot.as_posix()).encode("ascii")
    if output.count(needle) != 1:
        _invalid("unexpected replayed JSON module path")
    replacement = b'"module":' + json.dumps(original.as_posix()).encode("ascii")
    return output.replace(needle, replacement)


def freeze(paths: dict[str, Path], opt_options: list[str],
           clang_options: list[str], source_opt: str) -> None:
    """Replay selected compiler stages and freeze independently produced bytes."""
    if (type(paths) is not dict or
            set(paths) != set(INPUT_ROLES) | {"record", "receipt"} or
            any(not isinstance(path, Path) for path in paths.values())):
        _invalid("exact outer replay paths are required")
    outputs = (paths["record"], paths["receipt"])
    if (_same_path(*outputs) or
            any(_same_path(output, paths[role])
                for output in outputs for role in INPUT_ROLES)):
        _invalid("record or receipt aliases an input")
    for output in outputs:
        output.unlink(missing_ok=True)
    paths["receipt"].parent.mkdir(parents=True, exist_ok=True)
    try:
        if any(not paths[role].is_absolute() for role in INPUT_ROLES):
            _invalid("all outer replay input paths must be absolute")
        paths = {role: path.resolve() for role, path in paths.items()}
        _options(opt_options, clang_options, source_opt,
                 paths["recipe"].as_posix())
        inputs = {role: paths[role].read_bytes() for role in INPUT_ROLES}
        with TemporaryDirectory(dir=paths["receipt"].parent) as temporary:
            scratch = Path(temporary)
            combined = scratch / "outer.combined.ll"
            requested = scratch / "outer.requested.ll"
            requests = scratch / "outer.requests.json"
            optimized = scratch / "outer.optimized.ll"
            transformed = scratch / "outer.cff.ll"
            report = scratch / "outer.coverage.json"
            obj = scratch / "outer.obj"
            combined.write_bytes(inputs["combined_ir"])
            plugin = paths["pass_plugin"].as_posix()
            _run([paths["opt_exe"].as_posix(), "-load-pass-plugin", plugin,
                  "-passes=pyobf-native-cff-requests", *opt_options,
                  "-pyobf-cff-requests-output=" + requests.as_posix(),
                  "-verify-each", "-S", combined.as_posix(), "-o", requested.as_posix()],
                 paths["combined_ir"].parent, "request opt")
            requested_bytes = _module_id_from_snapshot(
                requested.read_bytes(), combined, paths["combined_ir"])
            request_bytes = _json_module_from_snapshot(
                requests.read_bytes(), combined, paths["combined_ir"])
            if (requested_bytes != inputs["requested_ir"] or
                    request_bytes != inputs["request_manifest"]):
                _invalid("request outputs differ from deterministic compiler replay")
            requested.write_bytes(requested_bytes)
            requests.write_bytes(request_bytes)
            selected = requested
            if source_opt == "O2":
                _run([paths["opt_exe"].as_posix(), "-passes=default<O2>", "-verify-each",
                      "-S", requested.as_posix(),
                      "-o", optimized.as_posix()],
                     paths["combined_ir"].parent, "source O2")
                optimized.write_bytes(_module_id_from_snapshot(
                    optimized.read_bytes(), requested, paths["requested_ir"]))
                selected = optimized
            if selected.read_bytes() != inputs["input_ir"]:
                _invalid("input_ir differs from deterministic compiler replay")
            _run([paths["opt_exe"].as_posix(), "-load-pass-plugin", plugin,
                  "-passes=pyobf-native-cff", *opt_options,
                  "-pyobf-cff-requests-input=" + requests.as_posix(),
                  "-pyobf-cff-report=" + report.as_posix(),
                  "-verify-each", "-S", selected.as_posix(),
                  "-o", transformed.as_posix()],
                 paths["combined_ir"].parent, "CFF opt")
            transformed_bytes = _module_id_from_snapshot(
                transformed.read_bytes(), selected, paths["input_ir"])
            report_bytes = _json_module_from_snapshot(
                report.read_bytes(), selected, paths["input_ir"])
            if (transformed_bytes != inputs["transformed_ir"] or
                    report_bytes != inputs["report"]):
                _invalid("CFF outputs differ from deterministic compiler replay")
            transformed.write_bytes(transformed_bytes)
            report.write_bytes(report_bytes)
            _run([paths["clang_exe"].as_posix(), *clang_options, "-c",
                  transformed.as_posix(), "-o", obj.as_posix()],
                 paths["combined_ir"].parent, "Clang")
            replayed = {
                "requested_ir": requested.read_bytes(),
                "request_manifest": requests.read_bytes(),
                "input_ir": selected.read_bytes(),
                "transformed_ir": transformed.read_bytes(),
                "report": report.read_bytes(),
                "object": obj.read_bytes(),
            }
            replayed["inventory"] = create_inventory(
                replayed["object"], replayed["transformed_ir"], replayed["report"])
            for role in REPLAYED_ROLES:
                if replayed[role] != inputs[role]:
                    _invalid(f"{role} differs from deterministic compiler replay")
        if any(paths[role].read_bytes() != inputs[role] for role in INPUT_ROLES):
            _invalid("outer replay inputs changed before receipt freeze")
        record = _record(inputs, paths, opt_options, clang_options, source_opt)
        exact = {**inputs, "replay_record": record}
        verify_outer_replay_record(record, exact)
        _atomic_write(paths["record"], record)
        _atomic_write(paths["receipt"],
                      create_receipt(exact, profile=OUTER_REPLAY_PROFILE))
    except Exception:
        for output in outputs:
            output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("freeze")
    command.add_argument("--source-opt", choices=("none", "O2"), required=True)
    command.add_argument("--record", type=Path, required=True)
    command.add_argument("--receipt", type=Path, required=True)
    command.add_argument("--role", action="append", default=[])
    command.add_argument("--opt-arg", action="append", default=[])
    command.add_argument("--clang-arg", action="append", default=[])
    args = parser.parse_args()
    try:
        roles = {}
        for item in args.role:
            if "=" not in item:
                _invalid("role needs name=path")
            name, path = item.split("=", 1)
            if name in roles or name not in INPUT_ROLES or not path:
                _invalid("duplicate, unknown or empty role")
            roles[name] = Path(path)
        freeze({**roles, "record": args.record, "receipt": args.receipt},
               args.opt_arg, args.clang_arg, args.source_opt)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
