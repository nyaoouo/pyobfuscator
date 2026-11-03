"""Replay the mixed CFF compiler chain before freezing builder input bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from cff_builder_receipt import REPLAY_PROFILE, REPLAY_ROLES, _atomic_write, create_receipt


RECORD_SCOPE = "trusted-builder-replay-record-v1"
INPUT_ROLES = REPLAY_ROLES[:-1]
OUTPUT_ROLES = ("transformed_ir", "report", "object")
OPT_DATA_PATHS = (("-pyobf-cff-config=", "recipe"),
                  ("-pyobf-cff-contribution-input=", "private"),
                  ("-pyobf-cff-edge-plan-input=", "plan"))
PATH_ROLES = {
    "image", "report", "private", "plan", "input_ir", "object",
    "transformed_ir", "request_manifest", "recipe", "opt_exe", "clang_exe",
    "pass_plugin",
}


def _invalid(reason):
    raise ValueError(f"builder replay: {reason}")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate record key")
        result[key] = value
    return result


def _options(values, kind):
    if (type(values) is not list or not values or len(values) > 64 or
            any(type(value) is not str or not value or len(value) > 1024
                for value in values)):
        _invalid(f"{kind} needs bounded ordered options")
    if kind == "opt":
        required = ("-pyobf-cff-functions=", "-pyobf-cff-config=",
                    "-pyobf-cff-deep-functions=", "-pyobf-cff-seed=",
                    "-pyobf-cff-markers=", "-pyobf-cff-strategy=",
                    "-pyobf-cff-contribution-input=", "-pyobf-cff-edge-owners=",
                    "-pyobf-cff-edge-plan-input=",
                    "-pyobf-cff-require-decision-flow=")
        forbidden = ("-pyobf-cff-report=", "-pyobf-cff-requests-input=")
        if any(sum(value.startswith(prefix) for value in values) != 1
               for prefix in required):
            _invalid("opt options lack one required mixed CFF input")
        if any(value.startswith(forbidden) or value in {
                "-load-pass-plugin", "-passes=pyobf-native-cff", "-verify-each",
                "-S", "-o"} for value in values):
            _invalid("opt options override the replay command")
    else:
        if values[-3:] != ["-ffunction-sections", "-O0", "-fno-lto"]:
            _invalid("Clang options differ from the function-section object emission")
        if any(value in ("-c", "-o") for value in values):
            _invalid("Clang options override the replay command")
    return values


def _record(input_bytes, opt_options, clang_options, paths):
    return _canonical({
        "schema_version": 1,
        "profile": REPLAY_PROFILE,
        "scope": RECORD_SCOPE,
        "input_sha256": {role: _sha(input_bytes[role]) for role in INPUT_ROLES},
        "replayed_sha256": {role: _sha(input_bytes[role]) for role in OUTPUT_ROLES},
        "opt_options": opt_options,
        "clang_options": clang_options,
        "paths": {role: paths[role].resolve().as_posix()
                  for role in ("opt_exe", "clang_exe", "pass_plugin", "input_ir",
                               "request_manifest", "recipe", "private", "plan")},
    })


def verify_replay_record(record_bytes: bytes, inputs: dict[str, bytes]) -> dict:
    """Check a fixed producer record against every actual replay-profile role."""
    if (type(record_bytes) is not bytes or not record_bytes or
            len(record_bytes) > 16384 or type(inputs) is not dict or
            set(inputs) != set(REPLAY_ROLES) or
            any(type(value) is not bytes for value in inputs.values()) or
            inputs["replay_record"] != record_bytes):
        _invalid("record and exact byte inputs are required")
    try:
        record = json.loads(record_bytes.decode("ascii"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _invalid("nonfinite record value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("builder replay: malformed record JSON") from error
    if (type(record) is not dict or set(record) != {
            "schema_version", "profile", "scope", "input_sha256",
            "replayed_sha256", "opt_options", "clang_options", "paths"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile"] != REPLAY_PROFILE or record["scope"] != RECORD_SCOPE or
            type(record["input_sha256"]) is not dict or
            set(record["input_sha256"]) != set(INPUT_ROLES) or
            type(record["replayed_sha256"]) is not dict or
            set(record["replayed_sha256"]) != set(OUTPUT_ROLES) or
            type(record["paths"]) is not dict or
            set(record["paths"]) != {"opt_exe", "clang_exe", "pass_plugin",
                                     "input_ir", "request_manifest", "recipe",
                                     "private", "plan"}):
        _invalid("record shape differs from the closed replay profile")
    if record_bytes != _canonical(record):
        _invalid("record is not canonical JSON")
    _options(record["opt_options"], "opt")
    _options(record["clang_options"], "clang")
    if any(type(path) is not str or not path or len(path) > 1024 or
           "\\" in path for path in record["paths"].values()):
        _invalid("record paths are not bounded forward-slash paths")
    for option, role in (("-pyobf-cff-config=", "recipe"),
                         ("-pyobf-cff-contribution-input=", "private"),
                         ("-pyobf-cff-edge-plan-input=", "plan")):
        if option + record["paths"][role] not in record["opt_options"]:
            _invalid(f"record {role} path differs from its opt option")
    for role in INPUT_ROLES:
        digest = record["input_sha256"][role]
        if type(digest) is not str or digest != _sha(inputs[role]):
            _invalid(f"{role} differs from the replay record")
    for role in OUTPUT_ROLES:
        digest = record["replayed_sha256"][role]
        if type(digest) is not str or digest != _sha(inputs[role]):
            _invalid(f"{role} differs from the replayed output")
    return {"record_consistency_verified": True, "scope": RECORD_SCOPE,
            "record_sha256": _sha(record_bytes)}


def _same_path(left, right):
    if left.resolve() == right.resolve():
        return True
    return left.exists() and right.exists() and left.samefile(right)


def _run(command, cwd, name):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"builder replay: {name} could not finish: {error}") from error
    if result.returncode:
        detail = result.stderr.splitlines()[0] if result.stderr else "no error text"
        _invalid(f"{name} failed ({result.returncode}): {detail[:200]}")


def _module_id_from_snapshot(output, snapshot, original):
    marker = b"; ModuleID = '"
    stem = marker + snapshot.as_posix().encode("utf-8") + b"'"
    ending = b"\r\n" if output.startswith(stem + b"\r\n") else b"\n"
    header = stem + ending
    if not output.startswith(header):
        _invalid("unexpected replayed LLVM module identifier")
    original_header = marker + original.as_posix().encode("utf-8") + b"'" + ending
    return original_header + output[len(header):]


def _json_module_from_snapshot(output, snapshot, original):
    needle = b'"module":' + json.dumps(snapshot.as_posix()).encode("ascii")
    if output.count(needle) != 1:
        _invalid("unexpected replayed JSON module path")
    replacement = b'"module":' + json.dumps(original.as_posix()).encode("ascii")
    return output.replace(needle, replacement)


def _replace_plan_hash(output, old, new, field):
    if (re.fullmatch(r"[0-9a-f]{64}", old) is None or
            re.fullmatch(r"[0-9a-f]{64}", new) is None):
        _invalid("unbounded original-edge plan digest")
    needle = (f'"{field}":"{old}"').encode("ascii")
    if output.count(needle) != 1:
        _invalid(f"expected one {field} digest")
    return output.replace(needle, (f'"{field}":"{new}"').encode("ascii"))


def _snapshot_plan(plan_bytes, canonical_print, source_ir, original_ir):
    if len(plan_bytes) > 65536:
        _invalid("original-edge plan exceeds the byte budget")
    try:
        plan = json.loads(plan_bytes.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _invalid("nonfinite original-edge plan value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("builder replay: invalid original-edge plan") from error
    if (type(plan) is not dict or set(plan) != {"schema_version", "profile",
            "input_ir_encoding", "input_ir_sha256", "owners"} or
            type(plan["schema_version"]) is not int or plan["schema_version"] != 2 or
            plan["profile"] != "schema4-original-edges-post-two-v1" or
            plan["input_ir_encoding"] != "llvm-module-print-v1" or
            type(plan["input_ir_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", plan["input_ir_sha256"]) is None or
            type(plan["owners"]) is not list or len(plan["owners"]) != 2):
        _invalid("unsupported original-edge plan profile")
    if b"\r" in canonical_print.replace(b"\r\n", b""):
        _invalid("canonical LLVM print has mixed line endings")
    printed = canonical_print.replace(b"\r\n", b"\n")
    if printed.count(source_ir.as_posix().encode("utf-8")) != 1:
        _invalid("canonical LLVM print has ambiguous module path")
    original = _module_id_from_snapshot(printed, source_ir, original_ir)
    if _sha(original) != plan["input_ir_sha256"]:
        _invalid("frozen original-edge plan differs from exact IR snapshot")
    scratch_hash = _sha(printed)
    updated = _replace_plan_hash(plan_bytes, plan["input_ir_sha256"],
                                 scratch_hash, "input_ir_sha256")
    return updated, _sha(updated), _sha(plan_bytes)


def _snapshot_options(options, snapshots, paths):
    for prefix, role in OPT_DATA_PATHS:
        expected = prefix + paths[role].as_posix()
        if options.count(expected) != 1:
            _invalid(f"{role} option path differs from its frozen input")
    result = []
    for value in options:
        replacement = next((prefix + snapshots[role].as_posix()
                            for prefix, role in OPT_DATA_PATHS
                            if value.startswith(prefix)), None)
        result.append(replacement if replacement is not None else value)
    return result


def freeze(paths, opt_options, clang_options):
    """Replay the fixed compiler chain and issue a receipt only after exact equality."""
    if set(paths) != PATH_ROLES | {"replay_record", "receipt"}:
        _invalid("exact replay paths are required")
    opt_options = _options(opt_options, "opt")
    clang_options = _options(clang_options, "clang")
    outputs = (paths["replay_record"], paths["receipt"])
    if _same_path(*outputs) or any(_same_path(output, paths[role])
                                   for output in outputs for role in PATH_ROLES):
        _invalid("record or receipt aliases a replay input")
    for output in outputs:
        output.unlink(missing_ok=True)
    paths["receipt"].parent.mkdir(parents=True, exist_ok=True)
    try:
        if any(not paths[role].is_absolute() for role in PATH_ROLES):
            _invalid("all replay input paths must be absolute")
        paths = {role: path.resolve() for role, path in paths.items()}
        inputs = {role: paths[role].read_bytes() for role in INPUT_ROLES}
        with TemporaryDirectory(dir=paths["receipt"].parent) as temporary:
            scratch = Path(temporary)
            source_ir = scratch / "payload.input.ll"
            request = scratch / "payload.requests.json"
            recipe = scratch / "payload.recipe.json"
            private = scratch / "payload.private.json"
            plan = scratch / "payload.plan.json"
            snapshots = {"recipe": recipe, "private": private, "plan": plan}
            for role, output in (("input_ir", source_ir),
                                 ("request_manifest", request),
                                 *snapshots.items()):
                output.write_bytes(inputs[role])
            canonical = scratch / "payload.canonical.ll"
            _run([paths["opt_exe"].as_posix(), "-S", source_ir.as_posix(),
                  "-o", canonical.as_posix()],
                 paths["input_ir"].parent, "canonical opt")
            scratch_plan, scratch_plan_hash, original_plan_hash = _snapshot_plan(
                inputs["plan"], canonical.read_bytes(), source_ir, paths["input_ir"])
            plan.write_bytes(scratch_plan)
            replay_ir = scratch / "payload.cff.ll"
            replay_report = scratch / "payload.cff.coverage.json"
            replay_object = scratch / "payload.cff.obj"
            opt = [paths["opt_exe"].as_posix(), "-load-pass-plugin",
                   paths["pass_plugin"].as_posix(), "-passes=pyobf-native-cff",
                   *_snapshot_options(opt_options, snapshots, paths),
                   "-pyobf-cff-report=" + replay_report.as_posix(),
                   "-pyobf-cff-requests-input=" + request.as_posix(),
                   "-verify-each", "-S", source_ir.as_posix(),
                   "-o", replay_ir.as_posix()]
            _run(opt, paths["input_ir"].parent, "opt")
            replay_ir.write_bytes(_module_id_from_snapshot(
                replay_ir.read_bytes(), source_ir, paths["input_ir"]))
            replay_report.write_bytes(_json_module_from_snapshot(
                replay_report.read_bytes(), source_ir, paths["input_ir"]))
            replay_report.write_bytes(_replace_plan_hash(
                replay_report.read_bytes(), scratch_plan_hash,
                original_plan_hash, "original_edge_plan_sha256"))
            clang = [paths["clang_exe"].as_posix(), *clang_options, "-c",
                     replay_ir.as_posix(), "-o", replay_object.as_posix()]
            _run(clang, paths["input_ir"].parent, "Clang")
            for role, output in (("transformed_ir", replay_ir),
                                 ("report", replay_report), ("object", replay_object)):
                if output.read_bytes() != inputs[role]:
                    _invalid(f"{role} differs from deterministic compiler replay")
        if any(paths[role].read_bytes() != inputs[role] for role in INPUT_ROLES):
            _invalid("replay inputs changed before receipt freeze")
        record = _record(inputs, opt_options, clang_options, paths)
        exact = {**inputs, "replay_record": record}
        verify_replay_record(record, exact)
        _atomic_write(paths["replay_record"], record)
        _atomic_write(paths["receipt"], create_receipt(exact, profile=REPLAY_PROFILE))
    except Exception:
        for output in outputs:
            output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in sorted(PATH_ROLES | {"replay_record", "receipt"}):
        parser.add_argument("--" + role.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--opt-arg", action="append", default=[])
    parser.add_argument("--clang-arg", action="append", default=[])
    args = parser.parse_args()
    paths = {role: getattr(args, role) for role in PATH_ROLES | {"replay_record", "receipt"}}
    try:
        freeze(paths, args.opt_arg, args.clang_arg)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
