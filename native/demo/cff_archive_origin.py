"""Freeze a bounded, selected O2 archive producer chain for G3 finalization."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cff_archive_origin_contract import ROLES, role_paths
from cff_builder_receipt import _atomic_write

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from archive_format import (ACCESS_DOMAIN, BODY_DOMAIN, CORE, HEADER, MAGIC,  # noqa: E402
                            MAX_PACKAGE_BYTES, RECORD_BYTES, parse_plan)
from pack_archive import Package, cpp_source  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402


PROFILE = "g3-archive-origin-pre-post-o2-v1"
SCOPE = "trusted-builder-archive-origin-v1"
REPLAYED = ("archive_plan", "pending_ir", "merged_requests", "linked_ir", "prepared_ir")
TOOL_SOURCES = {"pack_tool_source": "pack_archive.py",
                "archive_format_source": "archive_format.py",
                "merge_requests_source": "merge_requests.py"}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DEMO_NAMES = {
    "optimized_ir": "payload.optimized.ll", "archive_plan": "payload.archive.plan.json",
    "pending_ir": "payload.archive.pending.ll", "package": "payload.archive.bin",
    "generated_cpp": "payload.archive.cpp", "bindings": "payload.archive.bindings.json",
    "source_requests": "payload.cff.requests.json",
    "runtime_requested_ir": "payload.archive.runtime.requested.ll",
    "runtime_requests": "payload.archive.runtime.requests.json",
    "merged_requests": "payload.archive.requests.json",
    "linked_ir": "payload.archive.linked.ll", "prepared_ir": "payload.archive.prepared.ll",
    "recipe": "payload.binding.recipe.json",
}


def _invalid(reason: str) -> None:
    raise ValueError(f"archive origin: {reason}")


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


def _json(data: bytes, *, limit: int, label: str) -> object:
    if type(data) is not bytes or len(data) > limit:
        _invalid(f"{label} exceeds its byte budget")
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _invalid("nonfinite JSON value"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"archive origin: malformed {label} JSON") from error


def _options(values: list[str], recipe: str) -> list[str]:
    prefixes = ("-pyobf-cff-functions=", "-pyobf-cff-config=",
                "-pyobf-cff-deep-functions=", "-pyobf-cff-seed=",
                "-pyobf-cff-markers=", "-pyobf-cff-strategy=")
    if (type(values) is not list or len(values) != len(prefixes) or
            any(type(value) is not str or not value.startswith(prefix) or
                len(value) > 1024 for value, prefix in zip(values, prefixes)) or
            values[0] != "-pyobf-cff-functions=" or
            values[1] != "-pyobf-cff-config=" + recipe or
            values[2] != "-pyobf-cff-deep-functions=pyobf_demo_compute" or
            not re.fullmatch(r"-pyobf-cff-seed=[0-9]{1,20}", values[3]) or
            values[4:] != ["-pyobf-cff-markers=true", "-pyobf-cff-strategy=relative-tree"]):
        _invalid("plan options differ from the selected O2 archive profile")
    return values


def _role_bytes(inputs: dict[str, bytes]) -> None:
    if type(inputs) is not dict or set(inputs) != set(ROLES) or any(
            type(value) is not bytes for value in inputs.values()):
        _invalid("exact 20 byte roles are required")


def _check_sources(inputs: dict[str, bytes]) -> None:
    tools = Path(__file__).resolve().parents[1] / "tools"
    for role, name in TOOL_SOURCES.items():
        if inputs[role] != (tools / name).read_bytes():
            _invalid(f"{role} differs from the verifier source")


def _paths(paths: dict[str, str]) -> None:
    demo = Path(paths["optimized_ir"]).parent
    if any(Path(paths[role]) != demo / name for role, name in _DEMO_NAMES.items()):
        _invalid("archive role paths differ from selected demo layout")
    if Path(paths["child_replay_record"]) != demo.parent / "builder.replay.json":
        _invalid("child replay path differs from selected demo layout")
    if (Path(paths["opt_exe"]).name.lower() != "opt.exe" or
            Path(paths["llvm_link_exe"]).name.lower() != "llvm-link.exe" or
            Path(paths["opt_exe"]).parent != Path(paths["llvm_link_exe"]).parent or
            Path(paths["pass_plugin"]) != demo.parent / "llvm" / "pyobf_native_cff.dll"):
        _invalid("compiler tool paths differ from selected demo layout")
    tools = Path(__file__).resolve().parents[1] / "tools"
    if any(Path(paths[role]) != tools / name for role, name in TOOL_SOURCES.items()):
        _invalid("tool source paths differ from selected demo layout")


def _child_link(inputs: dict[str, bytes], paths: dict[str, str]) -> None:
    child_bytes = inputs["child_replay_record"]
    child = _json(child_bytes, limit=16384, label="child replay")
    if (type(child) is not dict or child_bytes != _canonical(child) or
            child.get("schema_version") != 1 or
            child.get("profile") != "builder-replayed-mixed-post-v1" or
            child.get("scope") != "trusted-builder-replay-record-v1" or
            type(child.get("input_sha256")) is not dict or
            type(child.get("paths")) is not dict or
            child["input_sha256"].get("input_ir") != _sha(inputs["prepared_ir"]) or
            child["input_sha256"].get("request_manifest") != _sha(inputs["merged_requests"]) or
            child["paths"].get("input_ir") != paths["prepared_ir"] or
            child["paths"].get("request_manifest") != paths["merged_requests"]):
        _invalid("prepared IR or merged requests differ from fixed child replay inputs")


def _package(inputs: dict[str, bytes]) -> int:
    """Authenticate every existing descriptor, access tag and body against the plan."""
    records = parse_plan(_json(inputs["archive_plan"], limit=MAX_PACKAGE_BYTES * 3,
                               label="plan"))
    if len(records) != 36:
        _invalid("selected archive profile needs 36 records")
    data = inputs["package"]
    if not HEADER.size + RECORD_BYTES * len(records) <= len(data) <= MAX_PACKAGE_BYTES:
        _invalid("package capacity differs from plan")
    header = data[:HEADER.size]
    magic, version, count, identity, total = HEADER.unpack(header)
    if (magic, version, count, total) != (MAGIC, 1, len(records), len(data)):
        _invalid("package header differs from plan")
    bindings = _json(inputs["bindings"], limit=65536, label="bindings")
    if (type(bindings) is not dict or set(bindings) != {
            "schema_version", "plan_sha256", "archive_id", "package_sha256", "records"} or
            type(bindings["schema_version"]) is not int or bindings["schema_version"] != 1 or
            bindings["plan_sha256"] != _sha(inputs["archive_plan"]) or
            bindings["archive_id"] != identity.hex() or
            bindings["package_sha256"] != _sha(data) or
            type(bindings["records"]) is not list or
            len(bindings["records"]) != len(records)):
        _invalid("bindings differ from exact package and plan")
    keys, wrappers = [], []
    offset = HEADER.size + RECORD_BYTES * count
    for index, record in enumerate(records):
        row = bindings["records"][index]
        wrapper = f"__pyobf_archive_{identity.hex()}_{index}"
        if (type(row) is not dict or set(row) != {
                "id", "index", "wrapper", "key_hex", "size", "alignment"} or
                row["id"] != record.identity or type(row["index"]) is not int or
                row["index"] != index or row["wrapper"] != wrapper or
                type(row["size"]) is not int or row["size"] != len(record.data) or
                type(row["alignment"]) is not int or row["alignment"] != record.alignment or
                type(row["key_hex"]) is not str or
                re.fullmatch(r"[0-9a-f]{64}", row["key_hex"]) is None):
            _invalid("bindings record differs from typed plan")
        key = bytes.fromhex(row["key_hex"])
        start = HEADER.size + index * RECORD_BYTES
        descriptor = data[start:start + RECORD_BYTES]
        core = descriptor[:CORE.size]
        expected = (index, record.kind, record.bit_width, record.alignment,
                    len(record.data), offset, record.byte_order, 0)
        if CORE.unpack(core) != expected or offset + len(record.data) > len(data):
            _invalid("package descriptor differs from typed plan")
        nonce, tag = descriptor[40:52], descriptor[52:68]
        access_nonce, access_tag = descriptor[68:80], descriptor[80:96]
        if nonce == access_nonce:
            _invalid("package nonce profile differs")
        try:
            access = AESGCM(key).decrypt(access_nonce, access_tag,
                                         ACCESS_DOMAIN + header + descriptor[:68])
            plain = AESGCM(key).decrypt(nonce, data[offset:offset + len(record.data)] + tag,
                                        BODY_DOMAIN + header + core)
        except InvalidTag as error:
            raise ValueError("archive origin: package authentication failed") from error
        if access != b"" or plain != record.data:
            _invalid("package plaintext differs from typed plan")
        offset += len(record.data)
        keys.append(key)
        wrappers.append(wrapper)
    if offset != len(data):
        _invalid("package has unaccounted body bytes")
    generated = cpp_source(Package(data, identity, tuple(keys), tuple(wrappers)), records)
    # pack_archive uses Path.write_text, which translates LF on Windows.
    if inputs["generated_cpp"] != generated.encode("utf-8").replace(b"\n", b"\r\n"):
        _invalid("generated C++ differs from authenticated package")
    return count


def _record(inputs: dict[str, bytes], paths: dict[str, str],
            options: list[str], count: int) -> bytes:
    return _canonical({"schema_version": 1, "profile": PROFILE, "scope": SCOPE,
                       "role_sha256": {role: _sha(inputs[role]) for role in ROLES},
                       "replayed_sha256": {role: _sha(inputs[role]) for role in REPLAYED},
                       "paths": paths, "plan_opt_options": options,
                       "record_count": count})


def verify_archive_origin_record(record_bytes: bytes,
                                 exact_role_bytes: dict[str, bytes]) -> dict:
    """Verify the fixed record and authenticated package without invoking tools."""
    _role_bytes(exact_role_bytes)
    record = _json(record_bytes, limit=8192, label="record")
    if (type(record) is not dict or set(record) != {
            "schema_version", "profile", "scope", "role_sha256", "replayed_sha256",
            "paths", "plan_opt_options", "record_count"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile"] != PROFILE or record["scope"] != SCOPE or
            record_bytes != _canonical(record) or
            type(record["role_sha256"]) is not dict or
            set(record["role_sha256"]) != set(ROLES) or
            type(record["replayed_sha256"]) is not dict or
            set(record["replayed_sha256"]) != set(REPLAYED) or
            type(record["paths"]) is not dict or set(record["paths"]) != set(ROLES) or
            type(record["record_count"]) is not int or record["record_count"] != 36):
        _invalid("record shape differs from selected profile")
    paths = record["paths"]
    if any(type(value) is not str or not 0 < len(value) <= 1024 or
           "\\" in value or not Path(value).is_absolute() or
           Path(value).resolve().as_posix() != value for value in paths.values()):
        _invalid("record paths are not canonical absolute paths")
    if len(set(paths.values())) != len(paths):
        _invalid("record roles alias an input path")
    _paths(paths)
    _options(record["plan_opt_options"], paths["recipe"])
    for group, roles in (("role_sha256", ROLES), ("replayed_sha256", REPLAYED)):
        for role in roles:
            digest = record[group][role]
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None or \
                    digest != _sha(exact_role_bytes[role]):
                _invalid(f"{role} differs from frozen {group}")
    _check_sources(exact_role_bytes)
    _child_link(exact_role_bytes, paths)
    count = _package(exact_role_bytes)
    if count != record["record_count"]:
        _invalid("plan count differs from frozen record")
    return {"verified": True, "record_consistency_verified": True,
            "scope": SCOPE, "record_sha256": _sha(record_bytes),
            "record_count": count, "replayed_roles": list(REPLAYED)}


def _run(command: list[str], cwd: Path, stage: str) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=120,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"archive origin: {stage} did not finish") from error
    if result.returncode:
        _invalid(f"{stage} failed")


def _module_id(output: bytes, scratch_input: Path, original_input: Path) -> bytes:
    marker = b"; ModuleID = '"
    start = marker + scratch_input.as_posix().encode("utf-8") + b"'"
    ending = b"\r\n" if output.startswith(start + b"\r\n") else b"\n"
    if not output.startswith(start + ending):
        _invalid("unexpected replayed LLVM ModuleID")
    return (marker + original_input.as_posix().encode("utf-8") + b"'" + ending +
            output[len(start + ending):])


def _replay(inputs: dict[str, bytes], paths: dict[str, Path],
            options: list[str], scratch: Path) -> None:
    snapshot = {role: scratch / f"{role}{'.ll' if role.endswith('_ir') else '.json'}"
                for role in ("optimized_ir", "source_requests", "runtime_requested_ir",
                             "runtime_requests", "recipe", "bindings")}
    for role, path in snapshot.items():
        path.write_bytes(inputs[role])
    plan = scratch / "plan.json"
    pending = scratch / "pending.ll"
    replay_options = ["-pyobf-cff-config=" + snapshot["recipe"].as_posix()
                      if value.startswith("-pyobf-cff-config=") else value for value in options]
    _run([paths["opt_exe"].as_posix(), "-load-pass-plugin", paths["pass_plugin"].as_posix(),
          "-passes=pyobf-native-archive-plan", *replay_options,
          "-pyobf-archive-plan-output=" + plan.as_posix(), "-verify-each", "-S",
          snapshot["optimized_ir"].as_posix(), "-o", pending.as_posix()],
         paths["optimized_ir"].parent, "archive plan")
    if plan.read_bytes() != inputs["archive_plan"]:
        _invalid("archive plan differs from deterministic replay")
    if _module_id(pending.read_bytes(), snapshot["optimized_ir"],
                  paths["optimized_ir"]) != inputs["pending_ir"]:
        _invalid("pending IR differs from deterministic replay")
    merge = scratch / "merged.json"
    merge_tool = scratch / "merge_requests.py"
    merge_tool.write_bytes(inputs["merge_requests_source"])
    _run([sys.executable, merge_tool.as_posix(), merge.as_posix(),
          snapshot["source_requests"].as_posix(),
          snapshot["runtime_requests"].as_posix()],
         paths["source_requests"].parent, "request merge")
    if merge.read_bytes() != inputs["merged_requests"]:
        _invalid("merged requests differ from deterministic replay")
    linked = scratch / "linked.ll"
    _run([paths["llvm_link_exe"].as_posix(), "-S", pending.as_posix(),
          snapshot["runtime_requested_ir"].as_posix(), "-o", linked.as_posix()],
         paths["pending_ir"].parent, "archive llvm-link")
    if linked.read_bytes() != inputs["linked_ir"]:
        _invalid("linked IR differs from deterministic replay")
    prepared = scratch / "prepared.ll"
    _run([paths["opt_exe"].as_posix(), "-load-pass-plugin", paths["pass_plugin"].as_posix(),
          "-passes=pyobf-native-archive-materialize",
          "-pyobf-archive-bindings=" + snapshot["bindings"].as_posix(),
          "-verify-each", "-S", linked.as_posix(), "-o", prepared.as_posix()],
         paths["linked_ir"].parent, "archive materialize")
    if _module_id(prepared.read_bytes(), linked, paths["linked_ir"]) != inputs["prepared_ir"]:
        _invalid("prepared IR differs from deterministic replay")


def freeze(paths: dict[str, Path], record_path: Path,
           plan_opt_options: list[str]) -> dict:
    if set(paths) != set(ROLES) or any(not path.is_absolute() for path in paths.values()):
        _invalid("exact absolute role paths are required")
    paths = {role: path.resolve() for role, path in paths.items()}
    record_path = record_path.resolve()
    if record_path in paths.values() or len(set(paths.values())) != len(paths):
        _invalid("record or role paths alias an input")
    record_path.unlink(missing_ok=True)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    options = _options(plan_opt_options, paths["recipe"].as_posix())
    _check_sources(inputs)
    count = _package(inputs)
    path_values = {role: path.as_posix() for role, path in paths.items()}
    _child_link(inputs, path_values)
    with TemporaryDirectory(dir=record_path.parent) as temporary:
        _replay(inputs, paths, options, Path(temporary))
    if any(paths[role].read_bytes() != inputs[role] for role in ROLES):
        _invalid("role bytes changed during freeze")
    record = _record(inputs, path_values, options, count)
    proof = verify_archive_origin_record(record, inputs)
    _atomic_write(record_path, record)
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    frozen = commands.add_parser("freeze")
    frozen.add_argument("--record", required=True, type=Path)
    frozen.add_argument("--role", action="append", default=[])
    frozen.add_argument("--plan-opt-arg", action="append", default=[])
    args = parser.parse_args()
    try:
        paths = role_paths(args.role)
        proof = freeze(paths, args.record, args.plan_opt_arg)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
