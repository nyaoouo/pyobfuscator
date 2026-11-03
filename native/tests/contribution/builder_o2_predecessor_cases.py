"""Exercise the fixed O2 predecessor against an actual O2/archive child."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))

from cff_archive_origin_contract import ROLES as ARCHIVE_ROLES  # noqa: E402
from cff_builder_o2_predecessor import (freeze,  # noqa: E402
                                        verify_o2_predecessor_record)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def refused(label: str, action, fragment: str) -> None:
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: unexpected refusal: {error}"
        return
    raise AssertionError(f"{label}: altered input was accepted")


@contextmanager
def modified(path: Path, changed: bytes):
    original, state = path.read_bytes(), path.stat()
    path.write_bytes(changed)
    try:
        yield
    finally:
        path.write_bytes(original)
        os.utime(path, ns=(state.st_atime_ns, state.st_mtime_ns))


def finalizer(build: Path, archive_paths: dict[str, Path], output: Path,
              o2_paths: dict[str, Path], *, include_o2: bool) -> subprocess.CompletedProcess:
    demo = build / "demo"
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    objdump = [line.split("=", 1)[1] for line in cache.splitlines()
               if line.startswith("PYOBF_NATIVE_OBJDUMP_EXECUTABLE:FILEPATH=")]
    assert len(objdump) == 1
    child = json.loads(archive_paths["child_replay_record"].read_bytes())
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               objdump[0], str(demo / "libpyobf_native_demo_inner.dll"),
               str(demo / "payload.cff.coverage.json"), "--output", str(output),
               "--post-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
               "--post-mixed-private", str(demo / "payload.binding.private.json"),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(build / "builder.fixed.json"),
               "--builder-input-ir", str(archive_paths["prepared_ir"]),
               "--builder-object", str(demo / "payload.cff.obj"),
               "--builder-subjects", "--builder-entry-states",
               "--builder-replay-record", str(archive_paths["child_replay_record"]),
               "--builder-transformed-ir", str(demo / "payload.cff.ll"),
               "--builder-request-manifest", str(archive_paths["merged_requests"]),
               "--builder-recipe", str(archive_paths["recipe"]),
               "--builder-opt-exe", child["paths"]["opt_exe"],
               "--builder-clang-exe", child["paths"]["clang_exe"],
               "--builder-pass-plugin", str(archive_paths["pass_plugin"]),
               "--archive-origin-record", str(build / "archive.origin.json")]
    for role in ARCHIVE_ROLES:
        command.append("--archive-origin-role=" + role + "=" + str(archive_paths[role]))
    if include_o2:
        command.extend(("--builder-o2-predecessor-record", str(build / "o2.fixed.json"),
                        "--builder-o2-requested-ir", str(o2_paths["requested_ir"]),
                        "--builder-o2-optimized-ir", str(o2_paths["optimized_ir"]),
                        "--builder-o2-opt-exe", str(o2_paths["opt_exe"])))
    return subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)


def check(build: Path) -> None:
    record_path = build / "o2.fixed.json"
    record_bytes = record_path.read_bytes()
    record = json.loads(record_bytes)
    assert record_bytes == canonical(record)
    paths = {role: Path(record["paths"][role]) for role in
             ("requested_ir", "optimized_ir", "opt_exe")}
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    archive_bytes = (build / "archive.origin.json").read_bytes()
    archive = json.loads(archive_bytes)
    archive_paths = {role: Path(archive["paths"][role]) for role in ARCHIVE_ROLES}
    proof = verify_o2_predecessor_record(record_bytes, paths, inputs,
                                         archive_bytes, archive_paths)
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_o2_predecessor"] == proof
    assert proof["optimizer_replay_verified"] and proof["archive_input_join_verified"]
    assert not proof["cpp_source_provenance_verified"]
    assert not proof["publisher_signature_verified"]

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        output = scratch / "final.json"
        baseline = finalizer(build, archive_paths, output, paths, include_o2=True)
        assert baseline.returncode == 0, baseline.stderr
        assert json.loads(output.read_bytes())["builder_o2_predecessor"] == proof

        requested = inputs["requested_ir"]
        needle = b"icmp ne i32 %17, 3,"
        assert requested.count(needle) == 1
        altered_requested = requested.replace(needle, b"icmp ne i32 %17, 4,", 1)
        with modified(paths["requested_ir"], altered_requested):
            old = finalizer(build, archive_paths, scratch / "old.json", paths,
                            include_o2=False)
            assert old.returncode == 0, "prior finalizer did not admit requested IR change: " + old.stderr
            output.write_bytes(b"stale final report")
            new = finalizer(build, archive_paths, output, paths, include_o2=True)
            assert new.returncode != 0 and "builder O2 predecessor proof failed" in new.stderr
            assert not output.exists(), "requested IR refusal retained stale output"

            forged = dict(record)
            forged["role_sha256"] = dict(record["role_sha256"])
            forged["role_sha256"]["requested_ir"] = hashlib.sha256(altered_requested).hexdigest()
            refused("forged internally consistent digest", lambda:
                    verify_o2_predecessor_record(canonical(forged), paths,
                        {**inputs, "requested_ir": altered_requested}, archive_bytes,
                        archive_paths), "optimized IR differs")

        refused("optimized IR", lambda: verify_o2_predecessor_record(
            record_bytes, paths, {**inputs, "optimized_ir": inputs["optimized_ir"] + b"\n"},
            archive_bytes, archive_paths), "optimized_ir")
        refused("optimizer bytes", lambda: verify_o2_predecessor_record(
            record_bytes, paths, {**inputs, "opt_exe": inputs["opt_exe"] + b"\x00"},
            archive_bytes, archive_paths), "opt_exe")

        changed_command = dict(record)
        changed_command["command"] = list(record["command"])
        changed_command["command"][1] = "-passes=default<O3>"
        refused("optimizer options", lambda: verify_o2_predecessor_record(
            canonical(changed_command), paths, inputs, archive_bytes,
            archive_paths), "closed O2 profile")
        with modified(record_path, canonical(changed_command)):
            output.write_bytes(b"stale final report")
            new = finalizer(build, archive_paths, output, paths, include_o2=True)
            assert new.returncode != 0 and not output.exists(), "options refusal retained stale output"

        wrong_path = scratch / "requested-alias.ll"
        os.link(paths["requested_ir"], wrong_path)
        refused("same-byte requested hardlink", lambda: verify_o2_predecessor_record(
            record_bytes, {**paths, "requested_ir": wrong_path}, inputs,
            archive_bytes, archive_paths), "closed O2 profile")
        output.write_bytes(b"stale final report")
        new = finalizer(build, archive_paths, output,
                        {**paths, "requested_ir": wrong_path}, include_o2=True)
        assert new.returncode != 0 and not output.exists(), "wrong path retained stale output"

        wrong_archive_path = scratch / "optimized-alias.ll"
        os.link(paths["optimized_ir"], wrong_archive_path)
        refused("same-byte archive hardlink", lambda: verify_o2_predecessor_record(
            record_bytes, paths, inputs, archive_bytes,
            {**archive_paths, "optimized_ir": wrong_archive_path}),
            "archive optimized_ir path")

        alias = scratch / "record-hardlink.json"
        os.link(paths["requested_ir"], alias)
        refused("record hardlink alias", lambda: freeze(paths, alias), "aliases an input")
        assert alias.read_bytes() == requested and paths["requested_ir"].read_bytes() == requested
        refused("record self-alias", lambda: freeze(paths, paths["requested_ir"]),
                "aliases an input")
        assert paths["requested_ir"].read_bytes() == requested
        sentinel = scratch / "unrelated-sentinel.bin"
        sentinel.write_bytes(b"keep unrelated record target")
        sentinel_state = sentinel.stat()
        record_symlink = scratch / "record-symlink.json"
        try:
            os.symlink(sentinel, record_symlink)
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            original_resolve = Path.resolve
            with patch.object(Path, "is_symlink", lambda path: path == record_symlink), \
                    patch.object(Path, "resolve", lambda path, *args, **kwargs:
                                 sentinel if path == record_symlink else
                                 original_resolve(path, *args, **kwargs)):
                refused("record symlink target (simulated)",
                        lambda: freeze(paths, record_symlink), "must not be a symlink")
            print("NTFS symlink creation unavailable; tested the guarded resolution path")
        else:
            refused("record symlink target", lambda: freeze(paths, record_symlink),
                    "must not be a symlink")
            assert record_symlink.is_symlink()
        assert sentinel.read_bytes() == b"keep unrelated record target"
        assert sentinel.stat().st_mtime_ns == sentinel_state.st_mtime_ns

        stale_record = scratch / "stale-freeze.json"
        stale_record.write_bytes(b"stale fixed record")
        refused("failed freeze clears stale record", lambda: freeze(
            {**paths, "optimized_ir": paths["requested_ir"]}, stale_record),
            "role paths alias")
        assert not stale_record.exists()

        moved = scratch / "o2.fixed.moved.json"
        record_path.rename(moved)
        try:
            output.write_bytes(b"stale final report")
            missing = finalizer(build, archive_paths, output, paths, include_o2=True)
            assert missing.returncode != 0 and not output.exists(), "missing record retained stale output"
        finally:
            moved.rename(record_path)
        assert record_path.read_bytes() == record_bytes

    print("fixed O2 predecessor and paired archive path/byte refusals passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: builder_o2_predecessor_cases.py <build-dir>")
    check(Path(sys.argv[1]).resolve())
