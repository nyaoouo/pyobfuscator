"""Exercise the selected O2 archive producer record on actual child artifacts."""

from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools")]

from cff_archive_origin import freeze, verify_archive_origin_record  # noqa: E402
from cff_archive_origin_contract import ROLES  # noqa: E402


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def finalizer(build: Path, paths: dict[str, Path], output: Path,
              *, archive: bool) -> subprocess.CompletedProcess:
    demo = build / "demo"
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    objdump = [line.split("=", 1)[1] for line in cache.splitlines()
               if line.startswith("PYOBF_NATIVE_OBJDUMP_EXECUTABLE:FILEPATH=")]
    assert len(objdump) == 1
    child = json.loads(paths["child_replay_record"].read_bytes())
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               objdump[0], str(demo / "libpyobf_native_demo_inner.dll"),
               str(demo / "payload.cff.coverage.json"), "--output", str(output),
               "--post-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
               "--post-mixed-private", str(demo / "payload.binding.private.json"),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(build / "builder.fixed.json"),
               "--builder-input-ir", str(paths["prepared_ir"]),
               "--builder-object", str(demo / "payload.cff.obj"),
               "--builder-subjects", "--builder-entry-states",
               "--builder-replay-record", str(paths["child_replay_record"]),
               "--builder-transformed-ir", str(demo / "payload.cff.ll"),
               "--builder-request-manifest", str(paths["merged_requests"]),
               "--builder-recipe", str(paths["recipe"]),
               "--builder-opt-exe", child["paths"]["opt_exe"],
               "--builder-clang-exe", child["paths"]["clang_exe"],
               "--builder-pass-plugin", str(paths["pass_plugin"])]
    if archive:
        command.extend(("--archive-origin-record", str(build / "archive.origin.json")))
        for role in ROLES:
            command.append("--archive-origin-role=" + role + "=" + str(paths[role]))
    return subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)


def check(build: Path) -> None:
    record_path = build / "archive.origin.json"
    record_bytes = record_path.read_bytes()
    record = json.loads(record_bytes)
    assert record_bytes == canonical(record)
    paths = {role: Path(record["paths"][role]) for role in ROLES}
    assert all(path.is_file() for path in paths.values())
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    proof = verify_archive_origin_record(record_bytes, inputs)
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["archive_origin"] == proof
    assert proof["record_count"] == 36
    plan = json.loads(inputs["archive_plan"])
    assert len(plan["records"]) == 36
    assert [plan["records"][index]["data_hex"] for index in (28, 30)] == [
        "00000000", "00000000"]
    bindings = json.loads(inputs["bindings"])
    assert all(row["key_hex"].encode() not in record_bytes for row in bindings["records"])
    assert all(row["key_hex"].encode() not in canonical(proof) for row in bindings["records"])

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        old_output, new_output = scratch / "old.json", scratch / "new.json"
        baseline = finalizer(build, paths, new_output, archive=True)
        assert baseline.returncode == 0, baseline.stderr
        assert json.loads(new_output.read_bytes())["archive_origin"] == proof

        altered = copy.deepcopy(plan)
        altered["records"][28]["data_hex"] = "01000000"
        changed_plan = json.dumps(altered, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with modified(paths["archive_plan"], changed_plan):
            old = finalizer(build, paths, old_output, archive=False)
            assert old.returncode == 0, "old complete finalizer did not admit plan mutation: " + old.stderr
            new_output.write_bytes(b"stale final report")
            new = finalizer(build, paths, new_output, archive=True)
            assert new.returncode != 0 and "archive origin proof failed" in new.stderr
            assert not new_output.exists(), "refusal retained stale final report"
        assert paths["archive_plan"].read_bytes() == inputs["archive_plan"]

        # An optimized original predicate change and a forged pending IR cannot
        # pass the producer replay even when the fixed record is freshly requested.
        optimized = inputs["optimized_ir"]
        assert b"icmp eq i32 %9, 3" in optimized
        with modified(paths["optimized_ir"], optimized.replace(
                b"icmp eq i32 %9, 3", b"icmp eq i32 %9, 4", 1)):
            refused("optimized producer", lambda: freeze(paths, scratch / "optimized.json",
                    record["plan_opt_options"]), "deterministic replay")
        pending = inputs["pending_ir"]
        assert b"source_filename = \"llvm-link\"" in pending
        with modified(paths["pending_ir"], pending.replace(
                b"source_filename = \"llvm-link\"",
                b"source_filename = \"forged-src\"", 1)):
            refused("forged pending", lambda: freeze(paths, scratch / "pending.json",
                    record["plan_opt_options"]), "pending IR differs")

        for role, fragment in (("package", "package"), ("bindings", "bindings"),
                               ("generated_cpp", "generated C++")):
            changed = bytearray(inputs[role])
            changed[-1] ^= 1
            refused(role, lambda role=role, changed=changed: verify_archive_origin_record(
                record_bytes, {**inputs, role: bytes(changed)}), role)
            with modified(paths[role], bytes(changed)):
                new_output.write_bytes(b"stale final report")
                result = finalizer(build, paths, new_output, archive=True)
                assert result.returncode != 0 and not new_output.exists(), role

        def fresh_digest_refusal(changes: dict[str, bytes], fragment: str) -> None:
            rec = copy.deepcopy(record)
            for role, changed in changes.items():
                rec["role_sha256"][role] = sha(changed)
                if role in rec["replayed_sha256"]:
                    rec["replayed_sha256"][role] = sha(changed)
            refused("authenticated package", lambda: verify_archive_origin_record(
                canonical(rec), {**inputs, **changes}), fragment)

        def package_change(changed: bytes) -> dict[str, bytes]:
            updated = json.loads(inputs["bindings"])
            updated["package_sha256"] = sha(changed)
            return {"package": changed, "bindings":
                    (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode()}

        body = bytearray(inputs["package"])
        body[-1] ^= 1
        fresh_digest_refusal(package_change(bytes(body)), "package authentication failed")
        for core_offset in (0, 4, 8, 12, 16, 24, 32, 36):
            descriptor = bytearray(inputs["package"])
            descriptor[40 + core_offset] ^= 1
            fresh_digest_refusal(package_change(bytes(descriptor)), "package descriptor")
        access_tag = bytearray(inputs["package"])
        access_tag[40 + 80] ^= 1  # descriptor zero: access tag
        fresh_digest_refusal(package_change(bytes(access_tag)), "package authentication failed")
        binding_doc = json.loads(inputs["bindings"])
        key = binding_doc["records"][28]["key_hex"]
        binding_doc["records"][28]["key_hex"] = ("0" if key[0] != "0" else "1") + key[1:]
        fresh_digest_refusal({"bindings": (json.dumps(binding_doc, indent=2, sort_keys=True) +
                                           "\n").encode()}, "package authentication failed")
        source = bytearray(inputs["generated_cpp"])
        source[-3] ^= 1
        fresh_digest_refusal({"generated_cpp": bytes(source)}, "generated C++")

        wrong = copy.deepcopy(record)
        wrong["plan_opt_options"][-1] = "-pyobf-cff-strategy=none"
        refused("wrong option", lambda: verify_archive_origin_record(
            canonical(wrong), inputs), "plan options")
        with modified(record_path, canonical(wrong)):
            new_output.write_bytes(b"stale final report")
            result = finalizer(build, paths, new_output, archive=True)
            assert result.returncode != 0 and not new_output.exists()
        wrong = copy.deepcopy(record)
        wrong["role_sha256"]["package"] = "0" * 64
        refused("wrong record", lambda: verify_archive_origin_record(
            canonical(wrong), inputs), "package differs")
        with modified(record_path, canonical(wrong)):
            new_output.write_bytes(b"stale final report")
            result = finalizer(build, paths, new_output, archive=True)
            assert result.returncode != 0 and not new_output.exists()
        refused("wrong role", lambda: verify_archive_origin_record(
            record_bytes, {role: inputs[role] for role in ROLES if role != "package"}),
            "exact 20 byte roles")
        new_output.write_bytes(b"stale final report")
        result = finalizer(build, {**paths, "package": paths["bindings"]},
                           new_output, archive=True)
        assert result.returncode != 0 and not new_output.exists()
        refused("changed package auth", lambda: verify_archive_origin_record(
            record_bytes, {**inputs, "package": inputs["package"][:-1] + b"\0"}),
            "package")

        package = paths["package"]
        before = package.read_bytes()
        direct = finalizer(build, paths, package, archive=True)
        assert direct.returncode != 0 and "aliases an input" in direct.stderr
        assert package.read_bytes() == before
        aliased_output = scratch / "alias.json"
        sidecar_input = aliased_output.with_name(aliased_output.name + ".tmp")
        sidecar_input.write_bytes(before)
        sidecar = finalizer(build, {**paths, "package": sidecar_input},
                            aliased_output, archive=True)
        assert sidecar.returncode != 0 and "aliases an input" in sidecar.stderr
        assert sidecar_input.read_bytes() == before and package.read_bytes() == before

    assert all(path.read_bytes() == inputs[role] for role, path in paths.items())
    print(json.dumps({"archive_record": sha(record_bytes), "records": proof["record_count"],
                      "old_finalizer_admitted_plan_mutation": True,
                      "archive_finalizer_refused_plan_mutation": True}, sort_keys=True))


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
