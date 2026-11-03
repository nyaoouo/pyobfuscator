"""Exercise deterministic builder replay against actual mixed child artifacts."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools")]

from cff_builder_receipt import (  # noqa: E402
    PROFILE, REPLAY_PROFILE, REPLAY_ROLES, ROLES, create_receipt, verify_receipt,
)
from cff_builder_replay import freeze, verify_replay_record  # noqa: E402
import cff_builder_replay as replay  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


REQUIRE_BINDING = ("_ZN12pyobfuscator6native12contribution6scoped12_GLOBAL__N_"
                   "115require_bindingERKNS2_5ScopeERKNS0_21BootstrapContextLeaseE")
CMOVNE = bytes.fromhex("0f45ca")
CMOVE = bytes.fromhex("0f44ca")
NOP = bytes.fromhex("909090")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: unexpected refusal: {error}"
        return
    raise AssertionError(f"{label}: altered input was accepted")


def paths_for(build, record):
    demo = build / "demo"
    paths = {"image": demo / "libpyobf_native_demo_inner.dll",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json",
             "object": demo / "payload.cff.obj",
             "transformed_ir": demo / "payload.cff.ll",
             "replay_record": build / "builder.replay.json",
             "receipt": build / "builder.fixed.json"}
    paths.update({role: Path(path) for role, path in record["paths"].items()})
    assert set(paths) == set(REPLAY_ROLES) | {"receipt"}
    return paths


def finalizer(build, paths, output, *, replay, receipt=None):
    demo = build / "demo"
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    matches = [line.split("=", 1)[1] for line in cache.splitlines()
               if line.startswith("PYOBF_NATIVE_OBJDUMP_EXECUTABLE:FILEPATH=")]
    assert len(matches) == 1
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               matches[0], str(paths["image"]), str(paths["report"]),
               "--output", str(output),
               "--post-mixed-plan", str(paths["plan"]),
               "--post-mixed-private", str(paths["private"]),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(receipt or paths["receipt"]),
               "--builder-input-ir", str(paths["input_ir"]),
               "--builder-object", str(paths["object"]),
               "--builder-subjects", "--builder-entry-states"]
    if replay:
        for role in ("replay_record", "transformed_ir", "request_manifest", "recipe",
                     "opt_exe", "clang_exe", "pass_plugin"):
            command.extend(("--builder-" + role.replace("_", "-"), str(paths[role])))
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=40)


def changed_cmov(object_bytes, image_bytes, *, source_optimization):
    pattern = CMOVNE if source_optimization == "none" else CMOVE
    obj = parse_object(object_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == REQUIRE_BINDING and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    object_offsets = [section.offset + offset for offset in range(section.size - 2)
                      if object_bytes[section.offset + offset:
                                      section.offset + offset + 3] == pattern]
    assert len(object_offsets) == 1, "expected one require_binding cmov in COFF"
    local = object_offsets[0] - section.offset
    assert all(not (relocation.offset < local + 3 and local < relocation.offset +
                    (8 if relocation.kind == 1 else 4)) for relocation in section.relocations)
    image = parse_image(image_bytes)
    linked = [symbol for symbol in image_symbols(image_bytes, image)
              if symbol.name == REQUIRE_BINDING and symbol.type == 0x20 and symbol.section > 0]
    assert len(linked) == 1
    rva = image.layout.sections[linked[0].section - 1].rva + linked[0].value
    pe_section = rva_section(image, rva, section.size, logical=True)
    start = pe_section.raw_offset + rva - pe_section.rva
    image_offsets = [start + offset for offset in range(section.size - 2)
                     if image_bytes[start + offset:start + offset + 3] == pattern]
    assert len(image_offsets) == 1 and \
           image_offsets[0] - start == local, "COFF and PE cmov must be the same instruction"
    altered_object, altered_image = bytearray(object_bytes), bytearray(image_bytes)
    altered_object[object_offsets[0]:object_offsets[0] + 3] = NOP
    altered_image[image_offsets[0]:image_offsets[0] + 3] = NOP
    return bytes(altered_object), bytes(altered_image)


def snapshot_freeze(paths, record, temp):
    """Transient original-path changes must not enter the compiler replay."""
    original_run = replay._run
    for role in ("input_ir", "request_manifest", "recipe", "private", "plan"):
        output_paths = {**paths,
                        "replay_record": temp / f"{role}.replay.json",
                        "receipt": temp / f"{role}.receipt.json"}

        def swapped_run(command, cwd, name):
            if name != "opt":
                return original_run(command, cwd, name)
            target = paths[role]
            data, state = target.read_bytes(), target.stat()
            try:
                target.write_bytes(b"invalid transient compiler input\n")
                return original_run(command, cwd, name)
            finally:
                target.write_bytes(data)
                os.utime(target, ns=(state.st_atime_ns, state.st_mtime_ns))

        with patch.object(replay, "_run", side_effect=swapped_run):
            freeze(output_paths, record["opt_options"], record["clang_options"])
        assert output_paths["replay_record"].read_bytes() == paths["replay_record"].read_bytes()
        assert output_paths["receipt"].read_bytes() == paths["receipt"].read_bytes()


def check(build):
    record_bytes = (build / "builder.replay.json").read_bytes()
    record = json.loads(record_bytes)
    paths = paths_for(build, record)
    inputs = {role: paths[role].read_bytes() for role in REPLAY_ROLES}
    proof = verify_replay_record(record_bytes, inputs)
    assert proof == {"record_consistency_verified": True,
                     "scope": "trusted-builder-replay-record-v1",
                     "record_sha256": sha(record_bytes)}
    assert verify_receipt(paths["receipt"].read_bytes(), inputs,
                          profile=REPLAY_PROFILE)["verified"] is True
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_replay"] == proof

    altered = copy.deepcopy(record)
    altered["input_sha256"]["recipe"] = "0" * 64
    refused("changed digest", lambda: verify_replay_record(
        json.dumps(altered, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        {**inputs, "replay_record": json.dumps(altered, sort_keys=True,
                                                separators=(",", ":")).encode() + b"\n"}),
        "recipe differs")
    refused("duplicate record key", lambda: verify_replay_record(
        record_bytes.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
        {**inputs, "replay_record": record_bytes.replace(
            b'"schema_version":1', b'"schema_version":1,"schema_version":1')}),
        "duplicate record key")
    altered = copy.deepcopy(record)
    altered["opt_options"][3] = "-pyobf-cff-seed=1"
    altered["opt_options"].append("-pyobf-cff-seed=2")
    changed = (json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n").encode()
    refused("duplicate opt argument", lambda: verify_replay_record(
        changed, {**inputs, "replay_record": changed}), "required mixed CFF input")
    altered = copy.deepcopy(record)
    altered["paths"]["recipe"] = "C:/unexpected.json"
    changed = (json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n").encode()
    refused("changed recipe path", lambda: verify_replay_record(
        changed, {**inputs, "replay_record": changed}),
        "recipe path differs from its opt option")
    refused("noncanonical record", lambda: verify_replay_record(
        record_bytes[:-1], {**inputs, "replay_record": record_bytes[:-1]}),
        "not canonical JSON")
    refused("changed exact input role", lambda: verify_replay_record(
        record_bytes, {**inputs, "request_manifest": inputs["request_manifest"] + b"x"}),
        "request_manifest differs")

    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        snapshot_freeze(paths, record, temp)
        relative = {**paths, "opt_exe": Path(paths["opt_exe"].name),
                    "replay_record": temp / "relative.replay.json",
                    "receipt": temp / "relative.receipt.json"}
        relative["replay_record"].write_bytes(b"stale")
        relative["receipt"].write_bytes(b"stale")
        refused("relative tool path", lambda: freeze(
            relative, record["opt_options"], record["clang_options"]),
            "input paths must be absolute")
        assert not relative["replay_record"].exists()
        assert not relative["receipt"].exists()
        copied_recipe = temp / "copied.recipe.json"
        copied_recipe.write_bytes(inputs["recipe"])
        mismatched_recipe = {**paths, "recipe": copied_recipe,
                             "replay_record": temp / "mismatched.replay.json",
                             "receipt": temp / "mismatched.receipt.json"}
        refused("mismatched recipe option", lambda: freeze(
            mismatched_recipe, record["opt_options"], record["clang_options"]),
            "recipe option path differs")
        plan_document = json.loads(inputs["plan"])
        plan_digest = plan_document["input_ir_sha256"].encode("ascii")
        assert inputs["plan"].count(plan_digest) == 1
        bad_plan = temp / "bad-plan.json"
        bad_plan.write_bytes(inputs["plan"].replace(plan_digest, b"0" * 64))
        bad_plan_paths = {**paths, "plan": bad_plan,
                          "replay_record": temp / "bad-plan.replay.json",
                          "receipt": temp / "bad-plan.receipt.json"}
        bad_plan_options = [value.replace(paths["plan"].as_posix(), bad_plan.as_posix())
                            for value in record["opt_options"]]
        refused("frozen plan IR digest", lambda: freeze(
            bad_plan_paths, bad_plan_options, record["clang_options"]),
            "frozen original-edge plan differs from exact IR snapshot")
        assert not bad_plan_paths["replay_record"].exists()
        assert not bad_plan_paths["receipt"].exists()
        # Configuration mistakes must not delete a tool, object, or linked PE.
        for output, victim in (("receipt", "image"), ("replay_record", "object")):
            colliding = {**paths, output: paths[victim]}
            before = sha(paths[victim].read_bytes())
            refused("aliased replay output", lambda: freeze(
                colliding, record["opt_options"], record["clang_options"]), "aliases")
            assert sha(paths[victim].read_bytes()) == before

        failed_paths = {**paths, "opt_exe": paths["clang_exe"],
                        "replay_record": temp / "failed.replay.json",
                        "receipt": temp / "failed.receipt.json"}
        failed_paths["replay_record"].write_bytes(b"stale")
        failed_paths["receipt"].write_bytes(b"stale")
        refused("wrong opt executable", lambda: freeze(
            failed_paths, record["opt_options"], record["clang_options"]),
            "canonical LLVM print has ambiguous module path")
        assert not failed_paths["replay_record"].exists()
        assert not failed_paths["receipt"].exists()

        for role in ("request_manifest", "recipe", "opt_exe", "replay_record"):
            mutant = temp / (role + ".changed")
            mutant.write_bytes(inputs[role] + b"x" if role != "opt_exe" else b"wrong tool")
            changed_paths = {**paths, role: mutant}
            output = temp / "stale.final.json"
            output.write_bytes(b"stale")
            denied = finalizer(build, changed_paths, output, replay=True)
            assert denied.returncode != 0 and not output.exists(), (role, denied.stderr)
            assert f"{role} bytes differ" in denied.stderr, (role, denied.stderr)

        changed_args = copy.deepcopy(record)
        changed_args["opt_options"][3] = "-pyobf-cff-seed=1"
        changed_bytes = (json.dumps(changed_args, sort_keys=True,
                                    separators=(",", ":")) + "\n").encode()
        changed_path = temp / "changed-args.replay.json"
        changed_path.write_bytes(changed_bytes)
        output = temp / "changed-args.final.json"
        output.write_bytes(b"stale")
        denied = finalizer(build, {**paths, "replay_record": changed_path},
                           output, replay=True)
        assert denied.returncode != 0 and not output.exists()
        assert "replay_record bytes differ" in denied.stderr, denied.stderr

        altered_record = copy.deepcopy(record)
        altered_record["input_sha256"]["request_manifest"] = "0" * 64
        changed_record = (json.dumps(altered_record, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode()
        record_path = temp / "refrozen.replay.json"
        record_path.write_bytes(changed_record)
        refrozen = temp / "refrozen.receipt.json"
        refrozen.write_bytes(create_receipt(
            {**inputs, "replay_record": changed_record}, profile=REPLAY_PROFILE))
        output = temp / "refrozen.final.json"
        output.write_bytes(b"stale")
        denied = finalizer(build, {**paths, "replay_record": record_path}, output,
                           replay=True, receipt=refrozen)
        assert denied.returncode != 0 and not output.exists()
        assert "builder replay record failed" in denied.stderr and \
               "request_manifest differs" in denied.stderr, denied.stderr

        # A paired COFF/PE change is admissible to the older six-role finalizer
        # because require_binding lies outside its selected function subjects.
        cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
        source_optimization = next((name for name in ("none", "O2") if
                                    f"PYOBF_NATIVE_CFF_SOURCE_OPT:UNINITIALIZED={name}" in cache or
                                    f"PYOBF_NATIVE_CFF_SOURCE_OPT:STRING={name}" in cache), None)
        assert source_optimization is not None
        changed_object, changed_image = changed_cmov(
            inputs["object"], inputs["image"],
            source_optimization=source_optimization)
        altered_paths = {**paths, "object": temp / "changed.obj",
                         "image": temp / "changed.dll",
                         "replay_record": temp / "changed.replay.json",
                         "receipt": temp / "changed.receipt.json"}
        altered_paths["object"].write_bytes(changed_object)
        altered_paths["image"].write_bytes(changed_image)
        old_inputs = {role: altered_paths[role].read_bytes() for role in ROLES}
        old_receipt = temp / "old.receipt.json"
        old_receipt.write_bytes(create_receipt(old_inputs, profile=PROFILE))
        assert verify_receipt(old_receipt.read_bytes(), old_inputs,
                              profile=PROFILE)["verified"] is True
        accepted = finalizer(build, altered_paths, temp / "old.final.json",
                             replay=False, receipt=old_receipt)
        assert accepted.returncode == 0, accepted.stderr
        assert (temp / "old.final.json").exists()
        altered_paths["replay_record"].write_bytes(b"stale")
        altered_paths["receipt"].write_bytes(b"stale")
        refused("paired COFF/PE cmov removal", lambda: freeze(
            altered_paths, record["opt_options"], record["clang_options"]),
            "object differs from deterministic compiler replay")
        assert not altered_paths["replay_record"].exists()
        assert not altered_paths["receipt"].exists()

    print("builder replay: five snapshotted compiler inputs, exact output and closed receipt, "
          f"{source_optimization} paired require_binding cmov red, "
          "role mutations and alias safety verified")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
