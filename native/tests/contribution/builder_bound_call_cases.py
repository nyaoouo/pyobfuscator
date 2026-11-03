"""Exercise actual bound-call PE/COFF routes and paired caller-side bypasses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_binding_status_effects_cases import (  # noqa: E402
    alias_relocation, paired_instruction,
)
from builder_local_callee_cases import cache_value, disassembly, inputs_for  # noqa: E402
from builder_subject_cases import root, symbol_section_mutation  # noqa: E402
from cff_builder_bound_call import (  # noqa: E402
    BOUND_CALL, CTOR, LOCK, verify_builder_bound_call,
)
from cff_builder_receipt import (  # noqa: E402
    REPLAY_PROFILE, REPLAY_ROLES, ROLES, create_receipt, verify_receipt,
)
from cff_joint_machine_evidence import _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: changed input was accepted")


def finalizer(build, paths, output, receipt, *, bound):
    demo = build / "demo"
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"),
               str(paths["image"]), str(paths["report"]), "--output", str(output),
               "--post-mixed-plan", str(paths["plan"]),
               "--post-mixed-private", str(paths["private"]),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(receipt),
               "--builder-input-ir", str(paths["input_ir"]),
               "--builder-object", str(paths["object"]),
               "--builder-subjects", "--builder-entry-states", "--builder-local-callees",
               "--builder-local-callees-seed", cache_value(build, "PYOBF_NATIVE_CFF_SEED"),
               "--builder-helper-arguments", "--builder-binding-status-effects",
               "--builder-context-availability-effect"]
    if bound:
        command.append("--builder-bound-call")
    return subprocess.run(command, capture_output=True, text=True, timeout=90,
                          check=False)


def changed_codes(build, image_bytes):
    with TemporaryDirectory(dir=build) as directory:
        path = Path(directory) / "paired.dll"
        path.write_bytes(image_bytes)
        return {BOUND_CALL: disassembly(
            cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"), path, BOUND_CALL)}


def paired_finalizer_case(build, paths, changed_object, changed_image, label):
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        altered = {**paths, "object": temp / "paired.obj", "image": temp / "paired.dll"}
        altered["object"].write_bytes(changed_object)
        altered["image"].write_bytes(changed_image)
        data = {role: path.read_bytes() for role, path in altered.items()}
        assert set(data) == set(ROLES)
        receipt = temp / "paired.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        predecessor = finalizer(build, altered, temp / "predecessor.json", receipt,
                                bound=False)
        assert predecessor.returncode == 0 and (temp / "predecessor.json").exists(), \
            (label, predecessor.stderr)
        output = temp / "stale.json"
        output.write_bytes(b"stale")
        current = finalizer(build, altered, output, receipt, bound=True)
        assert current.returncode != 0 and not output.exists(), (label, current.stderr)
        assert ("builder bound-call route proof failed:" in current.stderr and
                "builder receipt verification failed:" not in current.stderr), \
            (label, current.stderr)
    print(f"{label}: predecessor admits; new gate refuses and clears stale output")


def unwind_mutation(image_bytes, object_bytes):
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xbc40,
                            BOUND_CALL).ranges[0]
    directory, size = data_directory(image, 3)
    records = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    found = [unwind for begin, _, unwind in records if begin == span.rva]
    assert len(found) == 1
    section = rva_section(image, found[0], 6, logical=True)
    offset = section.raw_offset + found[0] - section.rva + 5
    altered = bytearray(image_bytes)
    altered[offset] ^= 0x10
    return bytes(altered)


def body_item(items, raw):
    selected = [item for item in items if item.raw == bytes.fromhex(raw)]
    assert len(selected) == 1, (raw, selected)
    return selected[0]


def paired_call_target(object_bytes, image_bytes, item, target):
    """Change the E8 target and its COFF REL32 root together."""
    obj = parse_object(object_bytes)
    source = root(obj, BOUND_CALL)
    destination = root(obj, target)
    section = obj.sections[source.section - 1]
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xbc41,
                            BOUND_CALL).ranges[0]
    target_span = function_subject(object_bytes, image_bytes, image, 0xbc42,
                                   target).ranges[0]
    offset = item.address - image.preferred_base - span.rva
    assert item.raw[0] == 0xe8 and len(item.raw) == 5
    relocations = [(index, rel) for index, rel in enumerate(section.relocations)
                   if rel.offset == offset + 1]
    assert len(relocations) == 1 and relocations[0][1].kind == 4
    table = struct.unpack_from("<I", object_bytes,
                               20 + (section.index - 1) * 40 + 24)[0]
    changed_object = bytearray(object_bytes)
    struct.pack_into("<I", changed_object, table + relocations[0][0] * 10 + 4,
                     destination.index)
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_offset = pe_section.raw_offset + span.rva - pe_section.rva + offset
    changed_image = bytearray(image_bytes)
    struct.pack_into("<i", changed_image, pe_offset + 1,
                     image.preferred_base + target_span.rva - (item.address + 5))
    return bytes(changed_object), bytes(changed_image)


def fixed_inputs(build, data):
    """Read the independently frozen compiler inputs, including replay inputs."""
    fixed = (build / "builder.fixed.json").read_bytes()
    if json.loads(fixed)["profile"] != REPLAY_PROFILE:
        assert verify_receipt(fixed, data)["verified"] is True
        return fixed, data, None
    record = (build / "builder.replay.json").read_bytes()
    document = json.loads(record)
    paths = document["paths"]
    replay = {**data,
              "transformed_ir": (build / "demo" / "payload.cff.ll").read_bytes(),
              "request_manifest": Path(paths["request_manifest"]).read_bytes(),
              "recipe": Path(paths["recipe"]).read_bytes(),
              "opt_exe": Path(paths["opt_exe"]).read_bytes(),
              "clang_exe": Path(paths["clang_exe"]).read_bytes(),
              "pass_plugin": Path(paths["pass_plugin"]).read_bytes(),
              "replay_record": record}
    assert set(replay) == set(REPLAY_ROLES)
    assert verify_receipt(fixed, replay, profile=REPLAY_PROFILE)["verified"] is True
    return fixed, replay, REPLAY_PROFILE


def check(build):
    paths = inputs_for(build)
    data = {role: path.read_bytes() for role, path in paths.items()}
    assert set(data) == set(ROLES)
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {BOUND_CALL: disassembly(objdump, paths["image"], BOUND_CALL)}
    proof = verify_builder_bound_call(data["object"], data["image"],
                                      data["report"], codes)
    assert proof == {
        "verified": True, "pointer_guard_verified": True,
        "retain_status_route_verified": True,
        "captured_lease_route_verified": True,
        "invoke_argument_route_verified": True,
        "publication_source_verified": False, "retain_effect_verified": False,
        "invoke_body_verified": False, "platform_lock_effect_verified": False,
        "transitive_binding_closed": False,
        "object_sha256": hashlib.sha256(data["object"]).hexdigest(),
        "image_sha256": hashlib.sha256(data["image"]).hexdigest(),
        "report_sha256": hashlib.sha256(data["report"]).hexdigest(),
    }
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_bound_call"] == proof
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        receipt = temp / "current.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        refreshed = temp / "current.final.json"
        result = finalizer(build, paths, refreshed, receipt, bound=True)
        assert result.returncode == 0 and refreshed.exists(), result.stderr
        assert json.loads(refreshed.read_bytes())["builder_bound_call"] == proof

    refused("missing code", lambda: verify_builder_bound_call(
        data["object"], data["image"], data["report"], {}), "disassembly")
    refused("wrong code", lambda: verify_builder_bound_call(
        data["object"], data["image"], data["report"], {BOUND_CALL: "wrong"}),
        "exact selected symbol")
    refused("bad report", lambda: verify_builder_bound_call(
        data["object"], data["image"], b"{}", codes), "raw compiler report")
    missing = symbol_section_mutation(data["object"],
                                      root(parse_object(data["object"]), CTOR), 0)
    refused("missing constructor", lambda: verify_builder_bound_call(
        missing, data["image"], data["report"], codes), "one offset-zero root")
    refused("unwind changed", lambda: verify_builder_bound_call(
        data["object"], unwind_mutation(data["image"], data["object"]),
        data["report"], codes), "unwind")

    items = _instructions(codes[BOUND_CALL], data["image"], BOUND_CALL.lower())
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    assert optimization in ("none", "O2")
    compare = body_item(items, "4d39c8")
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 compare, bytes.fromhex("4d39c0"))
    frozen, frozen_inputs, frozen_profile = fixed_inputs(build, data)
    refused("independent fixed receipt rejects changed object",
            lambda: verify_receipt(frozen, {**frozen_inputs, "object": changed[0]},
                                   profile=frozen_profile) if frozen_profile else
            verify_receipt(frozen, {**frozen_inputs, "object": changed[0]}),
            "object bytes differ")
    refused("pointer self-compare", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "guard compares another value")
    paired_finalizer_case(build, paths, *changed, "pointer self-compare")

    request_raw = "4c8b442460" if optimization == "none" else "4c8b442430"
    request_new = "4c8b442458" if optimization == "none" else "4c8b442438"
    item = body_item(items, request_raw)
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 item, bytes.fromhex(request_new))
    refused("wrong request", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "body")
    paired_finalizer_case(build, paths, *changed, "wrong request to invoke")

    capture_raw = "488b542478" if optimization == "none" else "488b542468"
    capture_new = "488b542458" if optimization == "none" else "488b542438"
    item = body_item(items, capture_raw)
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 item, bytes.fromhex(capture_new))
    refused("wrong captured context", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "body")

    lock_call = next(item for item in items if item.opcode in ("call", "callq") and
                     LOCK.lower() in item.operands[0])
    changed_object = alias_relocation(data["object"], data["image"],
                                      BOUND_CALL, LOCK, lock_call)
    refused("section alias relocation", lambda: verify_builder_bound_call(
        changed_object, data["image"], data["report"], codes),
        "closed callee set")
    retain_call = next(item for item in items if item.opcode in ("call", "callq") and
                       "retain_context" in item.operands[0])
    changed = paired_call_target(data["object"], data["image"], retain_call, LOCK)
    refused("retargeted retain", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "relocation inventory")

    entry_jump = items[6]
    success = body_item(items, capture_raw)
    assert entry_jump.raw[0] == 0xe9 and len(entry_jump.raw) == 5
    bypass = b"\xe9" + struct.pack("<i", success.address - (entry_jump.address + 5))
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 entry_jump, bypass)
    refused("entry bypass", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "dispatcher")

    dispatcher = int(entry_jump.operands[0].split(" ", 1)[0], 16)
    copy_slot = "2c" if optimization == "none" else "24"
    tree_loads = [item for item in items if item.address >= dispatcher and
                  item.raw == bytes.fromhex("8b4424" + copy_slot)]
    assert len(tree_loads) >= 2
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 tree_loads[-1], bytes.fromhex("894424" + copy_slot))
    refused("unselected dispatcher stack write", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "dispatcher")

    frame = items[0]
    frame_changed = (bytes.fromhex("4881ec90000000") if optimization == "none"
                     else bytes.fromhex("4883ec70"))
    changed = paired_instruction(data["object"], data["image"], BOUND_CALL,
                                 frame, frame_changed)
    refused("frame changed", lambda: verify_builder_bound_call(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "frame")
    print(f"bound call: actual {optimization} PE/COFF, final report and focused negatives passed")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
