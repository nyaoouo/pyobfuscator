"""Exercise actual context-availability COFF/PE routes and paired bypasses."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"),
                str(Path(__file__).resolve().parent)]

from builder_binding_status_effects_cases import paired_instruction  # noqa: E402
from builder_local_callee_cases import cache_value, disassembly, inputs_for  # noqa: E402
from builder_subject_cases import root, symbol_section_mutation  # noqa: E402
from cff_builder_context_availability import (  # noqa: E402
    AVAILABILITY, CONTEXT_EFFECT_CALLEES, LOCK, UNLOCK,
    verify_builder_context_availability,
)
from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
from cff_joint_machine_evidence import _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import (data_directory, parse_image, read_rva,  # noqa: E402
                       rva_section)


def refused(label, action, expected):
    try:
        action()
    except ValueError as error:
        assert expected in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: changed input was accepted")


def finalizer(build, paths, output, receipt, *, context):
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
               "--builder-helper-arguments", "--builder-binding-status-effects"]
    if context:
        command.append("--builder-context-availability-effect")
    return subprocess.run(command, capture_output=True, text=True, timeout=90,
                          check=False)


def _paired_call_target(object_bytes, image_bytes, item, target):
    """Retarget one direct E8 call in both the link relocation and final PE."""
    obj = parse_object(object_bytes)
    owner = root(obj, AVAILABILITY)
    replacement = root(obj, target)
    section = obj.sections[owner.section - 1]
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xb922,
                            AVAILABILITY).ranges[0]
    target_span = function_subject(object_bytes, image_bytes, image, 0xb923,
                                   target).ranges[0]
    offset = item.address - image.preferred_base - span.rva
    assert item.raw[0] == 0xe8 and len(item.raw) == 5
    assert object_bytes[section.offset + offset:section.offset + offset + 5] == b"\xe8\0\0\0\0"
    relocations = [(index, relocation) for index, relocation in enumerate(section.relocations)
                   if relocation.offset == offset + 1]
    assert len(relocations) == 1 and relocations[0][1].kind == 4
    table = struct.unpack_from("<I", object_bytes,
                               20 + (section.index - 1) * 40 + 24)[0]
    changed_object = bytearray(object_bytes)
    struct.pack_into("<I", changed_object, table + relocations[0][0] * 10 + 4,
                     replacement.index)
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_offset = pe_section.raw_offset + span.rva - pe_section.rva + offset
    assert image_bytes[pe_offset:pe_offset + 5] == item.raw
    changed_image = bytearray(image_bytes)
    relative = image.preferred_base + target_span.rva - (item.address + 5)
    struct.pack_into("<i", changed_image, pe_offset + 1, relative)
    return bytes(changed_object), bytes(changed_image)


def _unwind_mutation(image_bytes, object_bytes):
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xb924,
                            AVAILABILITY).ranges[0]
    directory, size = data_directory(image, 3)
    records = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    found = [unwind for begin, _, unwind in records if begin == span.rva]
    assert len(found) == 1
    section = rva_section(image, found[0], 6, logical=True)
    offset = section.raw_offset + found[0] - section.rva + 5
    altered = bytearray(image_bytes)
    altered[offset] ^= 0x10
    return bytes(altered)


def _paired_finalizer_case(build, paths, changed_object, changed_image, label):
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        altered = {**paths, "object": temp / "paired.obj", "image": temp / "paired.dll"}
        altered["object"].write_bytes(changed_object)
        altered["image"].write_bytes(changed_image)
        inputs = {role: path.read_bytes() for role, path in altered.items()}
        assert set(inputs) == set(ROLES)
        receipt = temp / "paired.receipt.json"
        receipt.write_bytes(create_receipt(inputs))
        assert verify_receipt(receipt.read_bytes(), inputs)["verified"] is True
        predecessor = finalizer(build, altered, temp / "predecessor.json", receipt,
                                context=False)
        assert predecessor.returncode == 0, (label, predecessor.stderr)
        assert (temp / "predecessor.json").exists()
        output = temp / "stale.json"
        output.write_bytes(b"stale")
        current = finalizer(build, altered, output, receipt, context=True)
        assert current.returncode != 0 and not output.exists(), (label, current.stderr)
        assert ("builder context-availability effect proof failed:" in current.stderr and
                "builder receipt verification failed:" not in current.stderr), \
            (label, current.stderr)
    print(f"{label}: fresh six-role receipt, predecessor admits, new gate refuses and clears stale output")


def _changed_codes(build, objdump, image_bytes):
    with TemporaryDirectory(dir=build) as directory:
        image_path = Path(directory) / "changed.dll"
        image_path.write_bytes(image_bytes)
        return {name: disassembly(objdump, image_path, name)
                for name in CONTEXT_EFFECT_CALLEES}


def check(build):
    paths = inputs_for(build)
    data = {role: path.read_bytes() for role, path in paths.items()}
    assert set(data) == set(ROLES)
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {name: disassembly(objdump, paths["image"], name)
             for name in CONTEXT_EFFECT_CALLEES}
    proof = verify_builder_context_availability(data["object"], data["image"],
                                                data["report"], codes)
    assert proof == {
        "verified": True, "context_availability_body_verified": True,
        "closing_field_route_verified": True, "lock_pair_route_verified": True,
        "platform_lock_effect_verified": False, "transitive_binding_closed": False,
        "object_sha256": hashlib.sha256(data["object"]).hexdigest(),
        "image_sha256": hashlib.sha256(data["image"]).hexdigest(),
        "report_sha256": hashlib.sha256(data["report"]).hexdigest(),
    }
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_context_availability_effect"] == proof
    with TemporaryDirectory(dir=build) as directory:
        receipt = Path(directory) / "current.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        refreshed = Path(directory) / "current.final.json"
        result = finalizer(build, paths, refreshed, receipt, context=True)
        assert result.returncode == 0 and refreshed.exists(), result.stderr
        current = json.loads(refreshed.read_bytes())
        assert current["builder_context_availability_effect"] == proof
    refused("missing lock disassembly", lambda: verify_builder_context_availability(
        data["object"], data["image"], data["report"],
        {AVAILABILITY: codes[AVAILABILITY], UNLOCK: codes[UNLOCK]}),
        "three linked disassemblies")
    refused("wrong lock disassembly", lambda: verify_builder_context_availability(
        data["object"], data["image"], data["report"],
        {**codes, LOCK: codes[UNLOCK]}), "exact selected symbol")
    refused("malformed report", lambda: verify_builder_context_availability(
        data["object"], data["image"], b"{}", codes), "raw compiler report")
    missing_root = symbol_section_mutation(data["object"],
                                           root(parse_object(data["object"]), LOCK), 0)
    refused("missing lock root", lambda: verify_builder_context_availability(
        missing_root, data["image"], data["report"], codes),
        "one offset-zero root definition")
    refused("frame/unwind mismatch", lambda: verify_builder_context_availability(
        data["object"], _unwind_mutation(data["image"], data["object"]),
        data["report"], codes), "frame/unwind")

    body = _instructions(codes[AVAILABILITY], data["image"], AVAILABILITY.lower())
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    mask = bytes.fromhex("f6c201" if optimization == "none" else "41f6c001")
    selected = [item for item in body if item.raw == mask]
    assert len(selected) == 1
    paired = paired_instruction(data["object"], data["image"], AVAILABILITY,
                                selected[0], mask[:-1] + b"\x00")
    paired_codes = _changed_codes(build, objdump, paired[1])
    refused("closing mask removed", lambda: verify_builder_context_availability(
        paired[0], paired[1], data["report"], paired_codes), "closing status")
    _paired_finalizer_case(build, paths, *paired, "closing mask removed")

    calls = [item for item in body if item.opcode in ("call", "callq")]
    assert len(calls) == 2
    for item, replacement, label in ((calls[0], UNLOCK, "lock retargeted to unlock"),
                                     (calls[1], LOCK, "unlock retargeted to lock")):
        changed = _paired_call_target(data["object"], data["image"], item, replacement)
        changed_codes = _changed_codes(build, objdump, changed[1])
        refused(label, lambda changed=changed: verify_builder_context_availability(
            changed[0], changed[1], data["report"], changed_codes),
            "call does not reach exact")
        if item is calls[0]:
            _paired_finalizer_case(build, paths, *changed, label)

    closed = bytes.fromhex("b908000000" if optimization == "none" else "ba08000000")
    status = [item for item in body if item.raw == closed]
    assert len(status) == 1
    changed = paired_instruction(data["object"], data["image"], AVAILABILITY,
                                 status[0], closed[:1] + b"\x09" + closed[2:])
    changed_codes = _changed_codes(build, objdump, changed[1])
    refused("closed status changed", lambda: verify_builder_context_availability(
        changed[0], changed[1], data["report"], changed_codes), "closing status")
    print(f"context availability: actual {optimization} PE/COFF and focused negatives passed")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
