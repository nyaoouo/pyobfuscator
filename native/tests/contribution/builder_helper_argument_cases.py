"""Check exact mixed-helper entry arguments in actual linked child code."""

import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_local_callee_cases import cache_value, disassembly, inputs_for  # noqa: E402
from builder_subject_cases import root, symbol_section_mutation  # noqa: E402
from cff_builder_helper_arguments import verify_builder_helper_arguments  # noqa: E402
from cff_builder_local_callees import REQUIRE_BINDING  # noqa: E402
from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
from cff_joint_machine_evidence import MEASURED, OWNED, _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: altered input was accepted")


def changed_lease_source(object_bytes, image_bytes, name, optimization):
    old, new = {
        (OWNED, "none"): (0x58, 0x78),
        (MEASURED, "none"): (0x70, 0x50),
        (OWNED, "O2"): (0x38, 0x40),
        (MEASURED, "O2"): (0x38, 0x30),
    }[(name, optimization)]
    pattern = bytes((0x48, 0x8b, 0x54, 0x24, old))
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, name).section - 1]
    offsets = [offset for offset in range(section.size - len(pattern) + 1)
               if object_bytes[section.offset + offset:section.offset + offset + len(pattern)] == pattern]
    assert len(offsets) == 1, "expected one exact pre-binding RDX stack load"
    offset = offsets[0]
    assert all(not (relocation.offset < offset + len(pattern) and
                    offset < relocation.offset + (8 if relocation.kind == 1 else 4))
               for relocation in section.relocations)
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb620, name)
    assert len(subject.ranges) == 1
    span = subject.ranges[0]
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    start = pe_section.raw_offset + span.rva - pe_section.rva
    assert image_bytes[start + offset:start + offset + len(pattern)] == pattern
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    changed_object[section.offset + offset + 4] = new
    changed_image[start + offset + 4] = new
    return bytes(changed_object), bytes(changed_image)


def changed_helper_unwind(image_bytes, name, object_bytes):
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb621, name)
    assert len(subject.ranges) == 1
    begin = subject.ranges[0].rva
    directory, size = data_directory(image, 3)
    entries = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    unwind = next(item[2] for item in entries if item[0] == begin)
    section = rva_section(image, unwind, 6, logical=True)
    offset = section.raw_offset + unwind - section.rva + 5
    changed = bytearray(image_bytes)
    changed[offset] ^= 0x10
    return bytes(changed)


def changed_entry_state(object_bytes, image_bytes, name, code, replacement):
    instructions = _instructions(code, image_bytes, name)
    first_jump = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
    initializer = instructions[instructions.index(first_jump) - 1]
    assert initializer.opcode == "movl" and initializer.raw[0] == 0xc7
    assert initializer.raw[-4:] != b"\x00" * 4
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, name).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb622, name)
    assert len(subject.ranges) == 1
    span = subject.ranges[0]
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_start = pe_section.raw_offset + span.rva - pe_section.rva
    relative = initializer.address - (image.preferred_base + span.rva)
    raw_offset = section.offset + relative + len(initializer.raw) - 4
    pe_offset = pe_start + relative + len(initializer.raw) - 4
    assert object_bytes[raw_offset:raw_offset + 4] == initializer.raw[-4:]
    assert image_bytes[pe_offset:pe_offset + 4] == initializer.raw[-4:]
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    value = struct.pack("<I", replacement)
    changed_object[raw_offset:raw_offset + 4] = value
    changed_image[pe_offset:pe_offset + 4] = value
    return bytes(changed_object), bytes(changed_image)


def changed_entry_branch(object_bytes, image_bytes, name, code):
    instructions = _instructions(code, image_bytes, name)
    first = instructions[2 if instructions[0].opcode == "pushq" else 1]
    assert first.opcode == "movl" and len(first.raw) == 5
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, name).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb623, name)
    assert len(subject.ranges) == 1
    span = subject.ranges[0]
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_start = pe_section.raw_offset + span.rva - pe_section.rva
    relative = first.address - (image.preferred_base + span.rva)
    assert object_bytes[section.offset + relative:section.offset + relative + 5] == first.raw
    assert image_bytes[pe_start + relative:pe_start + relative + 5] == first.raw
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    replacement = b"\x74\x03\x90\x90\x90"
    changed_object[section.offset + relative:section.offset + relative + 5] = replacement
    changed_image[pe_start + relative:pe_start + relative + 5] = replacement
    return bytes(changed_object), bytes(changed_image)


def finalizer(build, paths, output, receipt, *, helper):
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
               "--builder-subjects", "--builder-entry-states",
               "--builder-local-callees", "--builder-local-callees-seed",
               cache_value(build, "PYOBF_NATIVE_CFF_SEED")]
    if helper:
        command.append("--builder-helper-arguments")
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)


def check(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    assert set(inputs) == set(ROLES)
    assert verify_receipt((build / "builder.fixed.json").read_bytes(), inputs)["verified"] is True
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    assert optimization in ("none", "O2")
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    helpers = {name: disassembly(objdump, paths["image"], name) for name in (OWNED, MEASURED)}
    local_proof = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())[
        "builder_local_callees"]
    proof = verify_builder_helper_arguments(inputs["object"], inputs["image"],
                                            helpers, local_proof)
    assert proof["verified"] is True and proof["observed_entry_binding_arguments_verified"] is True
    assert [item["symbol"] for item in proof["subjects"]] == [OWNED, MEASURED]
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    if "PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS:BOOL=ON" in cache:
        assert final["builder_helper_arguments"] == proof

    refused("unbound local result", lambda: verify_builder_helper_arguments(
        inputs["object"], inputs["image"], helpers,
        {**local_proof, "local_status_route_verified": False}), "local callee proof")
    obj = parse_object(inputs["object"])
    missing = symbol_section_mutation(inputs["object"], root(obj, OWNED), 0)
    refused("missing helper root", lambda: verify_builder_helper_arguments(
        missing, inputs["image"], helpers, local_proof), "one offset-zero root definition")
    refused("wrong helper header", lambda: verify_builder_helper_arguments(
        inputs["object"], inputs["image"],
        {**helpers, OWNED: helpers[MEASURED]}, local_proof), "exact selected symbol")
    changed_unwind = changed_helper_unwind(inputs["image"], OWNED, inputs["object"])
    refused("helper frame unwind mismatch", lambda: verify_builder_helper_arguments(
        inputs["object"], changed_unwind, helpers, local_proof),
        "PE unwind codes")

    for name in (OWNED, MEASURED):
        changed_object, changed_image = changed_lease_source(
            inputs["object"], inputs["image"], name, optimization)
        with TemporaryDirectory(dir=build) as directory:
            temp = Path(directory)
            changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
            changed_paths["object"].write_bytes(changed_object)
            changed_paths["image"].write_bytes(changed_image)
            changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
            receipt = temp / "changed.receipt.json"
            receipt.write_bytes(create_receipt(changed_inputs))
            assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
            old = finalizer(build, changed_paths, temp / "old.final.json", receipt, helper=False)
            output = temp / "stale.final.json"
            output.write_bytes(b"stale")
            current = finalizer(build, changed_paths, output, receipt, helper=True)
            assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
            assert current.returncode != 0 and not output.exists(), current.stderr
            assert ("builder helper-argument proof failed" in current.stderr and
                    "binding call lost entry Scope or lease identity" in current.stderr and
                    "builder receipt verification failed" not in current.stderr), current.stderr
            changed_helpers = {helper: disassembly(objdump, changed_paths["image"], helper)
                               for helper in (OWNED, MEASURED)}
            refused("paired lease-source swap", lambda: verify_builder_helper_arguments(
                changed_object, changed_image, changed_helpers, local_proof),
                "binding call lost entry Scope or lease identity")
        print(f"{optimization} {name}: old exact finalizer admits paired COFF/PE; helper gate refuses")
    changed_object, changed_image = changed_entry_state(
        inputs["object"], inputs["image"], OWNED, helpers[OWNED],
        0 if optimization == "none" else 0xffffffff)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, helper=False)
        output = temp / "stale.final.json"
        output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, output, receipt, helper=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not output.exists(), current.stderr
        assert ("builder helper-argument proof failed" in current.stderr and
                "normal entry state does not reach the binding body" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print(f"{optimization} {OWNED}: old gate admits paired entry-state retarget; helper gate refuses")
    changed_object, changed_image = changed_entry_branch(
        inputs["object"], inputs["image"], OWNED, helpers[OWNED])
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, helper=False)
        output = temp / "stale.final.json"
        output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, output, receipt, helper=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not output.exists(), current.stderr
        assert ("builder helper-argument proof failed" in current.stderr and
                "entry prefix has an earlier control transfer" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print(f"{optimization} {OWNED}: old gate admits paired early branch; helper gate refuses")
    print(f"builder helper arguments: {optimization} exact entry-to-binding routes passed")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
