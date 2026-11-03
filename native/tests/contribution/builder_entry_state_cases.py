"""Exercise frozen mixed entry states in actual linked child images."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools")]

from cff_builder_entry_states import _decoded_immediate, verify_builder_entry_states  # noqa: E402
from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
from cff_builder_subjects import verify_builder_subjects  # noqa: E402
from cff_joint_machine_evidence import Instruction, STACK, _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from payload_binding import OWNER, WRAPPER  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


OWNERS = (OWNER, WRAPPER)


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        if fragment not in str(error):
            raise AssertionError(f"{label}: unexpected refusal: {error}") from error
        return
    raise AssertionError(f"{label}: mutated input was accepted")


def cache_path(build, name):
    prefix = name + ":FILEPATH="
    matches = [line[len(prefix):] for line in (build / "CMakeCache.txt").read_text(
        encoding="utf-8").splitlines() if line.startswith(prefix)]
    assert len(matches) == 1, f"missing CMake cache path: {name}"
    return Path(matches[0])


def owner_code(objdump, image_path, owner):
    result = subprocess.run([str(objdump), "-d", f"--disassemble-symbols={owner}",
                             str(image_path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.lower()


def initializer(code, image_bytes, owner):
    instructions = _instructions(code, image_bytes, owner)
    branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq", "jae"))
    matches = [item for item in instructions if item.address < branch.address and
               item.opcode == "movl" and len(item.operands) == 2 and
               item.operands[0].startswith("$") and STACK.fullmatch(item.operands[1])]
    assert len(matches) == 1
    return matches[0]


def changed_entry(object_bytes, image_bytes, code, owner):
    image = parse_image(image_bytes)
    item = initializer(code, image_bytes, owner)
    old = _decoded_immediate(item)
    changed = old ^ 0x01000000
    old_bytes, new_bytes = struct.pack("<I", old), struct.pack("<I", changed)
    image_rva = item.address - image.preferred_base + len(item.raw) - 4
    section = rva_section(image, image_rva, 4, logical=True)
    image_offset = section.raw_offset + image_rva - section.rva
    assert image_bytes[image_offset:image_offset + 4] == old_bytes

    proof = verify_builder_subjects(object_bytes, image_bytes)
    owner_ranges = proof["subjects"][OWNERS.index(owner)]["ranges"]
    function_rva = item.address - image.preferred_base
    ranges = [span for span in owner_ranges if span["rva"] <= function_rva and
              image_rva + 4 <= span["rva"] + span["size"]]
    assert len(ranges) == 1
    obj = parse_object(object_bytes)
    symbols = [symbol for symbol in obj.symbols if symbol.name == owner and
               symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(symbols) == 1
    source = obj.sections[symbols[0].section - 1]
    span = ranges[0]
    assert source.size == span["size"]
    object_in_section = image_rva - span["rva"]
    assert not any(relocation.offset < object_in_section + 4 and
                   object_in_section < relocation.offset + (8 if relocation.kind == 1 else 4)
                   for relocation in source.relocations)
    object_offset = source.offset + object_in_section
    assert object_bytes[object_offset:object_offset + 4] == old_bytes

    changed_image, changed_object = bytearray(image_bytes), bytearray(object_bytes)
    changed_image[image_offset:image_offset + 4] = new_bytes
    changed_object[object_offset:object_offset + 4] = new_bytes
    result_image, result_object = bytes(changed_image), bytes(changed_object)
    assert verify_builder_subjects(result_object, result_image)["verified"] is True
    return result_object, result_image


def frozen_inputs(build, image_bytes, object_bytes):
    demo = build / "demo"
    paths = {"image": demo / "libpyobf_native_demo_inner.dll",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json",
             "object": demo / "payload.cff.obj"}
    fixed = json.loads((build / "builder.fixed.json").read_text(encoding="utf-8"))
    digest = fixed["inputs"]["input_ir"]
    candidates = (demo / "payload.requested.ll", demo / "payload.archive.prepared.ll")
    matches = [path for path in candidates if path.is_file() and
               hashlib.sha256(path.read_bytes()).hexdigest() == digest]
    assert len(matches) == 1
    paths["input_ir"] = matches[0]
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    assert set(inputs) == set(ROLES)
    inputs["image"] = image_bytes
    inputs["object"] = object_bytes
    return paths, inputs


def production_refusal(build, objdump, original_codes, plan_bytes,
                       object_bytes, image_bytes, owner):
    changed_object, changed_image = changed_entry(object_bytes, image_bytes,
                                                  original_codes[owner], owner)
    paths, inputs = frozen_inputs(build, changed_image, changed_object)
    with TemporaryDirectory(dir=build) as directory:
        temporary = Path(directory)
        image_path = temporary / "changed.dll"
        object_path = temporary / "changed.obj"
        receipt_path = temporary / "changed.builder.json"
        output = temporary / "stale.final.json"
        image_path.write_bytes(changed_image)
        object_path.write_bytes(changed_object)
        receipt_path.write_bytes(create_receipt(inputs))
        assert verify_receipt(receipt_path.read_bytes(), inputs)["verified"] is True
        changed_codes = original_codes.copy()
        changed_codes[owner] = owner_code(objdump, image_path, owner)
        refused("matching COFF and PE entry mutation",
                lambda: verify_builder_entry_states(changed_image, plan_bytes, changed_codes),
                "entry state differs from frozen CFG seed")
        output.write_text("stale", encoding="ascii")
        demo = build / "demo"
        command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                   str(objdump), str(image_path), str(paths["report"]),
                   "--output", str(output),
                   "--post-mixed-plan", str(paths["plan"]),
                   "--post-mixed-private", str(paths["private"]),
                   "--post-mixed-material", str(demo / "release-material.private.json"),
                   "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
                   "--builder-receipt", str(receipt_path),
                   "--builder-input-ir", str(paths["input_ir"]),
                   "--builder-object", str(object_path),
                   "--builder-subjects", "--builder-entry-states"]
        denied = subprocess.run(command, capture_output=True, text=True, check=False)
        if (denied.returncode == 0 or output.exists() or
                "builder entry-state proof failed" not in denied.stderr or
                "builder subject proof failed" in denied.stderr or
                "builder receipt verification failed" in denied.stderr):
            raise AssertionError(f"entry mutant escaped or failed early: {denied.stderr}")


def check(build):
    demo = build / "demo"
    image_path = demo / "libpyobf_native_demo_inner.dll"
    image_bytes = image_path.read_bytes()
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    plan_bytes = (demo / "payload.post-mixed.edges.json").read_bytes()
    objdump = cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {owner: owner_code(objdump, image_path, owner) for owner in OWNERS}
    proof = verify_builder_entry_states(image_bytes, plan_bytes, codes)
    final = json.loads((demo / "payload.cff.final.json").read_text(encoding="utf-8"))
    assert proof == final["builder_entry_states"]
    assert final["builder_subjects"]["verified"] is True
    assert final["builder_consistency"]["verified"] is True
    assert proof["verified"] is True and [row["owner"] for row in proof["owners"]] == list(OWNERS)
    assert all(row["expected"] == row["observed"] for row in proof["owners"])

    changed_plan = copy.deepcopy(json.loads(plan_bytes))
    cfg = [item for item in changed_plan["owners"][0]["recipe"]["components"]
           if item["component"] == "cfg"]
    assert len(cfg) == 1
    cfg[0]["seed"] ^= 1
    refused("changed CFG seed", lambda: verify_builder_entry_states(
        image_bytes, json.dumps(changed_plan).encode("utf-8"), codes),
        "entry state differs from frozen CFG seed")
    item = initializer(codes[OWNER], image_bytes, OWNER)
    refused("non-C7 entry encoding", lambda: _decoded_immediate(Instruction(
        item.address, b"\x90" + item.raw[1:], item.opcode, item.operands)),
        "unsupported C7 /0 stack encoding")
    refused("displayed entry mismatch", lambda: _decoded_immediate(Instruction(
        item.address, item.raw, item.opcode, ("$0", item.operands[1]))),
        "immediate differs from PE bytes")
    for owner in OWNERS:
        production_refusal(build, objdump, codes, plan_bytes, object_bytes, image_bytes, owner)
    print("builder entry states: two PE values match frozen CFG seeds; C7, seed and two receipt-matched COFF/PE mutations refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    check(parser.parse_args().build)


if __name__ == "__main__":
    main()
