"""Exercise exact mixed builder function subjects in a real linked child."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))
sys.path.insert(0, str(ROOT / "tools"))

from cff_builder_subjects import SUBJECTS, verify_builder_subjects  # noqa: E402
from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        if fragment not in str(error):
            raise AssertionError(f"{label}: unexpected refusal: {error}") from error
        return
    raise AssertionError(f"{label}: mutated input was accepted")


def root(obj, name):
    matches = [symbol for symbol in obj.symbols if symbol.name == name and
               symbol.type == 0x20 and symbol.section > 0]
    assert len(matches) == 1 and matches[0].value == 0, name
    return matches[0]


def symbol_section_mutation(data, symbol, section):
    changed = bytearray(data)
    table = struct.unpack_from("<I", changed, 8)[0]
    struct.pack_into("<h", changed, table + 18 * symbol.index + 12, section)
    return bytes(changed)


def object_code_mutation(data, section):
    relocated = set()
    for relocation in section.relocations:
        width = 8 if relocation.kind == 1 else 4
        relocated.update(range(relocation.offset, relocation.offset + width))
    offset = next(index for index in range(section.size) if index not in relocated)
    changed = bytearray(data)
    changed[section.offset + offset] ^= 1
    return bytes(changed)


def image_code_mutation(data, rva):
    image = parse_image(data)
    section = rva_section(image, rva, 1, logical=True)
    changed = bytearray(data)
    changed[section.raw_offset + rva - section.rva] ^= 1
    return bytes(changed)


def relocation_addend_mutation(data, section):
    assert section.relocations
    changed = bytearray(data)
    changed[section.offset + section.relocations[0].offset] ^= 1
    return bytes(changed)


def linked_alias_mutation(data, original, alias):
    image = parse_image(data)
    linked = image_symbols(data, image)
    old, new = ([symbol for symbol in linked if symbol.name == name and
                 symbol.type == 0x20 and symbol.section > 0] for name in (original, alias))
    assert len(old) == len(new) == 1
    pe = struct.unpack_from("<I", data, 60)[0]
    table = struct.unpack_from("<I", data, pe + 12)[0]
    changed = bytearray(data)
    struct.pack_into("<Ih", changed, table + 18 * new[0].index + 8,
                     old[0].value, old[0].section)
    return bytes(changed)


def unexpected_fragment_mutation(data, obj, owner, fragment):
    """Reparent a real section as an undeclared associative COFF fragment."""
    section = obj.sections[fragment.section - 1]
    definitions = [symbol for symbol in obj.symbols if symbol.section == section.index and
                   symbol.name == section.name and symbol.storage == 3 and symbol.type == 0]
    assert len(definitions) == 1 and len(definitions[0].auxiliaries) == 1
    changed = bytearray(data)
    table = struct.unpack_from("<I", changed, 8)[0]
    auxiliary = table + 18 * (definitions[0].index + 1)
    struct.pack_into("<hB", changed, auxiliary + 12, owner.section, 5)
    return bytes(changed)


def cache_path(build, name):
    prefix = name + ":FILEPATH="
    lines = (build / "CMakeCache.txt").read_text(encoding="utf-8").splitlines()
    matches = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    assert len(matches) == 1, f"missing CMake cache path: {name}"
    return Path(matches[0])


def finalizer_refuses_mutated_object(build, object_bytes):
    demo = build / "demo"
    paths = {"image": demo / "libpyobf_native_demo_inner.dll",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json",
             "object": demo / "payload.cff.obj"}
    frozen = json.loads((build / "builder.fixed.json").read_text(encoding="utf-8"))
    digest = frozen["inputs"]["input_ir"]
    ir_candidates = (demo / "payload.requested.ll", demo / "payload.archive.prepared.ll")
    matching = [path for path in ir_candidates if path.is_file() and
                hashlib.sha256(path.read_bytes()).hexdigest() == digest]
    assert len(matching) == 1, "frozen receipt must select one actual input IR"
    paths["input_ir"] = matching[0]
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    assert set(inputs) == set(ROLES)
    with TemporaryDirectory(dir=build) as directory:
        temporary = Path(directory)
        mutated_object = temporary / "mutated.obj"
        mutated_object.write_bytes(object_bytes)
        inputs["object"] = object_bytes
        receipt = temporary / "mutated.builder.json"
        receipt.write_bytes(create_receipt(inputs))
        assert verify_receipt(receipt.read_bytes(), inputs)["verified"] is True
        output = temporary / "stale.final.json"
        output.write_text("stale", encoding="ascii")
        command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                   str(cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")),
                   str(paths["image"]), str(paths["report"]), "--output", str(output),
                   "--post-mixed-plan", str(paths["plan"]),
                   "--post-mixed-private", str(paths["private"]),
                   "--post-mixed-material", str(demo / "release-material.private.json"),
                   "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
                   "--builder-receipt", str(receipt),
                   "--builder-input-ir", str(paths["input_ir"]),
                   "--builder-object", str(mutated_object), "--builder-subjects"]
        denied = subprocess.run(command, capture_output=True, text=True, check=False)
        if (denied.returncode == 0 or output.exists() or
                "builder subject proof failed" not in denied.stderr or
                "builder receipt verification failed" in denied.stderr):
            raise AssertionError(f"finalizer admitted changed COFF or rejected early: {denied.stderr}")


def check(build):
    demo = build / "demo"
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_bytes = (demo / "libpyobf_native_demo_inner.dll").read_bytes()
    report = json.loads((demo / "payload.cff.final.json").read_text(encoding="utf-8"))
    proof = verify_builder_subjects(object_bytes, image_bytes)
    assert proof == report["builder_subjects"]
    assert report["builder_consistency"]["verified"] is True
    assert proof["verified"] is True and tuple(item["symbol"] for item in proof["subjects"]) == SUBJECTS
    ranges = sorted((span["rva"], span["rva"] + span["size"])
                    for item in proof["subjects"] for span in item["ranges"])
    assert len(ranges) >= len(SUBJECTS) and all(start < end for start, end in ranges)
    assert all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:]))

    obj = parse_object(object_bytes)
    owner, wrapper = (root(obj, name) for name in SUBJECTS[:2])
    owner_section = obj.sections[owner.section - 1]
    refused("missing root", lambda: verify_builder_subjects(
        symbol_section_mutation(object_bytes, owner, 0), image_bytes),
        "one offset-zero root definition")
    refused("undeclared alias", lambda: verify_builder_subjects(
        symbol_section_mutation(object_bytes, wrapper, owner.section), image_bytes),
        "undeclared aliases or mixed function ownership")
    refused("unexpected fragment", lambda: verify_builder_subjects(
        unexpected_fragment_mutation(object_bytes, obj, owner, wrapper), image_bytes),
        "required executable fragments")
    refused("object code change", lambda: verify_builder_subjects(
        object_code_mutation(object_bytes, owner_section), image_bytes),
        "bytes disagree after exact relocation evaluation")
    refused("relocation addend change", lambda: verify_builder_subjects(
        relocation_addend_mutation(object_bytes, owner_section), image_bytes),
        "bytes disagree after exact relocation evaluation")
    refused("PE code change", lambda: verify_builder_subjects(
        object_bytes, image_code_mutation(image_bytes, proof["subjects"][0]["ranges"][0]["rva"])),
        "bytes disagree after exact relocation evaluation")
    refused("linked alias", lambda: verify_builder_subjects(
        object_bytes, linked_alias_mutation(image_bytes, SUBJECTS[0], SUBJECTS[1])),
        "folded, aliased or contains another function")
    finalizer_refuses_mutated_object(build, object_code_mutation(object_bytes, owner_section))
    print(f"builder subjects: {len(SUBJECTS)} exact linked functions; seven API mutations and a receipt-matched finalizer mutation refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    check(args.build)


if __name__ == "__main__":
    main()
