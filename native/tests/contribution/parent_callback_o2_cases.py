"""Exercise the explicit optimized parent callback lowering on linked artifacts."""

import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from coff_layout import parse_object  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from function_inventory import create as create_inventory  # noqa: E402
from function_subject import function_subject  # noqa: E402
from parent_callback_cases import cache, outer_finalizer, post_finalize  # noqa: E402
from parent_callback_image import (  # noqa: E402
    DISPATCH, INITIALIZE, O2_ASSIGNMENT, O2_ENTRY_PREFIX,
    verify_parent_callback,
)
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402


DISPATCH_POST = ("_ZN12pyobfuscator6native4demo13dispatch_post"
                 "ERKNS0_23BootstrapContextRequestERNS1_14RuntimeContextE")


def file_offset(image, rva, size):
    section = rva_section(image, rva, size, logical=True)
    return section.raw_offset + rva - section.rva


def session_section(object_bytes, image_bytes):
    obj, image = parse_object(object_bytes), parse_image(image_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    subject = function_subject(object_bytes, image_bytes, image, 0xcafe, INITIALIZE)
    assert len(subject.ranges) == 1 and section.size == subject.ranges[0].size
    return obj, image, section, subject.ranges[0]


def changed_callback(object_bytes, raw_bytes, final_bytes):
    obj, image, section, session = session_section(object_bytes, final_bytes)
    original = object_bytes[section.offset:section.offset + section.size]
    matches = list(O2_ASSIGNMENT.finditer(original))
    assert len(matches) == 1
    callback_field = matches[0].start("callback")
    relocations = [(index, entry) for index, entry in enumerate(section.relocations)
                   if entry.offset == callback_field]
    assert len(relocations) == 1 and relocations[0][1].kind == 4
    old = [symbol for symbol in obj.symbols if symbol.index == relocations[0][1].target]
    new = [symbol for symbol in obj.symbols if symbol.name == DISPATCH_POST and
           symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    linked = [symbol for symbol in image_symbols(final_bytes, image)
              if symbol.name == DISPATCH_POST and symbol.type == 0x20 and symbol.section > 0]
    assert len(old) == len(new) == len(linked) == 1 and old[0].name == DISPATCH
    target = image.layout.sections[linked[0].section - 1].rva + linked[0].value
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    section_header = 20 + (section.index - 1) * 40
    relocation_offset = struct.unpack_from("<I", object_bytes, section_header + 24)[0]
    struct.pack_into("<I", changed_object,
                     relocation_offset + relocations[0][0] * 10 + 4, new[0].index)
    field_rva = session.rva + callback_field
    offset = file_offset(image, field_rva, 4)
    assert raw_bytes[offset:offset + 4] == read_rva(final_bytes, image, field_rva, 4)
    struct.pack_into("<i", changed_raw, offset, target - field_rva - 4)
    return bytes(changed_object), bytes(changed_raw)


def changed_entry(object_bytes, raw_bytes, final_bytes):
    _, image, section, session = session_section(object_bytes, final_bytes)
    assert object_bytes[section.offset:section.offset + 7] == O2_ENTRY_PREFIX[:7]
    offset = file_offset(image, session.rva, 7)
    assert raw_bytes[offset:offset + 7] == O2_ENTRY_PREFIX[:7]
    replacement = b"\xc3" + b"\x90" * 6
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    changed_object[section.offset:section.offset + 7] = replacement
    changed_raw[offset:offset + 7] = replacement
    return bytes(changed_object), bytes(changed_raw)


def changed_unwind(object_bytes, raw_bytes, final_bytes):
    _, image, _, session = session_section(object_bytes, final_bytes)
    directory, size = data_directory(image, 3)
    rows = struct.iter_unpack("<III", read_rva(final_bytes, image, directory, size))
    records = [unwind for begin, end, unwind in rows
               if begin == session.rva and end == session.rva + session.size]
    assert len(records) == 1
    allocation_rva = records[0] + 6
    offset = file_offset(image, allocation_rva, 1)
    assert raw_bytes[offset] == final_bytes[offset] == 0x19
    changed_raw = bytearray(raw_bytes)
    changed_raw[offset] = 0x1a
    return object_bytes, bytes(changed_raw)


def production_positive(build, suffix, expected):
    demo = build / "demo"
    target = "pyobf_native_demo_outer" + suffix
    with TemporaryDirectory(dir=build) as temporary:
        output = Path(temporary) / "current.final.json"
        command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                   cache(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"),
                   str(demo / f"lib{target}.dll"),
                   str(demo / f"{target}.coverage.json"),
                   "--output", str(output),
                   "--owner-object", str(demo / f"{target}.obj"),
                   "--owner-inventory", str(demo / f"{target}.obj.ownership.json"),
                   "--owner-plan", str(demo / f"{target}_unfinalized.reference-plan.private.json"),
                   "--post-release-report", str(demo / f"{target}.release.json"),
                   "--post-release-plan", str(demo / "release-plan.private.json"),
                   "--post-child-image", str(demo / "libpyobf_native_demo_inner.dll"),
                   "--post-child-final", str(demo / "payload.cff.final.json"),
                   "--post-child-raw", str(demo / "payload.cff.coverage.json"),
                   "--post-private", str(demo / "payload.binding.private.json"),
                   "--post-scoped", str(demo / "payload.scope-material.private.bin"),
                   "--post-join-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
                   "--post-join-material", str(demo / "release-material.private.json"),
                   "--parent-callback"]
        process = subprocess.run(command, capture_output=True, text=True,
                                 check=False, timeout=50)
        assert process.returncode == 0, process.stderr
        final = json.loads(output.read_text(encoding="utf-8"))
        assert final["parent_callback"] == expected


def proof(directory, suffix, objdump, build=None):
    image = directory / f"libpyobf_native_demo_outer{suffix}.dll"
    object_path = directory / f"pyobf_native_demo_outer{suffix}.obj"
    report = directory / f"pyobf_native_demo_outer{suffix}.coverage.json"
    code = subprocess.run(
        [objdump, "-d", f"--disassemble-symbols={INITIALIZE}", str(image)],
        capture_output=True, text=True, check=True, timeout=50).stdout.lower()
    result = verify_parent_callback(object_path.read_bytes(), image.read_bytes(),
                                    report.read_bytes(), code)
    assert result["lowering"] == "outer-source-o2"
    assert result["pe_unwind_allocation_verified"] is True
    if build is not None:
        production_positive(build, suffix, result)
    print(f"parent callback O2 {suffix or 'real'}: exact linked route, PE unwind"
          f"{' and production finalizer' if build is not None else ''}")


def paired_negatives(build):
    assert cache(build, "PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT") == "O2"
    directory = build / "demo"
    object_path = directory / "pyobf_native_demo_outer.obj"
    image_path = directory / "libpyobf_native_demo_outer.dll"
    report_path = directory / "pyobf_native_demo_outer.coverage.json"
    raw_path = directory / "unfinalized/libpyobf_native_demo_outer.dll"
    original_object, original_raw = object_path.read_bytes(), raw_path.read_bytes()
    original_final, raw_report = image_path.read_bytes(), report_path.read_bytes()
    source = (directory / "pyobf_native_demo_outer.cff.ll").read_bytes()
    for label, change, expected in (
            ("callback", changed_callback, "unique exact"),
            ("entry", changed_entry, "unsupported entry route"),
            ("unwind", changed_unwind, "PE unwind allocation")):
        with TemporaryDirectory(dir=build) as temporary:
            temp = Path(temporary)
            changed_object, changed_raw = change(original_object, original_raw,
                                                  original_final)
            object_file, raw_file = temp / "changed.obj", temp / "changed-raw.dll"
            inventory = temp / "changed.ownership.json"
            image, release = temp / "changed-final.dll", temp / "changed-release.json"
            object_file.write_bytes(changed_object)
            raw_file.write_bytes(changed_raw)
            inventory.write_bytes(create_inventory(changed_object, source, raw_report))
            post_finalize(build, raw_file, image, release)
            old_output = temp / "old.final.json"
            old = outer_finalizer(build, image, object_file, inventory, release,
                                  old_output, callback=False)
            assert old.returncode == 0 and old_output.exists(), f"{label}: {old.stderr}"
            new_output = temp / "new.final.json"
            new_output.write_bytes(b"stale")
            current = outer_finalizer(build, image, object_file, inventory, release,
                                      new_output, callback=True)
            assert current.returncode != 0 and not new_output.exists(), (
                f"{label}: new gate accepted={current.returncode == 0}, "
                f"output_exists={new_output.exists()}, stderr={current.stderr}")
            assert ("parent callback proof failed: parent callback:" in current.stderr and
                    expected in current.stderr and "builder receipt" not in current.stderr and
                    "POST role final join failed" not in current.stderr), current.stderr
        print(f"parent callback O2 {label}: re-finalized old-admitted, new-refused")


if __name__ == "__main__":
    assert len(sys.argv) in (3, 4)
    assert len(sys.argv) == 3 or sys.argv[3] == "--paired"
    location = Path(sys.argv[1]).resolve()
    directory = location / "demo" if (location / "demo").is_dir() else location
    for suffix in ("", "_triggered"):
        proof(directory, suffix, sys.argv[2], location if len(sys.argv) == 4 else None)
    if len(sys.argv) == 4 and sys.argv[3] == "--paired":
        paired_negatives(location)
