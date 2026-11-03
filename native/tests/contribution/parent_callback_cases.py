"""Exercise the outer callback gate on actual paired COFF and PE artifacts."""

import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "demo")]

from coff_layout import parse_object  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from function_subject import function_subject  # noqa: E402
from function_inventory import create as create_inventory  # noqa: E402
from parent_callback_image import (  # noqa: E402
    ASSIGNMENT, DISPATCH, DISPATCH_ROOT, ENTRY_BODY, ENTRY_PREFIX, INITIALIZE,
    PROTECTION_FAILURE, _call_successors, verify_parent_callback,
)
from pe_layout import parse_image, read_rva, rva_section  # noqa: E402


DISPATCH_POST = ("_ZN12pyobfuscator6native4demo13dispatch_post"
                 "ERKNS0_23BootstrapContextRequestERNS1_14RuntimeContextE")


def cache(build, key):
    entries = [line.split("=", 1)[1] for line in (build / "CMakeCache.txt").read_text(
        encoding="utf-8").splitlines() if line.startswith(key + ":")]
    assert len(entries) == 1, f"missing or repeated cache value: {key}"
    return entries[0]


def check_run(command, label):
    process = subprocess.run(command, capture_output=True, text=True,
                             check=False, timeout=50)
    assert process.returncode == 0, f"{label}: {process.stderr}"
    return process


def disassembly(build, image):
    return check_run([cache(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"), "-d",
                      f"--disassemble-symbols={INITIALIZE}", str(image)],
                     "exact session disassembly").stdout.lower()


def changed_callback(object_bytes, raw_bytes, final_bytes):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    section_root = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
                    symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(section_root) == 1
    section = obj.sections[section_root[0].section - 1]
    session = function_subject(object_bytes, final_bytes, image, 0xcafe, INITIALIZE)
    assert len(session.ranges) == 1
    session_rva = session.ranges[0].rva
    matches = list(ASSIGNMENT.finditer(object_bytes[section.offset:section.offset + section.size]))
    assert len(matches) == 1
    callback_field = matches[0].start("callback")
    relocations = [(index, entry) for index, entry in enumerate(section.relocations)
                   if entry.offset == callback_field]
    assert len(relocations) == 1 and relocations[0][1].kind == 4
    old = [symbol for symbol in obj.symbols if symbol.index == relocations[0][1].target]
    assert len(old) == 1 and old[0].name == DISPATCH
    new = [symbol for symbol in obj.symbols if symbol.name == DISPATCH_POST and
           symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(new) == 1
    linked = [symbol for symbol in image_symbols(final_bytes, image)
              if symbol.name == DISPATCH_POST and symbol.type == 0x20 and symbol.section > 0]
    assert len(linked) == 1
    target = image.layout.sections[linked[0].section - 1].rva + linked[0].value
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    section_header = 20 + (section.index - 1) * 40
    relocations_offset = struct.unpack_from("<I", object_bytes, section_header + 24)[0]
    struct.pack_into("<I", changed_object,
                     relocations_offset + relocations[0][0] * 10 + 4, new[0].index)
    field_rva = session_rva + callback_field
    pe_section = rva_section(image, field_rva, 4, logical=True)
    file_offset = pe_section.raw_offset + field_rva - pe_section.rva
    assert raw_bytes[file_offset:file_offset + 4] == read_rva(final_bytes, image, field_rva, 4)
    struct.pack_into("<i", changed_raw, file_offset, target - (field_rva + 4))
    return bytes(changed_object), bytes(changed_raw)


def changed_entry_return(object_bytes, raw_bytes, final_bytes):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    session = function_subject(object_bytes, final_bytes, image, 0xcaff, INITIALIZE)
    assert len(session.ranges) == 1
    entry = session.ranges[0].rva
    pe_section = rva_section(image, entry, 7, logical=True)
    file_offset = pe_section.raw_offset + entry - pe_section.rva
    prologue = bytes.fromhex("4881ec38010000")
    assert object_bytes[section.offset:section.offset + 7] == prologue
    assert raw_bytes[file_offset:file_offset + 7] == prologue
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    replacement = b"\xc3" + b"\x90" * 6
    changed_object[section.offset:section.offset + 7] = replacement
    changed_raw[file_offset:file_offset + 7] = replacement
    return bytes(changed_object), bytes(changed_raw)


def changed_entry_skip(object_bytes, raw_bytes, final_bytes):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    session = function_subject(object_bytes, final_bytes, image, 0xcb00, INITIALIZE)
    assert len(session.ranges) == 1
    entry = session.ranges[0].rva
    original = object_bytes[section.offset:section.offset + section.size]
    assert original[:12] == bytes.fromhex("4881ec380100004c89442440")
    epilogue = bytes.fromhex("4881c438010000c3")
    targets = [offset for offset in range(section.size - len(epilogue) + 1)
               if original[offset:offset + len(epilogue)] == epilogue]
    assert len(targets) == 1, "expected one exact normal-return epilogue"
    source_offset = 7
    target_offset = targets[0]
    replacement = b"\xe9" + struct.pack("<i", target_offset - (source_offset + 5))
    pe_section = rva_section(image, entry + source_offset, 5, logical=True)
    file_offset = pe_section.raw_offset + entry + source_offset - pe_section.rva
    assert raw_bytes[file_offset:file_offset + 5] == original[source_offset:source_offset + 5]
    assert read_rva(final_bytes, image, entry + target_offset, len(epilogue)) == epilogue
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    changed_object[section.offset + source_offset:section.offset + source_offset + 5] = replacement
    changed_raw[file_offset:file_offset + 5] = replacement
    return bytes(changed_object), bytes(changed_raw)


def changed_dispatch_pivot(object_bytes, raw_bytes, final_bytes):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    session = function_subject(object_bytes, final_bytes, image, 0xcb01, INITIALIZE)
    assert len(session.ranges) == 1
    entry = session.ranges[0].rva
    original = object_bytes[section.offset:section.offset + section.size]
    assert original.startswith(ENTRY_PREFIX)
    state = struct.unpack_from("<I", original, len(ENTRY_PREFIX))[0]
    roots = [offset for offset in range(section.size - len(DISPATCH_ROOT) + 1)
             if original[offset:offset + len(DISPATCH_ROOT)] == DISPATCH_ROOT]
    assert len(roots) == 1
    pivot_offset = roots[0] + len(DISPATCH_ROOT)
    pivot = struct.unpack_from("<I", original, pivot_offset)[0]
    changed = state if state < pivot else state + 1
    assert (state >= pivot) != (state >= changed)
    assert all(not (relocation.offset < pivot_offset + 4 and
                    pivot_offset < relocation.offset + 4)
               for relocation in section.relocations)
    pe_section = rva_section(image, entry + pivot_offset, 4, logical=True)
    file_offset = pe_section.raw_offset + entry + pivot_offset - pe_section.rva
    assert raw_bytes[file_offset:file_offset + 4] == original[pivot_offset:pivot_offset + 4]
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    struct.pack_into("<I", changed_object, section.offset + pivot_offset, changed)
    struct.pack_into("<I", changed_raw, file_offset, changed)
    return bytes(changed_object), bytes(changed_raw)


def changed_entry_trap(object_bytes, raw_bytes, final_bytes, trap=b"\xcc"):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == INITIALIZE and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    session = function_subject(object_bytes, final_bytes, image, 0xcb02, INITIALIZE)
    assert len(session.ranges) == 1
    entry = session.ranges[0].rva
    original = object_bytes[section.offset:section.offset + section.size]
    bodies = [offset for offset in range(section.size - len(ENTRY_BODY) + 1)
              if original[offset:offset + len(ENTRY_BODY)] == ENTRY_BODY]
    assert len(bodies) == 1
    source_offset = bodies[0] + len(ENTRY_BODY)
    expected = bytes.fromhex("8b842434010000")
    assert original[source_offset:source_offset + len(expected)] == expected
    assert all(not (relocation.offset < source_offset + len(expected) and
                    source_offset < relocation.offset + 4)
               for relocation in section.relocations)
    pe_section = rva_section(image, entry + source_offset, len(expected), logical=True)
    file_offset = pe_section.raw_offset + entry + source_offset - pe_section.rva
    assert raw_bytes[file_offset:file_offset + len(expected)] == expected
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    replacement = trap + b"\x90" * (len(expected) - len(trap))
    changed_object[section.offset + source_offset:section.offset + source_offset + len(expected)] = replacement
    changed_raw[file_offset:file_offset + len(expected)] = replacement
    return bytes(changed_object), bytes(changed_raw)


def changed_entry_ud2(object_bytes, raw_bytes, final_bytes):
    return changed_entry_trap(object_bytes, raw_bytes, final_bytes,
                              b"\x0f\x0b")


def post_finalize(build, raw, image, report):
    demo = build / "demo"
    role = "pyobf_native_demo_outer_unfinalized"
    command = [sys.executable, str(ROOT / "tools" / "finalize_post_release.py"),
               str(raw), str(demo / (role + ".reference-plan.private.json")),
               str(demo / "release-material.private.json"),
               str(demo / "release-key.record"), str(image),
               "--role", role,
               "--private", str(demo / "payload.binding.private.json"),
               "--scoped", str(demo / "payload.scope-material.private.bin"),
               "--child", str(demo / "libpyobf_native_demo_inner.dll"),
               "--child-report", str(demo / "payload.cff.final.json"),
               "--release-plan", str(demo / "release-plan.private.json"),
               "--report", str(report),
               "--mixed-plan", str(demo / "payload.post-mixed.edges.json")]
    if cache(build, "PYOBF_NATIVE_DEMO_PRE_CODE_HASH") == "ON":
        command.append("--pre-release")
    subjects = cache(build, "PYOBF_NATIVE_DEMO_POST_SUBJECTS")
    if subjects:
        command.extend(("--subjects", subjects))
    check_run(command, "re-finalized paired parent")


def outer_finalizer(build, image, object_path, inventory, release_report, output, *, callback):
    demo = build / "demo"
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               cache(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"),
               str(image), str(demo / "pyobf_native_demo_outer.coverage.json"),
               "--output", str(output),
               "--owner-object", str(object_path),
               "--owner-inventory", str(inventory),
               "--owner-plan", str(demo / "pyobf_native_demo_outer_unfinalized.reference-plan.private.json"),
               "--post-release-report", str(release_report),
               "--post-release-plan", str(demo / "release-plan.private.json"),
               "--post-child-image", str(demo / "libpyobf_native_demo_inner.dll"),
               "--post-child-final", str(demo / "payload.cff.final.json"),
               "--post-child-raw", str(demo / "payload.cff.coverage.json"),
               "--post-private", str(demo / "payload.binding.private.json"),
               "--post-scoped", str(demo / "payload.scope-material.private.bin"),
               "--post-join-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
               "--post-join-material", str(demo / "release-material.private.json")]
    if callback:
        command.append("--parent-callback")
    return subprocess.run(command, capture_output=True, text=True,
                          check=False, timeout=50)


def main(build):
    demo = build / "demo"
    object_path = demo / "pyobf_native_demo_outer.obj"
    image_path = demo / "libpyobf_native_demo_outer.dll"
    report_path = demo / "pyobf_native_demo_outer.coverage.json"
    final_path = demo / "pyobf_native_demo_outer.final.json"
    proof = verify_parent_callback(object_path.read_bytes(), image_path.read_bytes(),
                                   report_path.read_bytes(), disassembly(build, image_path))
    final = json.loads(final_path.read_text(encoding="utf-8"))
    assert final["parent_callback"] == proof and final["post_role_join"][
        "parent_image_sha256"] == final["image_sha256"]
    # A noreturn call has no synthetic fallthrough edge, even when the next
    # instruction is valid code in the linked function.
    call = (0, b"\xe8\x00\x00\x00\x00", "callq",
            (f"0x10 <{PROTECTION_FAILURE}>",))
    assert _call_successors(call, call[0] + len(call[1])) == (0x10, ())
    try:
        _call_successors((call[0], call[1], call[2],
                          ("0x10 <unknown_function>",)),
                         call[0] + len(call[1]))
    except ValueError as error:
        assert "no admitted return behavior" in str(error)
    else:
        assert False, "unknown call target was treated as returning"
    for label, change, expected in (
            ("callback substitution", changed_callback, "unique exact"),
            ("entry return", changed_entry_return, "unsupported entry route"),
            ("entry skip", changed_entry_skip, "unsupported entry route"),
            ("dispatcher pivot", changed_dispatch_pivot, "unique entry body"),
            ("entry trap", changed_entry_trap, "initial body has no CFG route"),
            ("entry ud2", changed_entry_ud2, "initial body has no CFG route")):
        with TemporaryDirectory(dir=build) as directory:
            temp = Path(directory)
            changed_obj, changed_raw = change(
                object_path.read_bytes(),
                (demo / "unfinalized/libpyobf_native_demo_outer.dll").read_bytes(),
                image_path.read_bytes())
            changed_object = temp / "changed.obj"
            changed_inventory = temp / "changed.ownership.json"
            changed_unfinalized = temp / "changed-unfinalized.dll"
            changed_image = temp / "changed-final.dll"
            changed_release = temp / "changed-release.json"
            changed_object.write_bytes(changed_obj)
            changed_inventory.write_bytes(create_inventory(
                changed_obj,
                (demo / "pyobf_native_demo_outer.cff.ll").read_bytes(),
                report_path.read_bytes()))
            changed_unfinalized.write_bytes(changed_raw)
            post_finalize(build, changed_unfinalized, changed_image, changed_release)
            old_output = temp / "old.final.json"
            old = outer_finalizer(build, changed_image, changed_object, changed_inventory,
                                  changed_release, old_output, callback=False)
            assert old.returncode == 0 and old_output.exists(), f"{label}: {old.stderr}"
            new_output = temp / "new.final.json"
            new_output.write_bytes(b"stale")
            current = outer_finalizer(build, changed_image, changed_object, changed_inventory,
                                      changed_release, new_output, callback=True)
            assert current.returncode != 0 and not new_output.exists(), (
                f"{label}: new gate accepted={current.returncode == 0}, "
                f"output_exists={new_output.exists()}, stderr={current.stderr}")
            assert ("parent callback proof failed: parent callback:" in current.stderr and
                    expected in current.stderr and "builder receipt" not in current.stderr and
                    "POST role final join failed" not in current.stderr), current.stderr
        print(f"parent callback {label}: re-finalized paired COFF/PE old-admitted, new-refused")


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve())
