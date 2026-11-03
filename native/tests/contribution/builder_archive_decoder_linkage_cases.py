"""Actual O2 archive decoder linkage and paired COFF/PE refusal cases."""

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

from builder_archive_publication_cases import (_bytes, _paired_field, refused)  # noqa: E402
from builder_entry_state_cases import owner_code  # noqa: E402
from cff_archive_origin_contract import ROLES as ARCHIVE_ROLES  # noqa: E402
from cff_builder_archive_decoder_linkage import (  # noqa: E402
    ARCHIVE_DECODER_CALLEES, ACQUIRE, PARSE, REQUIRE,
    verify_builder_archive_decoder_linkage)
from cff_builder_archive_publication import verify_builder_archive_publication  # noqa: E402
from cff_joint_machine_evidence import DIRECT, _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from coff_relocations import Resolver  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402

SPIN = "_ZN12pyobfuscator6native8platform10spin_pauseEv"


def _paired_call(object_bytes, image_bytes, item, replacement, *, caller_name=REQUIRE,
                 addend=0):
    obj, image = parse_object(object_bytes), parse_image(image_bytes)
    caller = next(row for row in obj.symbols if row.name == caller_name and
                  row.type == 0x20 and row.section > 0 and row.value == 0)
    target = next(row for row in obj.symbols if row.name == replacement and
                  row.type == 0x20 and row.section > 0 and row.value == 0)
    span = function_subject(object_bytes, image_bytes, image, 0xbe81, caller_name).ranges[0]
    section = obj.sections[caller.section - 1]
    offset = item.address - image.preferred_base - span.rva
    matches = [(index, row) for index, row in enumerate(section.relocations)
               if row.offset == offset + 1]
    assert len(matches) == 1 and matches[0][1].kind == 4
    assert object_bytes[section.offset + offset:section.offset + offset + 5] == b"\xe8\0\0\0\0"
    table = struct.unpack_from("<I", object_bytes,
                               20 + (section.index - 1) * 40 + 24)[0]
    altered_object = bytearray(object_bytes)
    struct.pack_into("<I", altered_object, table + matches[0][0] * 10 + 4, target.index)
    struct.pack_into("<i", altered_object, section.offset + offset + 1, addend)
    target_rva = Resolver(obj, image, image_symbols(image_bytes, image)).named(replacement)
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_offset = pe_section.raw_offset + span.rva - pe_section.rva + offset
    assert image_bytes[pe_offset:pe_offset + 5] == item.raw
    altered_image = bytearray(image_bytes)
    struct.pack_into("<i", altered_image, pe_offset + 1,
                     image.preferred_base + target_rva + addend - (item.address + 5))
    return bytes(altered_object), bytes(altered_image)


def _codes(objdump, image_path):
    return {name: owner_code(objdump, image_path, name)
            for name in ARCHIVE_DECODER_CALLEES}


def _changed_codes(objdump, scratch, image_bytes):
    image_path = scratch / "changed.dll"
    image_path.write_bytes(image_bytes)
    return _codes(objdump, image_path)


def _unwind_change(image_bytes, object_bytes):
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xbe82, REQUIRE).ranges[0]
    directory, size = data_directory(image, 3)
    rows = struct.iter_unpack("<III", read_rva(image_bytes, image, directory, size))
    matches = [unwind for begin, _, unwind in rows if begin == span.rva]
    assert len(matches) == 1
    section = rva_section(image, matches[0], 6, logical=True)
    offset = section.raw_offset + matches[0] - section.rva + 5
    altered = bytearray(image_bytes)
    altered[offset] ^= 0x10
    return bytes(altered)


def _stale_finalizer(build, objdump, object_bytes):
    # The fixed builder replay rejects changed bytes before the optional
    # decoder check. This checks the finalizer output lifecycle, separately
    # from the direct decoder semantic refusal below.
    demo = build / "demo"
    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        object_path = scratch / "changed.obj"
        output = scratch / "stale.json"
        object_path.write_bytes(object_bytes)
        output.write_bytes(b"stale")
        command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                   str(objdump), str(demo / "libpyobf_native_demo_inner.dll"),
                   str(demo / "payload.cff.coverage.json"), "--output", str(output),
                   "--post-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
                   "--post-mixed-private", str(demo / "payload.binding.private.json"),
                   "--post-mixed-material", str(demo / "release-material.private.json"),
                   "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
                   "--builder-receipt", str(build / "builder.fixed.json"),
                   "--builder-input-ir", str(demo / "payload.archive.prepared.ll"),
                   "--builder-object", str(object_path),
                   "--builder-subjects", "--builder-entry-states",
                   "--builder-archive-publication", "--builder-archive-decoder-linkage"]
        origin = json.loads((build / "archive.origin.json").read_bytes())
        child = json.loads((build / "builder.replay.json").read_bytes())
        command += ["--builder-replay-record", str(build / "builder.replay.json"),
                    "--builder-transformed-ir", str(demo / "payload.cff.ll"),
                    "--builder-request-manifest", str(demo / "payload.archive.requests.json"),
                    "--builder-recipe", str(demo / "payload.binding.recipe.json"),
                    "--builder-opt-exe", child["paths"]["opt_exe"],
                    "--builder-clang-exe", child["paths"]["clang_exe"],
                    "--builder-pass-plugin", child["paths"]["pass_plugin"],
                    "--archive-origin-record", str(build / "archive.origin.json")]
        command += ["--archive-origin-role=" + role + "=" + origin["paths"][role]
                    for role in ARCHIVE_ROLES]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=90)
        assert result.returncode != 0 and not output.exists(), result.stderr
        assert "builder receipt verification failed:" in result.stderr, result.stderr


def check(build):
    demo, record, _, roles, _, objdump, owner_codes, wrappers = _bytes(build)
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_path = demo / "libpyobf_native_demo_inner.dll"
    image_bytes = image_path.read_bytes()
    report_bytes = (demo / "payload.cff.coverage.json").read_bytes()
    edge_bytes = (demo / "payload.post-mixed.edges.json").read_bytes()
    codes = _codes(objdump, image_path)

    def prove(obj=object_bytes, image=image_bytes, disassembly=codes):
        return verify_builder_archive_decoder_linkage(obj, image, report_bytes,
                                                      disassembly)

    proof = prove()
    assert all(proof[key] is True for key in (
        "verified", "decoder_linkage_verified", "require_to_acquire_verified",
        "acquire_to_children_verified", "argument_chain_verified"))
    assert all(proof[key] is False for key in (
        "decoder_effect_verified", "cache_effect_verified", "platform_crypto_verified",
        "acquire_inter_state_reachability_verified"))
    assert proof["object_sha256"] == hashlib.sha256(object_bytes).hexdigest()
    assert proof["image_sha256"] == hashlib.sha256(image_bytes).hexdigest()
    assert proof["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
    final = json.loads((demo / "payload.cff.final.json").read_bytes())
    assert final["builder_archive_decoder_linkage"] == proof

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        items = _instructions(codes[REQUIRE], image_bytes, REQUIRE.lower())
        call = next(item for item in items if item.opcode in ("call", "callq") and
                    item.operands and ACQUIRE.lower() in item.operands[0])
        redirected_object, redirected_image = _paired_call(
            object_bytes, image_bytes, call, SPIN)
        redirected_codes = _changed_codes(objdump, scratch, redirected_image)
        predecessor = verify_builder_archive_publication(
            redirected_object, redirected_image, report_bytes, edge_bytes,
            record, roles, owner_codes, wrappers)
        assert predecessor["verified"] is True
        refused("paired require call retarget", lambda: prove(
            redirected_object, redirected_image, redirected_codes),
            "missing unique linked call")

        argument = next(item for item in items if item.operands ==
                        ("0x68(%rsp)", "%rcx"))
        wrong_object, wrong_image = _paired_field(
            object_bytes, image_bytes, REQUIRE, argument, 4, b"\x60")
        wrong_codes = _changed_codes(objdump, scratch, wrong_image)
        refused("paired wrong argument", lambda: prove(
            wrong_object, wrong_image, wrong_codes), "argument route")

        # The dispatcher leaf entering the call window is the last direct
        # jump to that window; alter it to land at the success epilogue.
        leaves = [item for item in items if item.opcode in ("jmp", "jmpq") and
                  DIRECT.fullmatch(item.operands[0]) and
                  int(DIRECT.fullmatch(item.operands[0])[1], 16) == items[13].address]
        assert len(leaves) == 1
        epilogue = next(item for item in items if item.opcode == "addq" and
                        item.operands == ("$0xb8", "%rsp"))
        leaf = leaves[0]
        replacement = b"\xe9" + struct.pack("<i", epilogue.address - (leaf.address + 5))
        bypass_object, bypass_image = _paired_field(
            object_bytes, image_bytes, REQUIRE, leaf, 0, replacement)
        bypass_codes = _changed_codes(objdump, scratch, bypass_image)
        refused("paired dispatcher bypass", lambda: prove(
            bypass_object, bypass_image, bypass_codes), "bypasses acquire call")

        acquire_items = _instructions(codes[ACQUIRE], image_bytes, ACQUIRE.lower())
        parse_call = next(item for item in acquire_items if item.opcode in ("call", "callq")
                          and item.operands and PARSE.lower() in item.operands[0])
        parse_result = acquire_items[acquire_items.index(parse_call) + 1]
        assert parse_result.raw == b"\x41\x89\xc0"
        stack_object, stack_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, parse_result, 0, b"\x40\x89\xc4")
        stack_codes = _changed_codes(objdump, scratch, stack_image)
        refused("paired parse result writes ESP", lambda: prove(
            stack_object, stack_image, stack_codes),
            "changes RSP outside its prologue/epilogue")
        before = acquire_items.index(parse_call) - 1
        while acquire_items[before].opcode not in ("jmp", "jmpq", "jae", "ret", "retq"):
            before -= 1
        parse_entry = acquire_items[before + 1].address
        parse_leaves = [item for item in acquire_items
                        if item.opcode in ("jmp", "jmpq") and
                        (target := DIRECT.fullmatch(item.operands[0])) and
                        int(target[1], 16) == parse_entry]
        assert len(parse_leaves) == 1 and parse_leaves[0].raw[:1] == b"\xe9"
        parse_leaf = parse_leaves[0]
        after_call = parse_call.address + len(parse_call.raw)
        altered_branch = b"\xe9" + struct.pack("<i", after_call - (parse_leaf.address + 5))
        skip_object, skip_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, parse_leaf, 0, altered_branch)
        skip_codes = _changed_codes(objdump, scratch, skip_image)
        refused("paired jump after parse call", lambda: prove(
            skip_object, skip_image, skip_codes), "bypasses a selected call window")

        epilogue = next(item for item in acquire_items if item.opcode == "addq" and
                        item.operands == ("$0xc0", "%rsp"))
        broken_object, broken_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, epilogue, 3, b"\0\0\0\0")
        broken_codes = _changed_codes(objdump, scratch, broken_image)
        refused("paired acquire stack-restore deletion", lambda: prove(
            broken_object, broken_image, broken_codes),
            "return does not restore its Win64 frame")

        return_leaf = next(item for item in acquire_items
                           if item.address == 0x18001c818)
        assert return_leaf.raw[:1] == b"\xe9" and len(return_leaf.raw) == 5
        restore_pop = next(item for item in acquire_items if item.opcode == "popq" and
                           item.operands == ("%rsi",))
        for label, target, reason in (
            ("paired return jumps after stack restore", restore_pop.address,
             "CFG bypasses its complete return frame restoration"),
            ("paired dispatcher re-enters prologue", acquire_items[0].address,
             "CFG re-enters its frame prologue"),
        ):
            branch = b"\xe9" + struct.pack("<i", target - (return_leaf.address + 5))
            branch_object, branch_image = _paired_field(
                object_bytes, image_bytes, ACQUIRE, return_leaf, 0, branch)
            branch_codes = _changed_codes(objdump, scratch, branch_image)
            refused(label, lambda obj=branch_object, image=branch_image, disassembly=branch_codes:
                    prove(obj, image, disassembly), reason)

        alias_sources = [(index, item) for index, item in enumerate(acquire_items[:-1])
                         if item.operands == ("0x80(%rsp)", "%rax") and
                         acquire_items[index + 1].operands == ("%rax", "0xa8(%rsp)")]
        assert len(alias_sources) == 1
        alias_index, alias_source = alias_sources[0]
        short_write_object, short_write_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, acquire_items[alias_index + 1], 0,
            b"\x66\x89\x84\x24\x50\0\0\0")
        short_write_codes = _changed_codes(objdump, scratch, short_write_image)
        refused("paired child-only MOVW writes captured slot", lambda: prove(
            short_write_object, short_write_image, short_write_codes),
            "unsupported route instruction")
        alias_object, alias_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, alias_source, 0,
            b"\x48\x8d\x84\x24\0\0\0\0")
        alias_object, alias_image = _paired_field(
            alias_object, alias_image, ACQUIRE, acquire_items[alias_index + 1], 0,
            b"\x48\x89\x84\x20\x50\0\0\0")
        alias_codes = _changed_codes(objdump, scratch, alias_image)
        refused("paired frame-derived alias write", lambda: prove(
            alias_object, alias_image, alias_codes),
            "unmodeled indexed route operand")
        direct_alias_object, direct_alias_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, alias_source, 0,
            b"\x48\x8d\x84\x24\0\0\0\0")
        direct_alias_object, direct_alias_image = _paired_field(
            direct_alias_object, direct_alias_image, ACQUIRE,
            acquire_items[alias_index + 1], 0,
            b"\x66\x48\x89\x80\x50\0\0\0")
        direct_alias_codes = _changed_codes(objdump, scratch, direct_alias_image)
        refused("paired direct frame-derived alias write", lambda: prove(
            direct_alias_object, direct_alias_image, direct_alias_codes),
            "frame-derived pointer overwrites a captured Win64 argument")
        arithmetic_object, arithmetic_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, alias_source, 0,
            b"\x48\x8d\x84\x24\0\0\0\0")
        arithmetic_object, arithmetic_image = _paired_field(
            arithmetic_object, arithmetic_image, ACQUIRE,
            acquire_items[alias_index + 1], 0,
            b"\x66\x48\x81\xc0\x50\0\0\0")
        arithmetic_codes = _changed_codes(objdump, scratch, arithmetic_image)
        refused("paired frame-derived pointer arithmetic", lambda: prove(
            arithmetic_object, arithmetic_image, arithmetic_codes),
            "mutates an unmodeled frame-derived pointer")

        overlap = next(item for item in acquire_items if item.address == 0x18001c2c7)
        interior_object, interior_image = _paired_call(
            object_bytes, image_bytes, overlap, ACQUIRE, caller_name=ACQUIRE,
            addend=0xf5)
        interior_codes = _changed_codes(objdump, scratch, interior_image)
        refused("paired call into parse-call byte", lambda: prove(
            interior_object, interior_image, interior_codes),
            "unselected call enters a protected function interval")

        missing = dict(codes)
        missing.pop(ARCHIVE_DECODER_CALLEES[-1])
        refused("missing symbol", lambda: prove(disassembly=missing),
                "five-symbol disassembly")
        changed_unwind = _unwind_change(image_bytes, object_bytes)
        refused("changed unwind", lambda: prove(image=changed_unwind),
                "frame/unwind")
        refused("unsupported raw report", lambda: verify_builder_archive_decoder_linkage(
            object_bytes, image_bytes, b"{}", codes), "function rows")
        _stale_finalizer(build, objdump, wrong_object)

    print("archive decoder linkage: actual final report and paired predecessor differential pass")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
