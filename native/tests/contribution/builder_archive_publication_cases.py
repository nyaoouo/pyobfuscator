"""Actual O2 archive publication and paired COFF/PE refusal cases."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from archive_origin_cases import modified  # noqa: E402
from builder_entry_state_cases import cache_path, owner_code  # noqa: E402
from builder_original_predicate_cases import paired_bytes_mutation  # noqa: E402
from builder_replay_cases import paths_for as replay_paths_for  # noqa: E402
from cff_archive_origin_contract import ROLES as ARCHIVE_ROLES  # noqa: E402
from cff_builder_archive_publication import (DECODER, PACKAGE,
    verify_builder_archive_publication)  # noqa: E402
from cff_builder_original_predicates import _dispatcher_destination, _imm  # noqa: E402
from cff_builder_receipt import (REPLAY_PROFILE, REPLAY_ROLES, ROLES as BUILDER_ROLES,
                                  create_receipt)  # noqa: E402
from cff_builder_subjects import SUBJECTS, verify_builder_subjects  # noqa: E402
from cff_joint_machine_evidence import _dispatcher_state, _graph, _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from coff_symbols import image_symbols  # noqa: E402
from function_subject import function_subject  # noqa: E402
from payload_binding import OWNER, WRAPPER  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


def refused(label, call, fragment):
    try:
        call()
    except ValueError as error:
        assert fragment in str(error), f"{label}: unexpected error: {error}"
        return
    raise AssertionError(f"{label}: mutation was admitted")


def _bytes(build):
    demo = build / "demo"
    record = (build / "archive.origin.json").read_bytes()
    role_paths = {name: Path(json.loads(record)["paths"][name]) for name in ARCHIVE_ROLES}
    roles = {name: path.read_bytes() for name, path in role_paths.items()}
    names = {index: json.loads(roles["bindings"])["records"][index]["wrapper"]
             for index in range(28, 34)}
    image_path = demo / "libpyobf_native_demo_inner.dll"
    objdump = cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {name: owner_code(objdump, image_path, name)
             for name in (OWNER, WRAPPER)}
    wrappers = {name: owner_code(objdump, image_path, name) for name in names.values()}
    return demo, record, role_paths, roles, names, objdump, codes, wrappers


def _paired_field(object_bytes, image_bytes, owner, instruction, offset, new_field):
    """Change the same instruction field in COFF and PE without a hidden linker fixup."""
    obj, image = parse_object(object_bytes), parse_image(image_bytes)
    roots = [row for row in obj.symbols if row.name == owner and row.type == 0x20 and
             row.section > 0 and row.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    root_rva = instruction.address - image.preferred_base
    # The image-symbol resolver is only needed to locate this root's final RVA.
    from coff_relocations import Resolver
    from coff_symbols import image_symbols
    resolver = Resolver(obj, image, image_symbols(image_bytes, image))
    root_rva = resolver.named(owner)
    location = instruction.address - image.preferred_base - root_rva + offset
    assert 0 <= location <= section.size - len(new_field)
    rva = instruction.address - image.preferred_base + offset
    pe_section = rva_section(image, rva, len(new_field), logical=True)
    pe_offset = pe_section.raw_offset + rva - pe_section.rva
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    changed_object[section.offset + location:section.offset + location + len(new_field)] = new_field
    changed_image[pe_offset:pe_offset + len(new_field)] = new_field
    return bytes(changed_object), bytes(changed_image)


def _paired_read_redirect(object_bytes, image_bytes, code, proof):
    image = parse_image(image_bytes)
    items = _instructions(code, image_bytes, OWNER)
    before = proof["conditions"][0]
    read = next(item for item in items if item.address - image.preferred_base == before["read_rva"])
    assert read.raw[:3] == b"\x44\x8b\x0d"
    old = int.from_bytes(read.raw[-4:], "little", signed=True)
    new = old + proof["conditions"][1]["slot_rva"] - before["slot_rva"]
    obj, pe = _paired_field(object_bytes, image_bytes, OWNER, read, len(read.raw) - 4,
                            struct.pack("<i", new))
    # A REL32 COFF field contains an addend, rather than the linked displacement.
    parsed = parse_object(object_bytes)
    roots = [row for row in parsed.symbols if row.name == OWNER and row.type == 0x20 and
             row.section > 0 and row.value == 0]
    section = parsed.sections[roots[0].section - 1]
    location = before["read_rva"] - parsed_image_root(object_bytes, image_bytes, OWNER) + len(read.raw) - 4
    relocation = [row for row in section.relocations if row.offset == location]
    assert len(relocation) == 1 and relocation[0].kind == 4
    obj = bytearray(obj)
    original = struct.unpack_from("<i", object_bytes, section.offset + location)[0]
    struct.pack_into("<i", obj, section.offset + location,
                     original + proof["conditions"][1]["slot_rva"] - before["slot_rva"])
    result = bytes(obj), pe
    assert verify_builder_subjects(*result)["verified"] is True
    return result


def _paired_rel32_shift(object_bytes, image_bytes, name, instruction, delta):
    old = int.from_bytes(instruction.raw[-4:], "little", signed=True)
    obj, pe = _paired_field(object_bytes, image_bytes, name, instruction,
                            len(instruction.raw) - 4, struct.pack("<i", old + delta))
    parsed = parse_object(object_bytes)
    roots = [row for row in parsed.symbols if row.name == name and row.type == 0x20 and
             row.section > 0 and row.value == 0]
    assert len(roots) == 1
    section = parsed.sections[roots[0].section - 1]
    location = instruction.address - parse_image(image_bytes).preferred_base - \
               parsed_image_root(object_bytes, image_bytes, name) + len(instruction.raw) - 4
    relocation = [row for row in section.relocations if row.offset == location]
    assert len(relocation) == 1 and relocation[0].kind == 4
    changed = bytearray(obj)
    addend = struct.unpack_from("<i", object_bytes, section.offset + location)[0]
    struct.pack_into("<i", changed, section.offset + location, addend + delta)
    function_subject(bytes(changed), pe, parse_image(pe), 0xb4ef, name)
    return bytes(changed), pe


def _paired_shift_outputs(object_bytes, image_bytes, owner_code, proof, target_rva):
    image = parse_image(image_bytes)
    rva_section(image, target_rva, 24, logical=True)
    items = _instructions(owner_code, image_bytes, OWNER)
    outputs = [item for item in items if item.opcode == "leaq" and
               len(item.operands) == 2 and item.operands[1] == "%rdx" and
               item.operands[0].endswith("(%rip)")]
    assert len(outputs) == 6
    first = outputs[0]
    first_rva = first.address - image.preferred_base + len(first.raw) + \
                int.from_bytes(first.raw[-4:], "little", signed=True)
    assert first_rva in {row["slot_rva"] for row in proof["conditions"]}
    delta = target_rva - first_rva
    obj, pe = object_bytes, image_bytes
    for output in outputs:
        obj, pe = _paired_rel32_shift(obj, pe, OWNER, output, delta)
    for condition in proof["conditions"]:
        read = next(item for item in items if
                    item.address - image.preferred_base == condition["read_rva"])
        obj, pe = _paired_rel32_shift(obj, pe, OWNER, read, delta)
    assert verify_builder_subjects(obj, pe)["verified"] is True
    return obj, pe


def _paired_false_decoder(object_bytes, image_bytes, names, wrappers):
    image = parse_image(image_bytes)
    acquire = [symbol for symbol in image_symbols(image_bytes, image)
               if "archive14acquire_record" in symbol.name]
    assert len(acquire) == 1
    target = image.layout.sections[acquire[0].section - 1].rva + acquire[0].value
    obj, pe = object_bytes, image_bytes
    for index in (28, 30):
        name = names[index]
        item = next(item for item in _instructions(wrappers[name], image_bytes, name)
                    if item.opcode == "callq" and "require_record" in item.operands[0])
        displacement = target + image.preferred_base - item.address - len(item.raw)
        obj, pe = _paired_field(obj, pe, name, item, 1, struct.pack("<i", displacement))
        parsed = parse_object(obj)
        root = next(row for row in parsed.symbols if row.name == name and row.type == 0x20 and
                    row.section > 0 and row.value == 0)
        section = parsed.sections[root.section - 1]
        location = item.address - image.preferred_base - parsed_image_root(obj, pe, name) + 1
        relocation = [row for row in section.relocations if row.offset == location]
        assert len(relocation) == 1 and relocation[0].kind == 4
        changed = bytearray(obj)
        struct.pack_into("<i", changed, section.offset + location, 0)
        obj = bytes(changed)
    header = struct.unpack_from("<I", pe, 60)[0]
    table, count = struct.unpack_from("<II", pe, header + 12)
    strings = table + count * 18
    length = struct.unpack_from("<I", pe, strings)[0]
    text = pe[strings:strings + length]
    assert text.count(b"acquire_record") == text.count(b"require_record") == 1
    changed = (text.replace(b"acquire_record", b"XXXXXXX_record")
                   .replace(b"require_record", b"acquire_record")
                   .replace(b"XXXXXXX_record", b"require_record"))
    pe = pe[:strings] + changed + pe[strings + length:]
    assert verify_builder_subjects(obj, pe)["verified"] is True
    for index in (28, 30):
        function_subject(obj, pe, parse_image(pe), 0xb4f1, names[index])
    return obj, pe


def _coff_symbol_alias(object_bytes, image_bytes, owner, instruction, intended):
    """Retarget one fixup to an undefined same-name alias at the same PE RVA."""
    parsed = parse_object(object_bytes)
    protected = {row.section for row in parsed.symbols if row.name in
                 (*SUBJECTS, DECODER, owner) and row.type == 0x20 and row.section > 0}
    protected_targets = {relocation.target for section in parsed.sections if
                         parsed.owners[section.index - 1] in protected
                         for relocation in section.relocations}
    alias = next(row for row in parsed.symbols if row.section == 0 and row.storage == 2 and
                 not row.auxiliaries and row.index not in protected_targets)
    expected = [row for row in parsed.symbols if row.name == intended and row.section > 0]
    assert len(expected) == 1
    root = next(row for row in parsed.symbols if row.name == owner and row.type == 0x20 and
                row.section > 0 and row.value == 0)
    section = parsed.sections[root.section - 1]
    field = 1 if instruction.opcode == "callq" else len(instruction.raw) - 4
    location = instruction.address - parse_image(image_bytes).preferred_base - \
               parsed_image_root(object_bytes, image_bytes, owner) + field
    index = next(number for number, row in enumerate(section.relocations)
                 if row.offset == location and row.target == expected[0].index)
    table = struct.unpack_from("<I", object_bytes, 8)[0]
    relocations = struct.unpack_from("<I", object_bytes,
                                     20 + (section.index - 1) * 40 + 24)[0]
    changed = bytearray(object_bytes)
    changed[table + alias.index * 18:table + alias.index * 18 + 8] = \
        object_bytes[table + expected[0].index * 18:table + expected[0].index * 18 + 8]
    struct.pack_into("<I", changed, relocations + index * 10 + 4, alias.index)
    result = bytes(changed)
    assert verify_builder_subjects(result, image_bytes)["verified"] is True
    function_subject(result, image_bytes, parse_image(image_bytes), 0xb4f2, owner)
    return result


def _paired_record33_stack_alias(object_bytes, image_bytes, owner_code):
    from coff_relocations import Resolver

    image = parse_image(image_bytes)
    instructions = _instructions(owner_code, image_bytes, OWNER)
    call_index = next(position for position, item in enumerate(instructions) if
                      item.opcode == "callq" and "_33>" in item.operands[0])
    output, capacity = instructions[call_index - 2:call_index]
    assert output.opcode == "leaq" and output.operands[1] == "%rdx"
    assert capacity.raw == b"\x41\xb8\x04\x00\x00\x00"
    replacement = b"\x48\x8d\x94\x24\x90\x00\x00\x00\x48\x83\xea\x04\x90"
    assert len(replacement) == len(output.raw) + len(capacity.raw)
    obj, pe = _paired_field(object_bytes, image_bytes, OWNER, output, 0, replacement)
    parsed = parse_object(object_bytes)
    resolver = Resolver(parsed, image, image_symbols(image_bytes, image))
    root = next(row for row in parsed.symbols if row.name == OWNER and row.type == 0x20 and
                row.section > 0 and row.value == 0)
    section = parsed.sections[root.section - 1]
    root_rva = resolver.named(OWNER)
    location = output.address - image.preferred_base - root_rva + len(output.raw) - 4
    relocation = [row for row in section.relocations if row.offset == location]
    assert len(relocation) == 1 and relocation[0].kind == 4
    desired = struct.unpack_from("<i", replacement, len(output.raw) - 4)[0]
    addend = desired + root_rva + location + 4 - resolver.target(relocation[0].target)
    changed = bytearray(obj)
    struct.pack_into("<i", changed, section.offset + location, addend)
    result = bytes(changed), pe
    assert verify_builder_subjects(*result)["verified"] is True
    return result


def parsed_image_root(object_bytes, image_bytes, owner):
    from coff_relocations import Resolver
    from coff_symbols import image_symbols
    image = parse_image(image_bytes)
    return Resolver(parse_object(object_bytes), image, image_symbols(image_bytes, image)).named(owner)


def _paired_wrapper(object_bytes, image_bytes, code, name, predicate, replacement):
    items = _instructions(code, image_bytes, name)
    chosen = [item for item in items if predicate(item)]
    assert len(chosen) == 1
    item = chosen[0]
    assert len(item.raw) == len(replacement)
    obj, pe = _paired_field(object_bytes, image_bytes, name, item, 0, replacement)
    function_subject(obj, pe, parse_image(pe), 0xb4ee, name)
    return obj, pe


def _code(objdump, scratch, image_bytes, names):
    path = scratch / "mutated.dll"
    path.write_bytes(image_bytes)
    return ({name: owner_code(objdump, path, name) for name in (OWNER, WRAPPER)},
            {name: owner_code(objdump, path, name) for name in names.values()})


def _finalizer(build, objdump, output, receipt, *, archive, publication):
    demo = build / "demo"
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               str(objdump), str(demo / "libpyobf_native_demo_inner.dll"),
               str(demo / "payload.cff.coverage.json"), "--output", str(output),
               "--post-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
               "--post-mixed-private", str(demo / "payload.binding.private.json"),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(receipt),
               "--builder-input-ir", str(demo / "payload.archive.prepared.ll"),
               "--builder-object", str(demo / "payload.cff.obj"),
               "--builder-subjects", "--builder-entry-states"]
    if archive:
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
        for role in ARCHIVE_ROLES:
            command.append("--archive-origin-role=" + role + "=" + origin["paths"][role])
    if publication:
        command.append("--builder-archive-publication")
    return subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)


def check(build):
    demo, record, role_paths, roles, names, objdump, codes, wrappers = _bytes(build)
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_bytes = (demo / "libpyobf_native_demo_inner.dll").read_bytes()
    report = (demo / "payload.cff.coverage.json").read_bytes()
    edges = (demo / "payload.post-mixed.edges.json").read_bytes()

    def prove(obj=object_bytes, image=image_bytes, owner_codes=codes, wrapper_codes=wrappers):
        return verify_builder_archive_publication(obj, image, report, edges,
            record, roles, owner_codes, wrapper_codes)

    proof = prove()
    final = json.loads((demo / "payload.cff.final.json").read_bytes())
    assert final["builder_archive_publication"] == proof
    assert proof["verified"] and proof["publication_route_verified"]
    assert proof["decoder_effect_verified"] is False
    assert proof["original_predicate_equivalence_verified"] is False
    assert proof["transitive_callee_semantics_verified"] is False
    assert proof["scope"].endswith("-after-mixed-helper-routes-v1")
    assert proof["object_sha256"] == hashlib.sha256(object_bytes).hexdigest()
    assert proof["image_sha256"] == hashlib.sha256(image_bytes).hexdigest()
    assert proof["archive_record_sha256"] == hashlib.sha256(record).hexdigest()
    assert [row["record_index"] for row in proof["conditions"]] == [28, 30]

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        output = scratch / "final.json"
        baseline = _finalizer(build, objdump, output, build / "builder.fixed.json",
                              archive=True, publication=True)
        assert baseline.returncode == 0, baseline.stderr
        assert json.loads(output.read_bytes())["builder_archive_publication"] == proof

        compare_object, compare_image = paired_bytes_mutation(
            object_bytes, image_bytes, codes[OWNER], OWNER,
            b"\x45\x39\xc8", b"\x45\x39\xc0", "cmovll")
        changed_codes, changed_wrappers = _code(objdump, scratch, compare_image, names)
        refused("paired self-compare", lambda: prove(compare_object, compare_image,
                changed_codes, changed_wrappers), "compare polarity or argument order")

        owner_items = _instructions(codes[OWNER], image_bytes, OWNER)
        selector = next(item for item in owner_items if item.opcode == "cmovll")
        assert selector.raw == b"\x0f\x4c\xca"
        selector_object, selector_image = _paired_field(
            object_bytes, image_bytes, OWNER, selector, 0, b"\x0f\x44\xca")
        changed_codes, changed_wrappers = _code(objdump, scratch, selector_image, names)
        refused("paired duplicate predicate selector", lambda: prove(
                selector_object, selector_image, changed_codes, changed_wrappers),
                "compute predicate inventory differs")

        read_object, read_image = _paired_read_redirect(object_bytes, image_bytes,
                                                        codes[OWNER], proof)
        changed_codes, changed_wrappers = _code(objdump, scratch, read_image, names)
        refused("paired redirected read", lambda: prove(read_object, read_image,
                changed_codes, changed_wrappers), "same-slot PE read")

        # The first physical predicate's true successor normally reaches its
        # local terminal. Redirecting it into the other read skips that call.
        image = parse_image(image_bytes)
        physical = sorted(proof["conditions"], key=lambda row: row["compare_rva"])
        _, owner_graph, _ = _graph(owner_items, allow_indirect=True)
        entry_branch = next(item for item in owner_items if item.opcode in ("jmp", "jmpq"))
        dispatcher = owner_graph[entry_branch.address][0]
        frame = _imm(owner_items[0].operands[0])
        state_slot = _dispatcher_state(owner_items, owner_graph, frame) + frame
        landing = _dispatcher_destination(owner_items, dispatcher,
            physical[0]["true_state"], state_slot)
        bypass = next(item for item in owner_items if item.address >= landing and
                      item.opcode in ("jmp", "jmpq"))
        assert bypass.raw[:1] == b"\xe9" and len(bypass.raw) == 5
        normal_path = [item for item in owner_items if landing <= item.address < bypass.address]
        assert normal_path and normal_path[0].address == landing
        assert all(item.opcode not in ("jmp", "jmpq", "jae", "ret", "retq")
                   for item in normal_path)
        assert owner_graph[bypass.address] == (dispatcher,)
        parsed = parse_object(object_bytes)
        root = next(row for row in parsed.symbols if row.name == OWNER and
                    row.type == 0x20 and row.section > 0 and row.value == 0)
        section = parsed.sections[root.section - 1]
        location = bypass.address - image.preferred_base - \
                   parsed_image_root(object_bytes, image_bytes, OWNER) + 1
        assert not any(row.offset == location for row in section.relocations)
        target = image.preferred_base + physical[1]["read_rva"]
        bypass_object, bypass_image = _paired_field(
            object_bytes, image_bytes, OWNER, bypass, 0,
            b"\xe9" + struct.pack("<i", target - bypass.address - 5))
        assert verify_builder_subjects(bypass_object, bypass_image)["verified"] is True
        changed_codes, changed_wrappers = _code(objdump, scratch, bypass_image, names)
        refused("paired normal-route publication bypass", lambda: prove(
                bypass_object, bypass_image, changed_codes, changed_wrappers),
                "bypassing CFG predecessor")

        # A direct E8 is also a control-flow edge into the other read.
        helper_call = next(item for item in normal_path if item.opcode == "callq")
        assert helper_call.raw[:1] == b"\xe8" and len(helper_call.raw) == 5
        original_target = helper_call.address + 5 + \
                          int.from_bytes(helper_call.raw[1:], "little", signed=True)
        call_object, call_image = _paired_rel32_shift(
            object_bytes, image_bytes, OWNER, helper_call, target - original_target)
        assert verify_builder_subjects(call_object, call_image)["verified"] is True
        changed_codes, changed_wrappers = _code(objdump, scratch, call_image, names)
        refused("paired local-call publication bypass", lambda: prove(
                call_object, call_image, changed_codes, changed_wrappers),
                "owner direct call enters its own protected interval")

        argument_write = next(item for item in owner_items if item.opcode == "movl" and
                              item.operands == ("%eax", "0xbc(%rsp)"))
        argument_object, argument_image = _paired_field(
            object_bytes, image_bytes, OWNER, argument_write, 3, b"\x8c")
        assert verify_builder_subjects(argument_object, argument_image)["verified"] is True
        changed_codes, changed_wrappers = _code(objdump, scratch, argument_image, names)
        refused("paired argument-spill overwrite", lambda: prove(
                argument_object, argument_image, changed_codes, changed_wrappers),
                "original predicate source stack slot has another writer")

        clear = next(item for item in owner_items if item.opcode == "movl" and
                     item.operands == ("$0x0", "0x140(%rsp)"))
        slot = proof["conditions"][0]["slot_rva"] + parse_image(image_bytes).preferred_base
        replacement = (b"\xc7\x05" + struct.pack("<i", slot - clear.address - 10) +
                       bytes(4) + b"\x90")
        assert len(replacement) == len(clear.raw)
        overwrite_object, overwrite_image = _paired_field(
            object_bytes, image_bytes, OWNER, clear, 0, replacement)
        assert verify_builder_subjects(overwrite_object, overwrite_image)["verified"] is True
        changed_codes, changed_wrappers = _code(objdump, scratch, overwrite_image, names)
        refused("paired publication overwrite", lambda: prove(
                overwrite_object, overwrite_image, changed_codes, changed_wrappers),
                "indirect or global writer")

        readonly_rva = 0x2c300  # Read-only .rdata in this actual O2 fixture.
        readonly = rva_section(parse_image(image_bytes), readonly_rva, 24, logical=True)
        assert readonly.name == b".rdata" and not readonly.flags & 0x80000000
        readonly_object, readonly_image = _paired_shift_outputs(
            object_bytes, image_bytes, codes[OWNER], proof, readonly_rva)
        changed_codes, changed_wrappers = _code(objdump, scratch, readonly_image, names)
        refused("paired six-slot read-only publication", lambda: prove(
                readonly_object, readonly_image, changed_codes, changed_wrappers),
                "archive output slot lacks writable COFF/PE storage")

        cache_object, cache_image = _paired_shift_outputs(
            object_bytes, image_bytes, codes[OWNER], proof,
            physical[0]["cache_rva"])
        changed_codes, changed_wrappers = _code(objdump, scratch, cache_image, names)
        refused("paired six-slot cache overlap", lambda: prove(
                cache_object, cache_image, changed_codes, changed_wrappers),
                "package, storage or cache extents overlap")

        for label, obj, pe in (("self-compare", compare_object, compare_image),
                               ("redirected-read", read_object, read_image)):
            receipt_inputs = {"image": pe, "report": report,
                              "private": (demo / "payload.binding.private.json").read_bytes(),
                              "plan": edges,
                              "input_ir": (demo / "payload.archive.prepared.ll").read_bytes(),
                              "object": obj}
            assert set(receipt_inputs) == set(BUILDER_ROLES)
            six_receipt = scratch / "six.fixed.json"
            six_receipt.write_bytes(create_receipt(receipt_inputs))
            with ExitStack() as stack:
                stack.enter_context(modified(demo / "payload.cff.obj", obj))
                stack.enter_context(modified(demo / "libpyobf_native_demo_inner.dll", pe))
                old = _finalizer(build, objdump, output, six_receipt,
                                 archive=False, publication=False)
                assert old.returncode == 0, f"old six-role gate refused {label}: {old.stderr}"
                replay_paths = replay_paths_for(build, json.loads((build / "builder.replay.json").read_bytes()))
                replay_inputs = {role: replay_paths[role].read_bytes() for role in REPLAY_ROLES}
                full_receipt = scratch / "full.fixed.json"
                full_receipt.write_bytes(create_receipt(replay_inputs, profile=REPLAY_PROFILE))
                output.write_bytes(b"stale final report")
                current = _finalizer(build, objdump, output, full_receipt,
                                     archive=True, publication=True)
                assert current.returncode != 0 and not output.exists(), label
                assert "builder replay" in current.stderr, current.stderr

        # Bounded wrong-package, record-ID, stack ABI and state-route shapes.
        wrapper28 = names[28]
        item = next(item for item in _instructions(wrappers[wrapper28], image_bytes, wrapper28)
                    if item.opcode == "movl" and item.operands == ("$0x1c", "%r8d"))
        wrong_id = item.raw[:2] + (30).to_bytes(4, "little")
        obj, pe = _paired_wrapper(object_bytes, image_bytes, wrappers[wrapper28], wrapper28,
                                  lambda row: row.address == item.address, wrong_id)
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("wrong wrapper record ID", lambda: prove(obj, pe, owner, wrapped),
                "Win64 call arguments")

        item = next(item for item in _instructions(wrappers[wrapper28], image_bytes, wrapper28)
                    if item.opcode == "movq" and item.operands == ("%r10", "0x28(%rsp)"))
        obj, pe = _paired_wrapper(object_bytes, image_bytes, wrappers[wrapper28], wrapper28,
                                  lambda row: row.address == item.address,
                                  item.raw[:-1] + b"\x30")
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("wrong wrapper stack argument", lambda: prove(obj, pe, owner, wrapped),
                "Win64 call arguments")

        item = next(item for item in _instructions(wrappers[wrapper28], image_bytes, wrapper28)
                    if item.opcode == "leaq" and item.operands[1] == "%rcx" and
                    item.operands[0].endswith("(%rip)"))
        obj, pe = _paired_rel32_shift(object_bytes, image_bytes, wrapper28, item, 8)
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("wrong archive package pointer", lambda: prove(obj, pe, owner, wrapped),
                "different package")

        cache = next(item for item in _instructions(wrappers[wrapper28], image_bytes, wrapper28)
                     if item.opcode == "leaq" and item.operands[1] == "%r10" and
                     item.operands[0].endswith("(%rip)"))
        cache_target = proof["conditions"][0]["cache_rva"]
        obj, pe = _paired_rel32_shift(object_bytes, image_bytes, wrapper28,
                                      cache, proof["conditions"][0]["package_rva"] - cache_target)
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("paired cache retarget to package", lambda: prove(obj, pe, owner, wrapped),
                "publication relocation changes the exact symbol address")

        false_object, false_image = _paired_false_decoder(
            object_bytes, image_bytes, names, wrappers)
        owner, wrapped = _code(objdump, scratch, false_image, names)
        assert all("require_record" in wrapped[names[index]] for index in (28, 30))
        refused("paired false decoder with PE symbols swapped", lambda: prove(
                false_object, false_image, owner, wrapped), "COFF final contribution bytes disagree")

        wrapper_items = _instructions(wrappers[wrapper28], image_bytes, wrapper28)
        for label, intended, instruction in (
                ("decoder", DECODER, next(item for item in wrapper_items if
                 item.opcode == "callq" and "require_record" in item.operands[0])),
                ("package", PACKAGE, next(item for item in wrapper_items if
                 item.opcode == "leaq" and item.operands[1] == "%rcx" and
                 item.operands[0].endswith("(%rip)"))),
                ("cache", "_ZN12_GLOBAL__N_18cache_28E", next(item for item in wrapper_items if
                 item.opcode == "leaq" and item.operands[1] == "%r10" and
                 item.operands[0].endswith("(%rip)")))):
            aliased = _coff_symbol_alias(object_bytes, image_bytes, wrapper28,
                                         instruction, intended)
            refused(f"COFF {label} alias relocation", lambda aliased=aliased: prove(
                    aliased, image_bytes), "different COFF symbol index")

        alias_object, alias_image = _paired_record33_stack_alias(
            object_bytes, image_bytes, codes[OWNER])
        changed_codes, changed_wrappers = _code(objdump, scratch, alias_image, names)
        refused("record-33 argument-stack alias", lambda: prove(
                alias_object, alias_image, changed_codes, changed_wrappers),
                "extra or missing stack-address producers")

        wrapper33 = names[33]
        wrapper33_items = _instructions(wrappers[wrapper33], image_bytes, wrapper33)
        prologue = wrapper33_items[0]
        epilogue = next(item for item in wrapper33_items if item.opcode == "addq" and
                        item.operands == ("$0x68", "%rsp"))
        assert prologue.raw == b"\x48\x83\xec\x68"
        assert epilogue.raw == b"\x48\x83\xc4\x68"
        obj, pe = _paired_wrapper(object_bytes, image_bytes, wrappers[wrapper33],
                                  wrapper33, lambda row: row.address == prologue.address,
                                  b"\x48\x83\xc4\x18")
        obj, pe = _paired_field(obj, pe, wrapper33, epilogue, 0,
                                b"\x48\x83\xec\x18")
        function_subject(obj, pe, parse_image(pe), 0xb4ee, wrapper33)
        assert verify_builder_subjects(obj, pe)["verified"] is True
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("record-33 caller-spill clobber", lambda: prove(obj, pe, owner, wrapped),
                "wrapper entry ABI or require-record call inventory")

        parsed = parse_object(object_bytes)
        root = next(row for row in parsed.symbols if row.name == wrapper28 and
                    row.type == 0x20 and row.section > 0 and row.value == 0)
        section = parsed.sections[root.section - 1]
        location = item.address - parse_image(image_bytes).preferred_base - \
                   parsed_image_root(object_bytes, image_bytes, wrapper28) + len(item.raw) - 4
        relocation_index = next(number for number, row in enumerate(section.relocations)
                                if row.offset == location)
        table = struct.unpack_from("<I", object_bytes, 20 + (section.index - 1) * 40 + 24)[0]
        wrong_reloc = bytearray(object_bytes)
        struct.pack_into("<H", wrong_reloc, table + relocation_index * 10 + 8, 5)
        refused("wrong REL32 kind", lambda: prove(bytes(wrong_reloc), image_bytes),
                "COFF final contribution bytes disagree")

        item = next(item for item in _instructions(wrappers[wrapper28], image_bytes, wrapper28)
                    if item.opcode == "movl" and item.operands[1] == "0x64(%rsp)" and
                    item.operands[0].startswith("$"))
        obj, pe = _paired_wrapper(object_bytes, image_bytes, wrappers[wrapper28], wrapper28,
                                  lambda row: row.address == item.address,
                                  item.raw[:-4] + (0).to_bytes(4, "little"))
        owner, wrapped = _code(objdump, scratch, pe, names)
        refused("wrong wrapper state route", lambda: prove(obj, pe, owner, wrapped),
                "wrapper entry state differs")
        with ExitStack() as stack:
            stack.enter_context(modified(demo / "payload.cff.obj", obj))
            stack.enter_context(modified(demo / "libpyobf_native_demo_inner.dll", pe))
            paths = replay_paths_for(build, json.loads((build / "builder.replay.json").read_bytes()))
            current_inputs = {role: paths[role].read_bytes() for role in REPLAY_ROLES}
            receipt = scratch / "wrong-state.fixed.json"
            receipt.write_bytes(create_receipt(current_inputs, profile=REPLAY_PROFILE))
            output.write_bytes(b"stale final report")
            current = _finalizer(build, objdump, output, receipt,
                                 archive=True, publication=True)
            assert current.returncode != 0 and not output.exists(), current.stderr

        refused("unsupported owner inventory", lambda: prove(owner_codes={OWNER: codes[OWNER]}),
                "exact mixed-owner disassemblies")
        refused("unsupported wrapper inventory", lambda: prove(wrapper_codes={}),
                "exact authenticated wrapper disassemblies")
        refused("wrong 20-role set", lambda: verify_builder_archive_publication(
                object_bytes, image_bytes, report, edges, record,
                {key: value for key, value in roles.items() if key != "package"},
                codes, wrappers), "exact 20 byte roles")

    print(json.dumps({"verified": True, "conditions": [28, 30],
                      "paired_old_six_role_admit": True,
                      "full_replay_pair_refusal_is_redundant": True}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    check(parser.parse_args().build)


if __name__ == "__main__":
    main()
