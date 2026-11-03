"""Exercise actual mixed child binding-status machine routes and paired bypasses."""

import hashlib
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
from cff_builder_binding_status_effects import (  # noqa: E402
    AVAILABILITY, BINDING_STATUS, CONTEXT_AVAILABILITY, EFFECT_CALLEES,
    GENERATION, REQUIRE_BINDING,
    STATE, _destination, _entry, _report, _states,
    verify_builder_binding_status_effects,
)
from cff_builder_receipt import (REPLAY_PROFILE, REPLAY_ROLES, ROLES,
                                 create_receipt, verify_receipt)  # noqa: E402
from cff_builder_replay import verify_replay_record  # noqa: E402
from cff_joint_machine_evidence import _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: changed input was accepted")


def finalizer(build, paths, output, receipt, *, effects):
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
               "--builder-helper-arguments"]
    if effects:
        command.append("--builder-binding-status-effects")
    return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)


def _instructions_for(objdump, image_path, image_bytes, name):
    return _instructions(disassembly(objdump, image_path, name), image_bytes, name.lower())


def _body_item(build, image_bytes, report_bytes, body, raw):
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    items = _instructions_for(objdump, build / "demo" / "libpyobf_native_demo_inner.dll",
                              image_bytes, BINDING_STATUS)
    recipes = _report(report_bytes)
    states = _states(BINDING_STATUS, recipes[BINDING_STATUS])
    spills, slot, dispatcher = _entry(items, states[0], ("%rdx", "%rcx"))
    count = 13 if cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT") == "none" else 7
    starts = [_destination(items, dispatcher, state, slot) for state in states[:count]]
    start = starts[body]
    end = min(address for address in (*starts, dispatcher) if address > start)
    selected = [item for item in items if start <= item.address < end and item.raw == raw]
    assert len(selected) == 1, (body, raw.hex(), selected)
    return selected[0]


def paired_instruction(object_bytes, image_bytes, name, item, replacement):
    assert len(item.raw) == len(replacement) and replacement != item.raw
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, name).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb820, name)
    assert len(subject.ranges) == 1
    span = subject.ranges[0]
    offset = item.address - image.preferred_base - span.rva
    assert 0 <= offset <= section.size - len(item.raw)
    assert all(not (rel.offset < offset + len(item.raw) and
                    offset < rel.offset + (8 if rel.kind == 1 else 4))
               for rel in section.relocations)
    pe_section = rva_section(image, span.rva, section.size, logical=True)
    pe_start = pe_section.raw_offset + span.rva - pe_section.rva
    object_offset, image_offset = section.offset + offset, pe_start + offset
    assert object_bytes[object_offset:object_offset + len(item.raw)] == item.raw
    assert image_bytes[image_offset:image_offset + len(item.raw)] == item.raw
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    changed_object[object_offset:object_offset + len(item.raw)] = replacement
    changed_image[image_offset:image_offset + len(item.raw)] = replacement
    return bytes(changed_object), bytes(changed_image)


def paired_instructions(object_bytes, image_bytes, changes):
    for name, item, replacement in changes:
        object_bytes, image_bytes = paired_instruction(
            object_bytes, image_bytes, name, item, replacement)
    return object_bytes, image_bytes


def alias_relocation(object_bytes, image_bytes, caller, target, item):
    """Retarget a call fixup to its target section symbol at the same PE VA."""
    obj = parse_object(object_bytes)
    source = root(obj, caller)
    destination = root(obj, target)
    section = obj.sections[source.section - 1]
    target_section = obj.sections[destination.section - 1]
    aliases = [symbol for symbol in obj.symbols if
               symbol.section == destination.section and symbol.name == target_section.name and
               symbol.type == 0 and symbol.storage == 3 and symbol.value == 0]
    assert len(aliases) == 1 and aliases[0].index != destination.index
    image = parse_image(image_bytes)
    span = function_subject(object_bytes, image_bytes, image, 0xb821, caller).ranges[0]
    relative = item.address - image.preferred_base - span.rva
    candidates = [(index, relocation) for index, relocation in enumerate(section.relocations)
                  if relocation.offset == relative + 1]
    assert len(candidates) == 1
    index, relocation = candidates[0]
    assert relocation.kind == 4 and relocation.target == destination.index
    table = struct.unpack_from("<I", object_bytes,
                               20 + (section.index - 1) * 40 + 24)[0]
    changed = bytearray(object_bytes)
    struct.pack_into("<I", changed, table + index * 10 + 4, aliases[0].index)
    return bytes(changed)


def _alias_case(build, paths, caller, target, item):
    original = paths["object"].read_bytes()
    altered_object = alias_relocation(original, paths["image"].read_bytes(),
                                      caller, target, item)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        altered = {**paths, "object": temp / "alias.obj"}
        altered["object"].write_bytes(altered_object)
        receipt = temp / "alias.receipt.json"
        receipt.write_bytes(create_receipt(
            {role: path.read_bytes() for role, path in altered.items()}))
        old = finalizer(build, altered, temp / "old.alias.json", receipt, effects=False)
        output = temp / "stale.alias.json"
        output.write_bytes(b"stale")
        current = finalizer(build, altered, output, receipt, effects=True)
        assert old.returncode == 0 and (temp / "old.alias.json").exists(), old.stderr
        assert current.returncode != 0 and not output.exists(), current.stderr
        assert ("builder binding-status effects proof failed:" in current.stderr and
                "root-symbol REL32 relocation" in current.stderr), current.stderr
    print(f"{caller} -> {target}: same-address section alias passes predecessor; exact root relocation refuses")


def _paired_case(build, paths, label, item, replacement, name=BINDING_STATUS):
    _paired_changes(build, paths, label, [(name, item, replacement)])


def _paired_changes(build, paths, label, changes, reason=None):
    changed_object, changed_image = paired_instructions(
        paths["object"].read_bytes(), paths["image"].read_bytes(),
        changes)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        altered = {**paths, "object": temp / "altered.obj", "image": temp / "altered.dll"}
        altered["object"].write_bytes(changed_object)
        altered["image"].write_bytes(changed_image)
        receipt = temp / "paired.receipt.json"
        paired_inputs = {role: path.read_bytes() for role, path in altered.items()}
        assert set(paired_inputs) == set(ROLES)
        receipt.write_bytes(create_receipt(paired_inputs))
        assert verify_receipt(receipt.read_bytes(), paired_inputs)["verified"] is True
        old = finalizer(build, altered, temp / "predecessor.json", receipt, effects=False)
        output = temp / "stale.json"
        output.write_bytes(b"stale")
        current = finalizer(build, altered, output, receipt, effects=True)
        assert old.returncode == 0 and (temp / "predecessor.json").exists(), old.stderr
        assert current.returncode != 0 and not output.exists(), current.stderr
        assert ("builder binding-status effects proof failed:" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
        if reason is not None:
            assert reason in current.stderr, current.stderr
        print(f"{label}: paired predecessor admits; binding-status effects refuses and clears output")


def _stack_changes(items, name, sources, old, new):
    changes = []
    for raw in sources:
        selected = [item for item in items if item.raw == bytes.fromhex(raw)]
        assert len(selected) == 1, (name, raw, selected)
        item = selected[0]
        assert item.raw[-1] == old
        changes.append((name, item, item.raw[:-1] + bytes((new,))))
    return changes


def check(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    assert set(inputs) == set(ROLES)
    fixed_bytes = (build / "builder.fixed.json").read_bytes()
    fixed = json.loads(fixed_bytes)
    if fixed["profile"] == REPLAY_PROFILE:
        record_bytes = (build / "builder.replay.json").read_bytes()
        record = json.loads(record_bytes)
        replay_inputs = {**inputs,
                         "transformed_ir": (build / "demo" / "payload.cff.ll").read_bytes(),
                         "request_manifest": Path(record["paths"]["request_manifest"]).read_bytes(),
                         "recipe": Path(record["paths"]["recipe"]).read_bytes(),
                         "opt_exe": Path(record["paths"]["opt_exe"]).read_bytes(),
                         "clang_exe": Path(record["paths"]["clang_exe"]).read_bytes(),
                         "pass_plugin": Path(record["paths"]["pass_plugin"]).read_bytes(),
                         "replay_record": record_bytes}
        assert set(replay_inputs) == set(REPLAY_ROLES)
        assert verify_receipt(fixed_bytes, replay_inputs, profile=REPLAY_PROFILE)["verified"] is True
        assert verify_replay_record(record_bytes, replay_inputs)["record_consistency_verified"] is True
    else:
        replay_inputs = None
        assert verify_receipt(fixed_bytes, inputs)["verified"] is True
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    local = {name: disassembly(objdump, paths["image"], name)
             for name in (REQUIRE_BINDING, BINDING_STATUS)}
    effects = {name: disassembly(objdump, paths["image"], name)
               for name in EFFECT_CALLEES}
    proof = verify_builder_binding_status_effects(
        inputs["object"], inputs["image"], inputs["report"], local, effects)
    assert proof == {
        "verified": True, "state_pointer_identity_verified": True,
        "generation_guard_verified": True, "availability_route_verified": True,
        "transitive_binding_closed": False, "context_availability_body_verified": False,
        "object_sha256": hashlib.sha256(inputs["object"]).hexdigest(),
        "image_sha256": hashlib.sha256(inputs["image"]).hexdigest(),
        "report_sha256": hashlib.sha256(inputs["report"]).hexdigest(),
    }
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_binding_status_effects"] == proof
    refused("missing state effect", lambda: verify_builder_binding_status_effects(
        inputs["object"], inputs["image"], inputs["report"], local,
        {GENERATION: effects[GENERATION], AVAILABILITY: effects[AVAILABILITY]}),
        "five linked disassemblies")
    refused("wrong generation target map", lambda: verify_builder_binding_status_effects(
        inputs["object"], inputs["image"], inputs["report"], local,
        {**effects, GENERATION: effects[STATE]}), "exact selected symbol")
    refused("missing status", lambda: verify_builder_binding_status_effects(
        inputs["object"], inputs["image"], inputs["report"],
        {REQUIRE_BINDING: local[REQUIRE_BINDING]}, effects), "five linked disassemblies")
    refused("malformed raw report", lambda: verify_builder_binding_status_effects(
        inputs["object"], inputs["image"], b"{}", local, effects),
        "raw compiler report")
    missing_root = symbol_section_mutation(inputs["object"],
                                           root(parse_object(inputs["object"]), GENERATION), 0)
    refused("missing generation root", lambda: verify_builder_binding_status_effects(
        missing_root, inputs["image"], inputs["report"], local, effects),
        "one offset-zero root definition")

    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    if optimization == "none":
        cases = (
            ("initial status guard", 0, bytes.fromhex("4183f800"),
             bytes.fromhex("4183f801")),
            ("parent pointer null guard", 2, bytes.fromhex("4983f800"),
             bytes.fromhex("4983f801")),
            ("lease pointer null guard", 3, bytes.fromhex("4983f800"),
             bytes.fromhex("4983f801")),
            ("pointer identity", 4, bytes.fromhex("4d39c8"),
             bytes.fromhex("4d39c0")),
            ("nonzero parent generation", 5, bytes.fromhex("4983f800"),
             bytes.fromhex("4983f801")),
            ("generation equality", 6, bytes.fromhex("4d39c8"),
             bytes.fromhex("4d39c0")),
            ("parent availability selection", 8, bytes.fromhex("4183f800"),
             bytes.fromhex("4183f801")),
        )
        state_items = _instructions_for(objdump, paths["image"], inputs["image"], STATE)
        state_changes = []
        for item in state_items:
            if "0x1c(%rsp)" in item.operands:
                assert item.opcode == "movl" and item.raw[3] == 0x1c
                state_changes.append((STATE, item, item.raw[:3] + b"\x0c" + item.raw[4:]))
        assert len(state_changes) == 6
        _paired_changes(build, paths, "source-none state slot overlaps lease pointer",
                        state_changes, "stack value intervals overlap")
    elif optimization == "O2":
        cases = (
            ("initial status guard", 0, bytes.fromhex("4183f800"),
             bytes.fromhex("4183f801")),
            ("parent pointer null guard", 1, bytes.fromhex("4883f900"),
             bytes.fromhex("4883f901")),
            ("lease pointer null guard", 1, bytes.fromhex("4883fa00"),
             bytes.fromhex("4883fa01")),
            ("pointer identity", 1, bytes.fromhex("4839d1"),
             bytes.fromhex("4839c9")),
            ("nonzero parent generation", 2, bytes.fromhex("4983f800"),
             bytes.fromhex("4983f801")),
            ("generation equality", 3, bytes.fromhex("4d39c8"),
             bytes.fromhex("4d39c0")),
            ("parent availability selection", 4, bytes.fromhex("4183f800"),
             bytes.fromhex("4183f801")),
        )
        binding_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                          BINDING_STATUS)
        generation_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                             GENERATION)
        availability_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                               AVAILABILITY)
        overlap_cases = (
            ("binding pointer slot overlaps lease argument",
             _stack_changes(binding_items, BINDING_STATUS,
                            ("4889442428", "488b4c2428"), 0x28, 0x2c)),
            ("generation context slot overlaps result",
             _stack_changes(generation_items, GENERATION,
                            ("4889442418", "4c8b442418", "488b442418"),
                            0x18, 0x14)),
            ("availability context slot overlaps lease argument",
             _stack_changes(availability_items, AVAILABILITY,
                            ("4889442438", "4c8b442438", "488b4c2438"),
                            0x38, 0x2c)),
        )
        for label, changes in overlap_cases:
            _paired_changes(build, paths, label, changes,
                            "stack value intervals overlap")
        _paired_changes(
            build, paths, "binding pointer crosses Win64 call shadow",
            _stack_changes(binding_items, BINDING_STATUS,
                           ("4889442428", "488b4c2428"), 0x28, 0x10),
            "Win64 outgoing call shadow space")
    else:
        raise AssertionError(f"unsupported source optimization: {optimization}")
    for label, body, old, new in cases:
        item = _body_item(build, inputs["image"], inputs["report"], body, old)
        _paired_case(build, paths, label, item, new)
        if label == "pointer identity" and replay_inputs is not None:
            altered_object, altered_image = paired_instruction(
                inputs["object"], inputs["image"], BINDING_STATUS, item, new)
            refused("fixed full replay catches paired pointer self-comparison",
                    lambda: verify_replay_record(record_bytes, {
                        **replay_inputs, "object": altered_object, "image": altered_image}),
                    "image differs from the replay record")
    binding_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                      BINDING_STATUS)
    first_spill = binding_items[1]
    assert first_spill.raw[:3] == bytes.fromhex("488954")
    _paired_case(build, paths, "lease ABI spill", first_spill,
                 first_spill.raw[:2] + b"\x4c" + first_spill.raw[3:])
    generation_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                         GENERATION)
    generation_fields = [item for item in generation_items
                         if item.raw == bytes.fromhex("488b4020")]
    assert len(generation_fields) == 1
    _paired_case(build, paths, "generation field source", generation_fields[0],
                 bytes.fromhex("488b4028"), GENERATION)
    availability_items = _instructions_for(objdump, paths["image"], inputs["image"],
                                           AVAILABILITY)
    fallback_fields = [item for item in availability_items
                       if item.raw == bytes.fromhex("8b4008")]
    assert len(fallback_fields) == 1
    _paired_case(build, paths, "availability fallback source", fallback_fields[0],
                 bytes.fromhex("8b400c"), AVAILABILITY)
    state_calls = [item for item in binding_items if item.opcode in ("call", "callq") and
                   STATE.lower() in item.operands[0]]
    assert len(state_calls) == 2
    _alias_case(build, paths, BINDING_STATUS, STATE, state_calls[0])
    context_calls = [item for item in availability_items
                     if item.opcode in ("call", "callq") and
                     CONTEXT_AVAILABILITY.lower() in item.operands[0]]
    assert len(context_calls) == 1
    _alias_case(build, paths, AVAILABILITY, CONTEXT_AVAILABILITY,
                context_calls[0])
    print(f"binding-status effects: actual {optimization} PE/COFF, seven paired guards passed")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
