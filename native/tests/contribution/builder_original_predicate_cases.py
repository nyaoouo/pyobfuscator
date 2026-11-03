"""Actual linked-image cases for bounded mixed POST original predicates."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_entry_state_cases import cache_path, owner_code  # noqa: E402
from cff_builder_original_predicates import (  # noqa: E402
    _only_stack_write, _wrapper_source, verify_builder_original_predicates)
from cff_builder_receipt import create_receipt, verify_receipt  # noqa: E402
from cff_builder_subjects import verify_builder_subjects  # noqa: E402
from cff_joint_machine_evidence import Instruction, _graph, _instructions  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from payload_binding import OWNER, WRAPPER  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


OWNERS = (OWNER, WRAPPER)
MUTATIONS = {OWNER: (b"\x41\x83\xf8\x00", b"\x45\x39\xc0\x90"),
             WRAPPER: (b"\x4d\x39\xc8", b"\x4d\x39\xc0")}
SOURCE_MUTATIONS = {
    OWNER: (b"\x48\x89\x94\x24\xb0\x00\x00\x00",
            b"\x83\xc0\x01\x0f\x1f\x44\x00\x00"),
    WRAPPER: (b"\x48\x8b\x84\x24\xc0\x00\x00\x00",
              b"\x83\x84\x24\xb0\x00\x00\x00\x01"),
}
WRAPPER_COPY_MUTATION = (SOURCE_MUTATIONS[WRAPPER][0],
                         b"\x48\x89\x84\x24\xb0\x00\x00\x00")
WRAPPER_REGISTER_MUTATIONS = (
    (b"\x48\x89\x8c\x24\xb0\x00\x00\x00",
     b"\x49\x89\xca\x0f\x1f\x44\x00\x00", None),
    (b"\x48\x8b\x84\x24\xc0\x00\x00\x00",
     b"\x41\x83\xc2\x01\x0f\x1f\x40\x00", None),
    (b"\x48\x8b\x84\x24\xb0\x00\x00\x00",
     b"\x4c\x89\xd0\x0f\x1f\x44\x00\x00", None),
)
WRAPPER_ENTRY_MUTATION = (b"\x4c\x89\x44\x24\x78", b"\x83\xc2\x01\x66\x90")


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        if fragment not in str(error):
            raise AssertionError(f"{label}: wrong refusal: {error}") from error
        return
    raise AssertionError(f"{label}: changed image was accepted")


def paired_mutations(object_bytes, image_bytes, code, owner, patches):
    instructions = _instructions(code, image_bytes, owner)
    image = parse_image(image_bytes)
    proof = verify_builder_subjects(object_bytes, image_bytes)
    owner_ranges = proof["subjects"][OWNERS.index(owner)]["ranges"]
    obj = parse_object(object_bytes)
    symbols = [symbol for symbol in obj.symbols if symbol.name == owner and
               symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(symbols) == 1
    source = obj.sections[symbols[0].section - 1]
    changed_image, changed_object = bytearray(image_bytes), bytearray(object_bytes)
    used = set()
    previous_address = 0
    for old, replacement, following in patches:
        assert len(old) == len(replacement)
        candidates = [item for index, item in enumerate(instructions) if item.raw == old and
                      item.address > previous_address and
                      (following is None or instructions[index + 1].opcode == following)]
        assert len(candidates) == 1
        item = candidates[0]
        assert item.address not in used
        used.add(item.address)
        previous_address = item.address
        rva = item.address - image.preferred_base
        section = rva_section(image, rva, len(old), logical=True)
        image_offset = section.raw_offset + rva - section.rva
        assert image_bytes[image_offset:image_offset + len(old)] == old
        spans = [span for span in owner_ranges if span["rva"] <= rva and
                 rva + len(old) <= span["rva"] + span["size"]]
        assert len(spans) == 1 and source.size == spans[0]["size"]
        in_section = rva - spans[0]["rva"]
        assert not any(relocation.offset < in_section + len(old) and
                       in_section < relocation.offset + (8 if relocation.kind == 1 else 4)
                       for relocation in source.relocations)
        object_offset = source.offset + in_section
        assert object_bytes[object_offset:object_offset + len(old)] == old
        changed_image[image_offset:image_offset + len(old)] = replacement
        changed_object[object_offset:object_offset + len(old)] = replacement
    result = bytes(changed_object), bytes(changed_image)
    assert verify_builder_subjects(*result)["verified"] is True
    return result


def paired_bytes_mutation(object_bytes, image_bytes, code, owner, old, replacement,
                          following=None):
    return paired_mutations(object_bytes, image_bytes, code, owner,
                            ((old, replacement, following),))


def paired_compare_mutation(object_bytes, image_bytes, code, owner):
    old, replacement = MUTATIONS[owner]
    return paired_bytes_mutation(object_bytes, image_bytes, code, owner, old,
                                 replacement, "cmovll" if owner == OWNER else None)


def current_inputs(build):
    demo = build / "demo"
    image_path = demo / "libpyobf_native_demo_inner.dll"
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_bytes = image_path.read_bytes()
    paths = {"image": image_path, "object": demo / "payload.cff.obj",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json"}
    candidates = (demo / "payload.requested.ll", demo / "payload.archive.prepared.ll")
    paths["input_ir"] = next(path for path in reversed(candidates) if path.is_file())
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    objdump = cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {owner: owner_code(objdump, image_path, owner) for owner in OWNERS}
    return demo, paths, inputs, objdump, codes


def check_none(build):
    demo, paths, inputs, objdump, codes = current_inputs(build)
    proof = verify_builder_original_predicates(
        inputs["object"], inputs["image"], inputs["report"],
        inputs["input_ir"], inputs["plan"], codes)
    assert proof["verified"] is True
    assert [len(row["conditions"]) for row in proof["owners"]] == [2, 1]
    assert [condition["condition"] for row in proof["owners"]
            for condition in row["conditions"]] == ["slt-zero", "eq-zero", "generation-ne-subject"]
    with TemporaryDirectory(dir=build) as directory:
        output = Path(directory) / "positive.final.json"
        command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                   str(objdump), str(paths["image"]), str(paths["report"]),
                   "--output", str(output),
                   "--post-mixed-plan", str(paths["plan"]),
                   "--post-mixed-private", str(paths["private"]),
                   "--post-mixed-material", str(demo / "release-material.private.json"),
                   "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
                   "--builder-receipt", str(build / "builder.fixed.json"),
                   "--builder-input-ir", str(paths["input_ir"]),
                   "--builder-object", str(paths["object"]),
                   "--builder-subjects", "--builder-entry-states",
                   "--builder-original-predicates"]
        final = subprocess.run(command, capture_output=True, text=True, check=False)
        assert final.returncode == 0 and output.is_file(), final.stderr
        assert json.loads(output.read_text(encoding="utf-8"))["builder_original_predicates"] == proof

    wrapper_items = _instructions(codes[WRAPPER], inputs["image"], WRAPPER)
    compare = next(index for index, item in enumerate(wrapper_items)
                   if item.raw == MUTATIONS[WRAPPER][0])
    prior = wrapper_items[compare - 1]
    assert prior.opcode == "movl" and len(prior.raw) == 5
    # A valid five-byte replacement is xorq r8,r8 followed by a two-byte NOP.
    # The verifier's graph decoder already refuses xorq; the local provenance
    # routine must also refuse it rather than carrying its stale r8 value.
    altered = (wrapper_items[:compare - 1] +
               [Instruction(prior.address, b"\x4d\x31\xc0", "xorq", ("%r8", "%r8")),
                Instruction(prior.address + 3, b"\x66\x90", "nopw", ())] +
               wrapper_items[compare:])
    refused("unsupported source-register clobber", lambda: _wrapper_source(
        altered, compare + 1), "unmodeled instruction")
    refused("unsupported x64 graph opcode", lambda: _graph(altered, allow_indirect=True),
            "unsupported instruction xorq")
    refused("shift into protected source slot", lambda: _only_stack_write(
        [Instruction(17, b"\xd1\x6c\x24\x70", "shrl", ("$0x1", "0x70(%rsp)"))],
        0x70, 4, set()), "another writer")

    cases = [(OWNER, "self compare", ((*MUTATIONS[OWNER], "cmovll"),),
              "unmodeled original comparisons", None),
             (WRAPPER, "self compare", ((*MUTATIONS[WRAPPER], None),),
              "no longer compares two independent values", None),
             (OWNER, "argument register overwrite", ((*SOURCE_MUTATIONS[OWNER], None),),
              "compute argument register is overwritten before its copy", None),
             (WRAPPER, "handoff stack arithmetic", ((*SOURCE_MUTATIONS[WRAPPER], None),),
              "wrapper source has an unmodeled stack update", "unsupported addl memory destination"),
             (WRAPPER, "handoff stack copy", ((*WRAPPER_COPY_MUTATION, None),),
              "wrapper source reads a different object field", None),
             (WRAPPER, "handoff via r10d", WRAPPER_REGISTER_MUTATIONS,
              "wrapper source reads a different object field", None),
             (WRAPPER, "parent before first spill", ((*WRAPPER_ENTRY_MUTATION, None),),
              "entry argument %rdx changes before its first spill",
              "entry spill changed before immutable capture")]
    for owner, label, patches, fragment, old_refusal in cases:
        changed_object, changed_image = paired_mutations(
            inputs["object"], inputs["image"], codes[owner], owner, patches)
        with TemporaryDirectory(dir=build) as directory:
            temporary = Path(directory)
            image_path = temporary / "changed.dll"
            object_path = temporary / "changed.obj"
            receipt_path = temporary / "changed.builder.json"
            old_output = temporary / "old.final.json"
            new_output = temporary / "new.final.json"
            image_path.write_bytes(changed_image)
            object_path.write_bytes(changed_object)
            changed_inputs = inputs.copy()
            changed_inputs["image"] = changed_image
            changed_inputs["object"] = changed_object
            receipt_path.write_bytes(create_receipt(changed_inputs))
            assert verify_receipt(receipt_path.read_bytes(), changed_inputs)["verified"] is True
            changed_codes = codes.copy()
            changed_codes[owner] = owner_code(objdump, image_path, owner)
            refused(f"{owner} paired {label}", lambda: verify_builder_original_predicates(
                changed_object, changed_image, inputs["report"], inputs["input_ir"],
                inputs["plan"], changed_codes), fragment)
            base_command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
                            str(objdump), str(image_path), str(paths["report"]),
                            "--post-mixed-plan", str(paths["plan"]),
                            "--post-mixed-private", str(paths["private"]),
                            "--post-mixed-material", str(demo / "release-material.private.json"),
                            "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
                            "--builder-receipt", str(receipt_path),
                            "--builder-input-ir", str(paths["input_ir"]),
                            "--builder-object", str(object_path),
                            "--builder-subjects", "--builder-entry-states"]
            old = subprocess.run(base_command + ["--output", str(old_output)],
                                 capture_output=True, text=True, check=False)
            if old_refusal is None:
                assert old.returncode == 0 and old_output.is_file(), old.stderr
            else:
                assert (old.returncode != 0 and not old_output.exists() and
                        old_refusal in old.stderr), old.stderr
            new_output.write_text("stale", encoding="ascii")
            updated = subprocess.run(base_command + ["--output", str(new_output),
                                                    "--builder-original-predicates"],
                                     capture_output=True, text=True, check=False)
            expected_reason = "builder original-predicate proof failed" if old_refusal is None else old_refusal
            assert (updated.returncode != 0 and not new_output.exists() and
                    expected_reason in updated.stderr and
                    "builder receipt verification failed" not in updated.stderr and
                    "builder subject proof failed" not in updated.stderr), updated.stderr
    ir = inputs["input_ir"].decode("utf-8")
    for owner, original, replacement in ((OWNER, "icmp slt i32", "icmp sgt i32"),
                                         (WRAPPER, "icmp ne i64", "icmp eq i64")):
        begin = ir.index(f"@{owner}(")
        end = ir.index("\n}", begin)
        body = ir[begin:end]
        assert body.count(original) == 1
        changed_ir = (ir[:begin] + body.replace(original, replacement, 1) + ir[end:]).encode("utf-8")
        with TemporaryDirectory(dir=build) as directory:
            receipt_path = Path(directory) / "changed.builder.json"
            changed_inputs = inputs.copy()
            changed_inputs["input_ir"] = changed_ir
            receipt_path.write_bytes(create_receipt(changed_inputs))
            assert verify_receipt(receipt_path.read_bytes(), changed_inputs)["verified"] is True
            refused(f"{owner} valid IR polarity change", lambda: verify_builder_original_predicates(
                inputs["object"], inputs["image"], inputs["report"], changed_ir,
                inputs["plan"], codes), "unmodeled original predicate")
    print("builder original predicates: none linked positive; five paired receipt-refrozen COFF/PE mutants old-admitted/new-refused, two source mutants refused by older joint-machine gate")


def check_o2(build):
    _, _, inputs, _, codes = current_inputs(build)
    instructions = _instructions(codes[OWNER], inputs["image"], OWNER)
    candidates = [(index, item) for index, item in enumerate(instructions) if
                  item.opcode == "cmpl" and item.operands == ("%r9d", "%r8d") and
                  instructions[index + 1].opcode == "cmovll"]
    assert len(candidates) == 1
    index, _ = candidates[0]
    assert any(item.opcode == "movl" and item.operands[1] == "%r9d" and
               "(%rip)" in item.operands[0] for item in instructions[:index])
    refused("optimized/archive publication operand", lambda: verify_builder_original_predicates(
        inputs["object"], inputs["image"], inputs["report"], inputs["input_ir"],
        inputs["plan"], codes), "unmodeled original predicate")
    print("builder original predicates: O2/archive RIP-relative publication comparison refused closed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("none_build", type=Path)
    parser.add_argument("--o2-archive-build", type=Path)
    args = parser.parse_args()
    check_none(args.none_build)
    if args.o2_archive_build: check_o2(args.o2_archive_build)


if __name__ == "__main__":
    main()
