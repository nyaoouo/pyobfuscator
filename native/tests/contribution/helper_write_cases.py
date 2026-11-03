"""Actual linked helper write mutations and bounded frame-analysis negatives."""

import struct
import subprocess

from cff_joint_machine_evidence import Instruction, MEASURED, OWNED, _instructions
from cff_source_mixed_helper_writes import _check_instructions, check_helper_direct_writes
from linked_machine_mutations import _replace
from pe_layout import parse_image


def _refuse_instructions(instructions, reason):
    try:
        _check_instructions(instructions)
    except ValueError as error:
        if reason not in str(error):
            raise AssertionError(f"helper refusal has wrong reason: {error}") from error
    else:
        raise AssertionError(f"helper {reason} escaped")


def check_helper_internal_cases():
    alias = (
        Instruction(100, bytes.fromhex("53"), "pushq", ("%rbx",)),
        Instruction(101, bytes.fromhex("48 83 ec 40"), "subq", ("$0x40", "%rsp")),
        Instruction(105, bytes.fromhex("4c 8d 44 24 50"), "leaq", ("0x50(%rsp)", "%r8")),
        Instruction(110, bytes.fromhex("49 89 00"), "movq", ("%rax", "(%r8)")),
    )
    _refuse_instructions(alias, "directly writes caller or return stack")

    unknown = alias[:2] + (
        Instruction(105, bytes.fromhex("49 89 02"), "movq", ("%rax", "(%r10)")),)
    _refuse_instructions(unknown, "unproved direct memory write")

    conditional_store = alias[:2] + (
        Instruction(105, bytes.fromhex("0f 95 44 24 48"), "setne", ("0x48(%rsp)",)),)
    _refuse_instructions(conditional_store, "unsupported register operation")

    adjustment = (
        Instruction(100, bytes.fromhex("48 89 c4"), "movq", ("%rax", "%rsp")),)
    _refuse_instructions(adjustment, "unknown stack adjustment")

    merge = alias[:2] + (
        Instruction(105, bytes.fromhex("74 06"), "je", ("0x71",)),
        Instruction(107, bytes.fromhex("48 83 c4 10"), "addq", ("$0x10", "%rsp")),
        Instruction(111, bytes.fromhex("eb 00"), "jmp", ("0x71",)),
        Instruction(113, bytes.fromhex("89 44 24 20"), "movl", ("%eax", "0x20(%rsp)")),
        Instruction(117, bytes.fromhex("cc"), "int3", ()),
    )
    _refuse_instructions(merge, "ambiguous CFG merge")

    hidden = (
        Instruction(100, bytes.fromhex("c3"), "retq", ()),
        Instruction(101, bytes.fromhex("89 84 24 f0 00 00 00"),
                    "movl", ("%eax", "0xf0(%rsp)")),
    )
    _refuse_instructions(hidden, "unvisited executable instructions")


def check_helper_write_mutations(checker, binary, report, private, directory, objdump):
    check_helper_internal_cases()
    image = binary.read_bytes()
    layout = parse_image(image)
    codes = {name: subprocess.check_output(
        [str(objdump), "-d", f"--disassemble-symbols={name}", str(binary)],
        text=True, timeout=20).lower() for name in (OWNED, MEASURED)}
    check_helper_direct_writes(image, codes)
    owned = _instructions(codes[OWNED], image, OWNED)
    target = [item for item in owned if item.raw == bytes.fromhex("48 8b 8c 24 b8 00 00 00")
              and item.opcode == "movq" and item.operands == ("0xb8(%rsp)", "%rcx")]
    if len(target) != 1:
        raise AssertionError("owned helper mutation anchor changed")
    anchor = target[0]
    for label, displacement, reason in (
            ("caller-scope", 0xf0, "directly writes caller or return stack"),
            ("return-overlap", 0x79, "directly writes caller or return stack"),
            ("below-frame", -1, "writes below its reserved stack frame")):
        changed = bytes.fromhex("48 89 84 24") + struct.pack("<i", displacement)
        mutant = directory / f"helper-{label}.exe"
        mutant.write_bytes(_replace(image, layout, anchor, changed))
        final = directory / f"helper-{label}.final.json"
        final.write_text("stale final output")
        result = subprocess.run([*map(str, checker), str(mutant), str(report),
                                 "--contribution-input", str(private), "--output", str(final)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 or final.exists() or reason not in result.stderr:
            raise AssertionError(f"linked helper {label} escaped bounded gate: {result.stderr}")
        print(f"actual linked helper {label} refused: {result.stderr.strip()}")

    tampered = dict(codes)
    tampered[OWNED] = tampered[OWNED].replace("48 8b 8c 24 b8 00 00 00",
                                             "48 8b 8c 24 b9 00 00 00", 1)
    try:
        check_helper_direct_writes(image, tampered)
    except ValueError as error:
        if "disassembly bytes differ from actual PE image" not in str(error):
            raise AssertionError(f"helper byte mismatch lacked bounded reason: {error}") from error
    else:
        raise AssertionError("tampered helper disassembly escaped exact PE check")
