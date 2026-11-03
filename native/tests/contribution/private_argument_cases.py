"""Actual linked schema4 PE mutations for private helper identity arguments."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from cff_contribution_policy import check_source_mixed_private_policy
from cff_joint_machine_evidence import Instruction, _instructions
from cff_source_mixed_arguments import _states
from cff_source_mixed_site_map import check_two_site_map
from linked_machine_mutations import _replace, _unique
from pe_layout import parse_image


def check_private_arguments(checker, binary, report, private, successful_final,
                            directory, objdump, run):
    raw = private.read_bytes()
    original_report = report.read_bytes()
    document = json.loads(original_report)
    identity = check_source_mixed_private_policy(raw, document)
    if (identity.owner, identity.routing_tag, identity.domain, identity.owner_id) != (
            "mixed_site_body", 0x1020, 1, 7) or len(identity._fields) != 4:
        raise AssertionError("private argument projection exposed or lost a field")
    image = binary.read_bytes()
    layout = parse_image(image)
    code = subprocess.check_output([str(objdump), "-d",
        "--disassemble-symbols=mixed_site_body", str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, "mixed_site_body")
    calls = [item for item in instructions if item.opcode == "callq" and
             "<pyobf_native_mixed_" in item.operands[0]]
    if len(calls) != 5:
        raise AssertionError("private argument PE fixture lost its five helpers")
    first = calls[0]
    choices = (("routing_tag", "$0x1020", "%edx", 0x1021),
               ("domain", "$0x1", "%r8d", 2),
               ("owner_id", "$0x7", "%r9d", 8))

    def refuse(label, changed, policy=private, coverage=report, reason="source-mixed private arguments"):
        changed_image = directory / f"private-argument-{label}.exe"
        changed_image.write_bytes(changed)
        final = directory / f"private-argument-{label}.final.json"
        final.write_bytes(successful_final.read_bytes())
        denied = run([*checker, changed_image, coverage, "--contribution-input", policy,
                      "--output", final], succeeds=False)
        if final.exists() or reason not in denied.stderr:
            raise AssertionError(f"private argument mutation escaped {label}: {denied.stderr}")
        print(f"actual linked private argument refused: {label}")
        return changed_image

    for field, before, register, value in choices:
        instruction = _unique(instructions, lambda item: item.opcode == "movl" and
            item.operands == (before, register) and first.address - 64 < item.address < first.address,
            f"first helper {field} setup")
        if instruction.raw[-4:] != struct.pack("<I", int(before[1:], 0)):
            raise AssertionError(f"{field} setup lost its actual imm32")
        changed = _replace(image, layout, instruction,
                           instruction.raw[:-4] + struct.pack("<I", value))
        changed_image = refuse(field, changed, reason=f"helper {field}")
        if field == "owner_id":
            changed_code = subprocess.check_output([str(objdump), "-d",
                "--disassemble-symbols=mixed_site_body", str(changed_image)],
                text=True, timeout=20).lower()
            proof = next(row["runtime_contribution"] for row in document["functions"]
                         if row.get("function") == "mixed_site_body")
            check_two_site_map(changed_code, proof, "mixed_site_body", changed)
            print("old linked site/source map accepts the owner-id PE mutant")

    unknown = _unique(instructions, lambda item: item.opcode == "movl" and
        item.operands == ("$0x7", "%r9d") and first.address - 64 < item.address < first.address,
        "first helper owner setup")
    # 41 89 c1 is movl %eax,%r9d; the old immediate and the new instruction
    # occupy the same exact PE interval after NOP padding.
    refuse("unknown-owner", _replace(image, layout, unknown,
           bytes.fromhex("41 89 c1")), reason="helper owner_id")
    refuse("skipped-owner", _replace(image, layout, unknown,
           b"\x90" * len(unknown.raw)), reason="helper owner_id")
    refuse("wide-owner", _replace(image, layout, unknown,
           bytes.fromhex("49 89 c1")), reason="helper owner_id")
    # Partial-width lowering is outside the admitted machine instruction set.
    refuse("partial-owner", _replace(image, layout, unknown,
           bytes.fromhex("66 41 b9 08 00")), reason="unsupported instruction movw")

    paired_policy = json.loads(raw)
    paired_policy["owners"]["mixed_site_body"] = 8
    paired_raw = json.dumps(paired_policy).encode()
    paired_path = directory / "private-argument-paired.private.json"
    paired_path.write_bytes(paired_raw)
    paired_report = copy.deepcopy(document)
    proof = next(row["runtime_contribution"] for row in paired_report["functions"]
                 if row.get("function") == "mixed_site_body")
    proof["private_input_sha256"] = hashlib.sha256(paired_raw).hexdigest()
    paired_report_path = directory / "private-argument-paired.coverage.json"
    paired_report_path.write_text(json.dumps(paired_report))
    refuse("paired-policy", image, paired_path, paired_report_path, "helper owner_id")
    if private.read_bytes() != raw or report.read_bytes() != original_report:
        raise AssertionError("private argument fixture modified original policy/report")

    diamond = [Instruction(index, b"\x90", opcode, operands) for index, opcode, operands in (
        (0, "jae", ("0x2",)), (1, "movl", ("$7", "%r9d")),
        (2, "movl", ("$8", "%r9d")), (3, "callq", ("0x100",)))]
    states = _states(diamond, {0: (1, 2), 1: (3,), 2: (3,), 3: ()})
    if "r9" in states[3].registers:
        raise AssertionError("conflicting CFG predecessors invented a private owner constant")
