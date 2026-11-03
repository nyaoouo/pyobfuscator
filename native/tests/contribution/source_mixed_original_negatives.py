"""Mutate actual schema4 original-edge artifacts and require a cleared final output."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from cff_build import run
from cff_joint_machine_evidence import DIRECT, _graph, _instructions
from cff_source_mixed_dispatcher import _leaf_groups
from linked_machine_mutations import _replace
from pe_layout import parse_image


def _refuse(command, output, reason=None):
    output.write_text("stale final output")
    result = run([*command, "--output", output], succeeds=False)
    if output.exists() or (reason is not None and reason not in result.stderr):
        raise AssertionError(f"expected original-edge rejection {reason!r}: {result.stderr}")


def check_artifacts(checker, objdump, binary, report, private, plan, final,
                    directory, owner):
    base = [*checker, binary, report, "--contribution-input", private,
            "--source-mixed-original-edges", plan]
    _refuse([*checker, binary, report, "--contribution-input", private],
            directory / "default.final.json", "source-mixed contribution acquisition is unsupported")
    changed_plan = copy.deepcopy(json.loads(plan.read_text()))
    changed_plan["edges"][0]["label"] += 1
    bad_plan = directory / "bad-plan.json"
    bad_plan.write_text(json.dumps(changed_plan))
    _refuse([*checker, binary, report, "--contribution-input", private,
             "--source-mixed-original-edges", bad_plan],
            directory / "bad-plan.final.json", "plan bytes differ")
    changed_plan["edges"][0]["label"] -= 1
    changed_plan["input_ir_sha256"] = "0" * 64
    bad_ir_plan = directory / "bad-ir-sha-plan.json"
    bad_ir_plan.write_text(json.dumps(changed_plan))
    _refuse([*checker, binary, report, "--contribution-input", private,
             "--source-mixed-original-edges", bad_ir_plan],
            directory / "bad-ir-sha-plan.final.json", "plan bytes differ")
    changed_report_identity = copy.deepcopy(json.loads(report.read_text()))
    changed_report_identity["original_edge_plan_sha256"] = "0" * 64
    bad_identity_report = directory / "bad-plan-identity-report.json"
    bad_identity_report.write_text(json.dumps(changed_report_identity))
    _refuse([*checker, binary, bad_identity_report, "--contribution-input", private,
             "--source-mixed-original-edges", plan],
            directory / "bad-plan-identity-report.final.json", "plan bytes differ")
    del changed_report_identity["original_edge_plan_sha256"]
    missing_identity_report = directory / "missing-plan-identity-report.json"
    missing_identity_report.write_text(json.dumps(changed_report_identity))
    _refuse([*checker, binary, missing_identity_report, "--contribution-input", private,
             "--source-mixed-original-edges", plan],
            directory / "missing-plan-identity-report.final.json", "plan bytes differ")
    changed_report = copy.deepcopy(json.loads(report.read_text()))
    proof = next(item["runtime_contribution"] for item in changed_report["functions"]
                 if item.get("function") == owner)
    proof["original_edges"]["edges"][0]["point"] += 1
    bad_report = directory / "bad-report.json"
    bad_report.write_text(json.dumps(changed_report))
    _refuse([*checker, binary, bad_report, "--contribution-input", private,
             "--source-mixed-original-edges", plan], directory / "bad-report.final.json")
    changed_private = copy.deepcopy(json.loads(private.read_text()))
    changed_private["routing_tag"] += 1
    bad_private = directory / "bad-private.json"
    bad_private.write_text(json.dumps(changed_private))
    _refuse([*checker, binary, report, "--contribution-input", bad_private,
             "--source-mixed-original-edges", plan],
            directory / "bad-private.final.json", "raw input SHA-256 differs")
    paired_private = copy.deepcopy(json.loads(private.read_text()))
    paired_report = copy.deepcopy(json.loads(report.read_text()))
    paired_proof = next(item["runtime_contribution"] for item in paired_report["functions"]
                        if item.get("function") == owner)
    rules = paired_private["bindings"][owner]["sites"]
    label = min(map(int, rules))
    replacement = label + 1 if str(label + 1) not in rules else label - 1
    rule = rules.pop(str(label))
    rules[str(replacement)] = rule
    paired_policy = directory / "paired-private.json"
    paired_policy.write_text(json.dumps(paired_private))
    paired_proof["private_input_sha256"] = hashlib.sha256(paired_policy.read_bytes()).hexdigest()
    next(site for site in paired_proof["sites"] if site["label"] == label)["label"] = replacement
    paired_proof["sites"].sort(key=lambda site: site["label"])
    for index, site in enumerate(paired_proof["sites"]):
        site["index"] = index
    edge = next(edge for edge in paired_proof["original_edges"]["edges"]
                if edge["point"] == label)
    edge["point"] = replacement
    edge["canonical_point"] = replacement
    paired = directory / "paired-report.json"
    paired.write_text(json.dumps(paired_report))
    _refuse([*checker, binary, paired, "--contribution-input", paired_policy,
             "--source-mixed-original-edges", plan], directory / "paired.final.json")
    image = binary.read_bytes()
    code = subprocess.check_output([str(objdump), "-d", f"--disassemble-symbols={owner}",
                                    str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, owner)
    layout = parse_image(image)
    helpers = [item for item in instructions if item.opcode == "callq" and
               "<pyobf_native_mixed_" in item.operands[0]]
    if len(helpers) != 5:
        raise AssertionError("linked fixture lost five mixed helper calls")
    site_stores = [item for item in instructions if item.opcode == "movl" and
                   len(item.operands) == 2 and item.operands[1] == "0x20(%rsp)" and
                   item.operands[0].startswith("$0x") and
                   int(item.operands[0][1:], 0) == label]
    if not site_stores:
        raise AssertionError("linked fixture lost planned site immediates")
    selected = site_stores[0]
    if selected.raw[-4:] != struct.pack("<I", label):
        raise AssertionError("linked site immediate is not a decoded uint32")
    changed_site = _replace(image, layout, selected,
                            selected.raw[:-4] + struct.pack("<I", replacement))
    first_branch = next(item for item in instructions if item.opcode == "jmp")
    dispatcher = int(DIRECT.fullmatch(first_branch.operands[0])[1], 16)
    state_init = next(item for item in instructions if item.address < first_branch.address and
                      item.opcode == "movl" and item.operands[0].startswith("$0x") and
                      item.operands[1].endswith("(%rsp)"))
    state_stores = [item for item in instructions if helpers[-1].address < item.address < dispatcher and
                    item.opcode == "movl" and item.operands[-1] == state_init.operands[1]]
    if len(state_stores) != 2:
        raise AssertionError("linked fixture lost final group and original branch state updates")
    missing_state = _replace(image, layout, state_stores[0], b"\x90")
    by_address, graph, _ = _graph(instructions)
    group_calls = {item.address: 0 if index < 3 else 1
                   for index, item in enumerate(helpers)}
    leaves = {}
    for item in instructions:
        if item.address < dispatcher or item.opcode not in ("jmp", "jmpq"):
            continue
        target = int(DIRECT.fullmatch(item.operands[0])[1], 16)
        membership = _leaf_groups(target, dispatcher, by_address, graph, group_calls)
        if len(membership) == 1:
            (group,) = membership
            if group in leaves:
                raise AssertionError("linked fixture has ambiguous helper-group leaves")
            leaves[group] = (item, target)
    if set(leaves) != {0, 1} or any(len(item.raw) != 5 or item.raw[0] != 0xe9
                                    for item, _ in leaves.values()):
        raise AssertionError("linked fixture lacks two rel32 helper-group leaves")
    left, left_target = leaves[0]
    right, right_target = leaves[1]
    def jump(item, target):
        return b"\xe9" + struct.pack("<i", target - item.address - 5)
    swapped_leaves = _replace(image, layout, left, jump(left, right_target))
    swapped_leaves = _replace(swapped_leaves, layout, right, jump(right, left_target))
    mutants = (("site-immediate", changed_site),
               ("missing-last-state", missing_state),
               ("missing-helper", _replace(image, layout, helpers[-1], b"\x90")),
               ("swapped-dispatch-leaves", swapped_leaves))
    for name, changed in mutants:
        mutant = directory / f"{name}.exe"
        mutant.write_bytes(changed)
        _refuse([*checker, mutant, report, "--contribution-input", private,
                 "--source-mixed-original-edges", plan], directory / f"{name}.final.json",
                "planned original edge state reaches a different linked helper group"
                if name == "swapped-dispatch-leaves" else None)
    (directory / "missing-last-state.exe").write_bytes(missing_state)
    _refuse([*checker, directory / "missing-last-state.exe", report,
             "--contribution-input", private, "--source-mixed-original-edges", plan], final)
    print("original-edge plan, private/report and exact-PE bypasses refused", flush=True)
