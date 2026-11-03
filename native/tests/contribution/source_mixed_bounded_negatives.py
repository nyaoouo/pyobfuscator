"""Mutate the frozen N-edge artifacts and actual linked PE, clearing stale output."""

import copy
from collections import deque
import json
from pathlib import Path
import struct
import subprocess

from cff_build import run
from cff_joint_machine_evidence import (DIRECT, OWNED, State, _dispatcher_state,
                                        _entry_spills, _graph, _instructions, _join, _transfer)
from cff_source_mixed_bounded_dispatcher import _leaf_groups
from cff_source_mixed_bounded_numeric import check_numeric_sensitivity
from linked_machine_mutations import _jump, _replace, _replace_range, _retarget_call
from pe_layout import parse_image


def _refuse(command, output, reason=None):
    output.write_text("stale final output")
    result = run([*command, "--output", output], succeeds=False)
    if output.exists() or reason is not None and reason not in result.stderr:
        raise AssertionError(f"bounded edge mutation was accepted {reason!r}: {result.stderr}")


def _write(directory, name, document):
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def check_artifacts(checker, objdump, binary, report, private, plan, directory, owner,
                    saturation=False):
    base = [*checker, binary, report, "--contribution-input", private,
            "--source-mixed-bounded-edges", plan]
    changed = copy.deepcopy(json.loads(plan.read_text()))
    changed["owners"][0]["edges"][0]["label"] += 1
    bad_plan = _write(directory, "bad-plan.json", changed)
    _refuse([*checker, binary, report, "--contribution-input", private,
             "--source-mixed-bounded-edges", bad_plan], directory / "bad-plan.final.json",
            "plan bytes differ")
    changed = copy.deepcopy(json.loads(plan.read_text()))
    changed["input_ir_sha256"] = "0" * 64
    bad_ir = _write(directory, "bad-ir-plan.json", changed)
    _refuse([*checker, binary, report, "--contribution-input", private,
             "--source-mixed-bounded-edges", bad_ir], directory / "bad-ir.final.json",
            "plan bytes differ")
    changed = copy.deepcopy(json.loads(report.read_text()))
    row = next(item for item in changed["functions"] if item.get("function") == owner)
    reported_edges = row["runtime_contribution"]["original_edges"]["edges"]
    reported_edges[0]["dispatch_state"] = reported_edges[1]["dispatch_state"]
    bad_state = _write(directory, "bad-state-report.json", changed)
    _refuse([*checker, binary, bad_state, "--contribution-input", private,
             "--source-mixed-bounded-edges", plan], directory / "bad-state.final.json")
    changed = copy.deepcopy(json.loads(private.read_text()))
    labels = list(changed["bindings"][owner]["sites"])
    rules = changed["bindings"][owner]["sites"]
    rules[labels[0]], rules[labels[1]] = rules[labels[1]], rules[labels[0]]
    bad_private = _write(directory, "swapped-private.json", changed)
    _refuse([*checker, binary, report, "--contribution-input", bad_private,
             "--source-mixed-bounded-edges", plan], directory / "swapped-private.final.json")

    image = binary.read_bytes()
    layout = parse_image(image)
    code = subprocess.check_output([str(objdump), "-d", f"--disassemble-symbols={owner}",
                                    str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, owner)
    helpers = [item for item in instructions if item.opcode in ("call", "callq") and
               "<pyobf_native_mixed_" in item.operands[0]]
    sites = next(item["runtime_contribution"]["sites"] for item in
                 json.loads(report.read_text())["functions"] if item.get("function") == owner)
    if len(helpers) != sum(len(site["sources"]) for site in sites):
        raise AssertionError("linked fixture lost bounded helper calls")
    label = sites[0]["label"]
    site_stores = [item for item in instructions if item.opcode == "movl" and
                   len(item.operands) == 2 and item.operands[1] == "0x20(%rsp)" and
                   item.operands[0].startswith("$0x") and
                   int(item.operands[0][1:], 0) == label and
                   item.raw[-4:] == struct.pack("<I", label)]
    if not site_stores:
        raise AssertionError("linked fixture lost planned site immediate")
    replacement = next(site["label"] for site in sites if site["label"] != label)
    changed_site = _replace(image, layout, site_stores[0],
                            site_stores[0].raw[:-4] + struct.pack("<I", replacement))
    target = int(DIRECT.fullmatch(helpers[1].operands[0])[1], 16)
    changed_helper = _replace(image, layout, helpers[0], _retarget_call(helpers[0], target))
    first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
    dispatcher = int(DIRECT.fullmatch(first_branch.operands[0])[1], 16)
    state_init = next(item for item in instructions if item.address < first_branch.address and
                      item.opcode == "movl" and item.operands[0].startswith("$0x") and
                      item.operands[1].endswith("(%rsp)"))
    state_stores = [item for item in instructions if helpers[-1].address < item.address < dispatcher and
                    item.opcode == "movl" and item.operands[-1] == state_init.operands[1]]
    if not state_stores:
        raise AssertionError("linked fixture lost final bounded state update")
    missing_state = _replace(image, layout, state_stores[0], b"\x90")
    by_address, graph, _ = _graph(instructions)
    group_calls = {}
    cursor = 0
    for index, site in enumerate(sites):
        for _ in site["sources"]:
            group_calls[helpers[cursor].address] = index
            cursor += 1
    leaves = {}
    for item in instructions:
        if item.address < dispatcher or item.opcode not in ("jmp", "jmpq"):
            continue
        target = int(DIRECT.fullmatch(item.operands[0])[1], 16)
        membership = _leaf_groups(target, dispatcher, by_address, graph, group_calls)
        if len(membership) == 1:
            group, = membership
            leaves[group] = (item, target)
    if len(leaves) != len(sites):
        raise AssertionError("linked bounded fixture lost distinct helper leaves")
    left, left_target = leaves[0]
    right, right_target = leaves[1]
    if any(len(item.raw) != 5 for item in (left, right)):
        raise AssertionError("bounded helper leaves are not rel32 jumps")
    swapped_leaves = _replace(image, layout, left, _jump(left, right_target))
    swapped_leaves = _replace(swapped_leaves, layout, right, _jump(right, left_target))
    helper_code = subprocess.check_output([str(objdump), "-d",
        f"--disassemble-symbols={OWNED}", str(binary)], text=True, timeout=20).lower()
    body = _instructions(helper_code, image, OWNED)
    calls = [item for item in body if item.opcode in ("call", "callq")]
    if len(calls) < 2:
        raise AssertionError("linked owned helper lost binding/query calls")
    bypass_binding = _replace(image, layout, calls[0], _jump(calls[0], calls[1].address))
    stack_frame = next((item for item in body if item.opcode == "subq" and
                        item.operands[-1] == "%rsp"), None)
    if stack_frame is None:
        raise AssertionError("linked helper has no bounded stack allocation")
    direct_stack_write = _replace(image, layout, stack_frame, b"\x90")
    mutants = (("site-immediate", changed_site), ("helper-result-redirect", changed_helper),
               ("missing-state", missing_state), ("swapped-leaves", swapped_leaves),
               ("helper-binding-bypass", bypass_binding),
               ("helper-direct-stack", direct_stack_write))
    for name, payload in mutants:
        mutated = directory / f"{name}.exe"
        mutated.write_bytes(payload)
        _refuse([*checker, mutated, report, "--contribution-input", private,
                 "--source-mixed-bounded-edges", plan], directory / f"{name}.final.json")
    if saturation:
        # This fixture has a result-copy span in the first gateway. Make it a
        # spare constant word and OR it into the fully mixed state immediately
        # before the unique dispatcher write. A numeric proof that guesses an
        # arbitrary value for this slot would falsely accept these PE bytes.
        measured = next(index for index, item in enumerate(instructions) if
                        item.address == helpers[1].address)
        copy_span = instructions[measured + 3:measured + 5]
        if ([item.opcode for item in copy_span] != ["movl", "movl"] or
                copy_span[1].operands[-1] != "0x78(%rsp)" or
                sum(len(item.raw) for item in copy_span) != 11):
            raise AssertionError("saturation mutant lost its result-copy code interval")
        final_write = next(index for index, item in enumerate(instructions) if
                           item.address > helpers[1].address and
                           item.opcode == "movl" and
                           item.operands[-1] == state_init.operands[1])
        mix_span = instructions[final_write - 5:final_write]
        if ([item.opcode for item in mix_span] !=
                ["movl", "shrl", "xorl", "xorl", "addl"] or
                sum(len(item.raw) for item in mix_span) != 14):
            raise AssertionError("saturation mutant lost its final state-mix interval")
        frame, spills = _entry_spills(instructions)
        dispatcher_slot = _dispatcher_state(instructions, graph, frame)
        _transfer.entry = instructions[0].address
        states = {instructions[0].address: State(0, {"rcx": "lease", "rdx": "scope"},
            {}, {}, {}, {}, {}, 0)}
        pending = deque((instructions[0].address,))
        while pending:
            address = pending.popleft()
            state = _transfer(by_address[address], states[address], frame, spills)
            for successor in graph[address]:
                prior = states.get(successor)
                merged = state if prior is None else _join(prior, state)
                if prior != merged:
                    states[successor] = merged
                    pending.append(successor)
        for kind, writer in (("movq", b"\x48\xc7\x44\x24\x78\xff\xff\xff\xff"),
                             ("movl", b"\xc7\x44\x24\x78\xff\xff\xff\xff")):
            changed = _replace_range(image, layout, copy_span,
                                     writer + b"\x90" * (11 - len(writer)))
            changed = _replace_range(changed, layout, mix_span,
                                     b"\x31\xd1\x01\xc8\x0b\x44\x24\x78" + b"\x90" * 6)
            mutant = directory / f"saturated-{kind}.exe"
            mutant.write_bytes(changed)
            _refuse([*checker, mutant, report, "--contribution-input", private,
                     "--source-mixed-bounded-edges", plan],
                    directory / f"saturated-{kind}.final.json")
            mutated_code = subprocess.check_output([str(objdump), "-d",
                f"--disassemble-symbols={owner}", str(mutant)], text=True,
                timeout=20).lower()
            mutated_instructions = _instructions(mutated_code, changed, owner)
            _, mutated_graph, _ = _graph(mutated_instructions)
            try:
                check_numeric_sensitivity(mutated_instructions, mutated_graph,
                    helpers[:2], states[helpers[0].address], frame, dispatcher,
                    dispatcher_slot)
            except ValueError as error:
                if "numeric sensitivity:" not in str(error):
                    raise AssertionError("saturation mutant failed outside numeric proof") from error
                print(f"saturated {kind} numeric proof refused: {error}", flush=True)
            else:
                raise AssertionError("constant spare word hid both helper returns")
