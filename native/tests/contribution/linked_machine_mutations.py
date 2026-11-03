"""Mutate the actual linked PE instruction stream for the G2e final gate."""

from __future__ import annotations

import json
import struct
import subprocess

from cff_joint_machine_evidence import DIRECT, Instruction, MEASURED, OWNED, _instructions, verify_joint_machine
from cff_source_mixed_site_map import check_two_site_map
from pe_layout import data_directory, parse_image, read_rva, rva_section


def _unique(instructions, predicate, label):
    matches = [item for item in instructions if predicate(item)]
    if len(matches) != 1:
        raise AssertionError(f"linked PE mutation needs one {label}, found {len(matches)}")
    return matches[0]


def _replace(image, layout, instruction, payload):
    if len(payload) > len(instruction.raw): raise AssertionError("mutation exceeds original instruction")
    result = bytearray(image)
    rva = instruction.address - layout.preferred_base
    section = rva_section(layout, rva, len(instruction.raw), logical=True)
    offset = section.raw_offset + rva - section.rva
    if bytes(result[offset:offset + len(instruction.raw)]) != instruction.raw:
        raise AssertionError("mutation no longer addresses the actual PE instruction")
    result[offset:offset + len(instruction.raw)] = payload + b"\x90" * (len(instruction.raw) - len(payload))
    return bytes(result)


def _jump(origin, destination):
    return b"\xe9" + struct.pack("<i", destination - origin.address - 5)


def _retarget_call(origin, destination):
    if not origin.raw.startswith(b"\xe8") or len(origin.raw) != 5:
        raise AssertionError("joint helper call is not rel32")
    return b"\xe8" + struct.pack("<i", destination - origin.address - 5)


def _call(origin, destination):
    return b"\xe8" + struct.pack("<i", destination - origin.address - 5)


def _replace_range(image, layout, items, payload):
    start = items[0].address
    raw = b"".join(item.raw for item in items)
    if any(left.address + len(left.raw) != right.address for left, right in zip(items, items[1:])):
        raise AssertionError("mutation range is not one continuous PE instruction span")
    if len(raw) != len(payload): raise AssertionError("mutation range changed instruction extent")
    section = rva_section(layout, start - layout.preferred_base, len(raw), logical=True)
    offset = section.raw_offset + start - layout.preferred_base - section.rva
    result = bytearray(image)
    if bytes(result[offset:offset + len(raw)]) != raw:
        raise AssertionError("mutation range no longer matches linked PE bytes")
    result[offset:offset + len(raw)] = payload
    return bytes(result)


def check_two_site_linked_mutations(checker, binary, report, directory, objdump, run):
    """Mutate decoded site/source arguments and routes in the actual linked PE."""
    image = binary.read_bytes()
    layout = parse_image(image)
    code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                    str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, "mixed_site_body")
    helpers = [item for item in instructions if item.opcode == "callq" and
        any(name in item.operands[0] for name in ("<pyobf_native_mixed_owned_contribution_word_v1>",
                                                 "<pyobf_native_mixed_measured_contribution_word_v1>"))]
    if len(helpers) != 5:
        raise AssertionError("three-plus-two mutation fixture lost its five linked helpers")
    if [DIRECT.fullmatch(item.operands[0])[2] for item in helpers] != [
            MEASURED, OWNED, OWNED, OWNED, MEASURED]:
        raise AssertionError("linked 703-to-701 helper order no longer differs from canonical report order")
    site_stores = [item for item in instructions if item.opcode == "movl" and
        len(item.operands) == 2 and item.operands[1] == "0x20(%rsp)" and
        item.operands[0] in ("$0x2bd", "$0x2bf")]
    source_stores = [item for item in instructions if item.opcode == "movl" and
        len(item.operands) == 2 and item.operands[1] == "0x28(%rsp)" and
        item.operands[0] in ("$0xd", "$0x11", "$0x1d", "$0x25")]
    if len(site_stores) != 5 or len(source_stores) != 5:
        raise AssertionError("linked mutation fixture lost its five decoded immediate pairs")
    if [int(item.operands[0][1:], 0) for item in site_stores] != [703, 703, 701, 701, 701]:
        raise AssertionError("actual PE site order no longer opposes the canonical report order")

    def changed_immediates(items, substitutions):
        changed = image
        for item in items:
            before = int(item.operands[0][1:], 0)
            if before not in substitutions: continue
            if item.raw[-4:] != struct.pack("<I", before):
                raise AssertionError("mutation site does not carry the decoded final imm32")
            changed = _replace(changed, layout, item,
                item.raw[:-4] + struct.pack("<I", substitutions[before]))
        return changed

    mutations = [
        ("paired-site-label-swap", changed_immediates(site_stores, {701: 703, 703: 701}),
         "wrong ordered source providers"),
        ("paired-source-word-swap", changed_immediates(source_stores, {13: 37, 37: 13}),
         "wrong ordered source providers"),
        ("duplicate-site-group", changed_immediates(site_stores, {701: 703}),
         "missing, duplicate or ambiguous site groups"),
    ]
    measured_call = helpers[0]
    owned_call = helpers[2]
    measured_target = int(DIRECT.fullmatch(measured_call.operands[0])[1], 16)
    owned_target = int(DIRECT.fullmatch(owned_call.operands[0])[1], 16)
    swapped_helpers = _replace(image, layout, measured_call,
        _retarget_call(measured_call, owned_target))
    swapped_helpers = _replace(swapped_helpers, layout, owned_call,
        _retarget_call(owned_call, measured_target))
    mutations.append(("paired-provider-swap", swapped_helpers, "wrong ordered source providers"))
    first_return_copy = _unique(instructions, lambda item: item.opcode == "movl" and
        item.operands == ("%eax", "%edx") and helpers[0].address < item.address < helpers[1].address,
        "first group measured return copy")
    if len(first_return_copy.raw) != 2:
        raise AssertionError("measured return detachment lacks a two-byte copy")
    mutations.append(("detached-first-return", _replace(image, layout, first_return_copy,
        bytes.fromhex("31 d2")), "detached or misrouted return-to-dispatcher"))
    mutations.append(("unknown-machine-instruction", _replace(image, layout, first_return_copy,
        bytes.fromhex("50 90")), "unsupported instruction pushq"))
    bypass = _unique(instructions, lambda item: item.opcode == "movl" and
        item.operands == ("$0x7", "%r9d") and helpers[0].address - 48 < item.address < helpers[0].address,
        "first group pre-argument setup")
    if len(bypass.raw) < 5:
        raise AssertionError("site-store CFG bypass lacks a five-byte instruction")
    mutations.append(("bypassed-site-store", _replace(image, layout, bypass,
        _jump(bypass, helpers[0].address)), "missing, bypassed or ambiguous site/source arguments"))
    first_exit = next(item for item in instructions if item.address > helpers[1].address and
        item.address < helpers[2].address and item.opcode in ("jmp", "jmpq"))
    before_second = max((item for item in instructions if item.address < helpers[2].address and
        item.opcode in ("jmp", "jmpq", "jae", "ret", "retq")), key=lambda item: item.address)
    second_setup = before_second.address + len(before_second.raw)
    mutations.append(("cross-site-return-route", _replace(image, layout, first_exit,
        _jump(first_exit, second_setup)), "detached or misrouted return-to-dispatcher"))
    state_store = _unique(instructions, lambda item: item.opcode == "movl" and
        len(item.operands) == 2 and item.operands[1] == "0xc4(%rsp)" and
        helpers[1].address < item.address < first_exit.address, "first group dispatcher state store")
    if b"\xc4\x00\x00\x00" not in state_store.raw:
        raise AssertionError("state-store mutation needs actual disp32 stack addressing")
    mutations.append(("decoy-return-state-slot", _replace(image, layout, state_store,
        state_store.raw.replace(b"\xc4\x00\x00\x00", b"\xc8\x00\x00\x00", 1)),
        "detached or misrouted return-to-dispatcher"))
    for label, changed_bytes, reason in mutations:
        changed = directory / f"two-linked-{label}.exe"; changed.write_bytes(changed_bytes)
        final = directory / f"two-linked-{label}.final.json"
        refused = run([*checker, changed, report, "--output", final], succeeds=False)
        if final.exists() or reason not in refused.stderr:
            raise AssertionError(f"actual linked site-map mutation escaped {label}: {refused.stderr}")
        print(f"actual two-site PE mutation refused: {label}")
    document = json.loads(report.read_text())
    proof = next(row["runtime_contribution"] for row in document["functions"]
        if row.get("function") == "mixed_site_body")
    entry_state = _unique(instructions, lambda item: item.opcode == "movl" and
        item.operands[0] == "$0x9f6a197" and item.operands[1] == "0xc4(%rsp)" and
        item.address < helpers[0].address, "entry state immediate for a dead site-label decoy")
    decoy = _replace(image, layout, entry_state, entry_state.raw[:-4] + struct.pack("<I", 705))
    decoy_image = directory / "two-linked-dead-decoy-label.exe"; decoy_image.write_bytes(decoy)
    forged = json.loads(report.read_text())
    forged_proof = next(row["runtime_contribution"] for row in forged["functions"]
        if row.get("function") == "mixed_site_body")
    forged_proof["sites"][1]["label"] = 705
    decoy_report = directory / "two-linked-dead-decoy-label.report.json"
    decoy_report.write_text(json.dumps(forged))
    decoy_final = directory / "two-linked-dead-decoy-label.final.json"
    refused = run([*checker, decoy_image, decoy_report, "--output", decoy_final], succeeds=False)
    if decoy_final.exists() or "contains an unknown site label" not in refused.stderr:
        raise AssertionError(f"dead numeric decoy was treated as a called site: {refused.stderr}")
    print("actual two-site PE dead label decoy and forged report refused")
    changed_bytes = _replace(image, layout, site_stores[0],
        site_stores[0].raw[:-4] + struct.pack("<I", 705))
    try:
        check_two_site_map(code, proof, "mixed_site_body", changed_bytes)
    except SystemExit as error:
        if "disassembly bytes differ from actual PE image" not in str(error):
            raise AssertionError(f"code/image mismatch gave an unrelated refusal: {error}")
    else:
        raise AssertionError("two-site map accepted disassembly from different PE bytes")
    pdata_rva, pdata_size = data_directory(layout, 3)
    pdata = read_rva(image, layout, pdata_rva, pdata_size)
    entry_rva = instructions[0].address - layout.preferred_base
    record = next((index for index in range(0, len(pdata), 12)
        if struct.unpack_from("<I", pdata, index)[0] == entry_rva), None)
    if record is None: raise AssertionError("linked two-site body has no exact unwind record")
    pdata_section = rva_section(layout, pdata_rva + record, 12, logical=True)
    pdata_offset = pdata_section.raw_offset + pdata_rva + record - pdata_section.rva
    _, end_rva, unwind_rva = struct.unpack_from("<III", pdata, record)
    short = bytearray(image)
    struct.pack_into("<I", short, pdata_offset + 4, end_rva - 1)
    unwind_section = rva_section(layout, unwind_rva, 1, logical=True)
    unwind_offset = unwind_section.raw_offset + unwind_rva - unwind_section.rva
    flagged = bytearray(image)
    flagged[unwind_offset] |= 0x08
    for label, changed_bytes in (("short-unwind-extent", short),
                                 ("forged-unwind-flags", flagged)):
        changed = directory / f"two-linked-{label}.exe"; changed.write_bytes(changed_bytes)
        final = directory / f"two-linked-{label}.final.json"
        refused = run([*checker, changed, report, "--output", final], succeeds=False)
        if final.exists() or "source-mixed linked site map" not in refused.stderr:
            raise AssertionError(f"actual PE unwind mutation escaped {label}: {refused.stderr}")
        print(f"actual two-site PE unwind mutation refused: {label}")


def check_linked_mutations(checker, binary, report, directory, objdump, run):
    image = binary.read_bytes()
    layout = parse_image(image)
    code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                    str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, "mixed_site_body")
    first = _unique(instructions, lambda item: item.opcode == "callq" and
                    "<pyobf_native_mixed_owned_contribution_word_v1>" in item.operands[0], "owned call")
    second = _unique(instructions, lambda item: item.opcode == "callq" and
                    "<pyobf_native_mixed_measured_contribution_word_v1>" in item.operands[0], "measured call")
    state_init = _unique(instructions, lambda item: item.opcode == "movl" and
                         item.operands[0].startswith("$0x9f6a197") and
                         item.address < first.address, "entry state initialization")
    entry_branch = min(item.address for item in instructions if item.opcode in ("jmp", "jmpq", "jae"))
    lease_spill = _unique(instructions, lambda item: item.opcode == "movq" and
                          item.operands[0] == "%rcx" and item.address < entry_branch and
                          item.operands[1].endswith("(%rsp)"), "entry lease spill")
    lease_offset = int(lease_spill.operands[1].split("(", 1)[0], 0)
    if not 0 <= lease_offset < 128: raise AssertionError("mutation needs a disp8 entry lease spill")
    setup_candidates = [item for item in instructions if item.opcode == "movq" and
                        len(item.operands) == 2 and item.operands[0].endswith("(%rsp)") and
                        item.operands[1] == "%rcx" and item.address < first.address]
    if not setup_candidates: raise AssertionError("linked PE mutation lacks a query setup start")
    setup_start = setup_candidates[-1]
    rcx_ready = _unique(instructions, lambda item: item.opcode == "movl" and
                        item.operands == ("$0x1020", "%edx") and
                        setup_start.address < item.address < first.address,
                        "first helper routing setup")
    return_copy = _unique(instructions, lambda item: item.opcode == "movl" and
                          item.operands == ("%eax", "%edx") and
                          first.address < item.address < second.address,
                          "first helper result transfer")
    measured_target = int(DIRECT.fullmatch(second.operands[0])[1], 16)
    other_call = _unique(instructions, lambda item: item.opcode == "callq" and
                         item.address not in (first.address, second.address), "non-joint call")
    other_target = int(DIRECT.fullmatch(other_call.operands[0])[1], 16)
    state_offset = int(state_init.operands[1].split("(", 1)[0], 0)
    state_load = _unique(instructions, lambda item: item.opcode == "movl" and
                         item.operands == (state_init.operands[1], "%r10d") and
                         setup_start.address < item.address < first.address,
                         "first helper state load")
    query_exit = min(item.address for item in instructions if item.address > second.address and
                     item.opcode in ("jmp", "jmpq", "jae"))
    state_write = _unique(instructions, lambda item: item.opcode == "movl" and
                          item.operands == ("%eax", state_init.operands[1]) and
                          second.address < item.address < query_exit, "joint state update")
    entry_jump = _unique(instructions, lambda item: item.address == entry_branch,
                         "entry dispatcher jump")
    dispatcher = int(DIRECT.fullmatch(entry_jump.operands[0])[1], 16)
    dispatcher_cmp = next((item for item in instructions if item.address > dispatcher and
                           item.opcode == "cmpl" and len(item.raw) == 5), None)
    if dispatcher_cmp is None: raise AssertionError("dispatcher lacks a pre-branch comparison")
    document = json.loads(report.read_text())
    row = next(item for item in document["functions"] if item.get("function") == "mixed_site_body")
    mutations = (
        ("entry-spill-overwrite", dispatcher_cmp, bytes.fromhex("4c 89 44 24") + bytes((lease_offset,)), "immutable entry reference spill overwritten"),
        ("cross-branch-rsp-shift", state_load, bytes.fromhex("48 81 ec 20 00 00 00"), "non-entry stack-pointer shift"),
        ("partial-rcx", rcx_ready, bytes.fromhex("66 b9 00 00"), "unsupported instruction movw"),
        ("writing-cmpxchg", state_load, bytes.fromhex("4c 0f b1 44 24") + bytes((lease_offset,)), "unsupported instruction cmpxchgq"),
        ("skipped-setup", setup_start, _jump(setup_start, first.address), "lost first/eighth argument provenance"),
        ("branch-into-middle", setup_start, _jump(setup_start, first.address + 1), "branch crosses interval or enters instruction middle"),
        ("intervening-call", rcx_ready, _call(rcx_ready, other_target), "unmodelled call may alter entry spills"),
        ("wrong-helper", first, _retarget_call(first, measured_target), "joint helper order or count"),
        ("detached-return", return_copy, bytes.fromhex("31 d2"), "both joint return words do not reach"),
    )
    for label, instruction, payload, machine_reason in mutations:
        changed = directory / f"linked-{label}.exe"
        changed_bytes = (_replace_range(image, layout, instruction, payload) if isinstance(instruction, tuple)
                         else _replace(image, layout, instruction, payload))
        changed.write_bytes(changed_bytes)
        changed_code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                                str(changed)], text=True, timeout=20).lower()
        try:
            verify_joint_machine(changed_bytes, changed_code, document, row)
        except ValueError as error:
            if machine_reason not in str(error):
                raise AssertionError(f"{label} was rejected for the wrong machine reason: {error}") from error
        else:
            raise AssertionError(f"{label} escaped the independent machine proof")
        final = directory / f"linked-{label}.final.json"
        refused = run([*checker, changed, report, "--check-joint-caller-flow",
                       "--output", final], succeeds=False)
        if final.exists():
            raise AssertionError(f"linked PE mutation escaped {label}: {refused.stderr}")
        print(f"linked PE {label} refused: {refused.stderr.strip()}")
    state_index = instructions.index(state_write)
    tail = instructions[state_index - 3:state_index]
    if ([item.opcode for item in tail] != ["xorl", "xorl", "addl"] or
            [len(item.raw) for item in tail] != [3, 2, 2] or
            tail[-1].operands != ("%ecx", "%eax") or len(state_write.raw) != 7):
        raise AssertionError("linked return mix lacks the bounded mutation span")
    return_mutants = (
        ("zero-multiplier", (*tail, state_write),
         bytes.fromhex("31 c9 0f af c1 89 c2") + state_write.raw,
         "odd immediate multiplier"),
        ("alias-sub-cancellation", tuple(tail), bytes.fromhex("89 ca 29 d1 01 c8 90"),
         "return expressions detach or cancel"),
        ("alias-xor-cancellation", tuple(tail), bytes.fromhex("89 ca 31 d1 01 c8 90"),
         "return expressions detach or cancel"),
        ("double-xor-cancellation", tuple(instructions[state_index - 5:state_index]),
         bytes.fromhex("89 ca 31 c9 31 d1 31 d1 01 c8 90 90 90 90"), "return"),
    )
    for label, span, payload, machine_reason in return_mutants:
        changed_bytes = _replace_range(image, layout, span, payload)
        changed = directory / f"linked-{label}.exe"
        changed.write_bytes(changed_bytes)
        changed_code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                                str(changed)], text=True, timeout=20).lower()
        try:
            verify_joint_machine(changed_bytes, changed_code, document, row)
        except ValueError as error:
            if machine_reason not in str(error):
                raise AssertionError(f"{label} missed its bounded return check: {error}") from error
        else:
            raise AssertionError(f"{label} escaped bounded return routing diagnostics")
        final = directory / f"linked-{label}.final.json"
        refused = run([*checker, changed, report, "--check-joint-caller-flow",
                       "--output", final], succeeds=False)
        if final.exists(): raise AssertionError(f"{label} promoted full binding: {refused.stderr}")
        print(f"linked PE {label} refused: {refused.stderr.strip()}")
    # Keep both helper calls and return instructions, but retarget their shared
    # input and output to a plausible adjacent local while the dispatcher still
    # reads the original state slot. This must not inherit a true final flag.
    decoy = state_offset - 4
    if decoy < 0: raise AssertionError("state slot has no bounded adjacent decoy")
    changed_bytes = image
    for item in (state_load, state_write):
        if len(item.raw) < 7: raise AssertionError("decoy mutation needs disp32 stack addressing")
        changed_bytes = _replace(changed_bytes, layout, item,
                                 item.raw[:-4] + struct.pack("<I", decoy))
    changed = directory / "linked-decoy-state.exe"
    changed.write_bytes(changed_bytes)
    changed_code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                            str(changed)], text=True, timeout=20).lower()
    try:
        verify_joint_machine(changed_bytes, changed_code, document, row)
    except ValueError as error:
        if "state origin differs from dispatcher state" not in str(error):
            raise AssertionError(f"decoy was rejected for the wrong machine reason: {error}") from error
    else:
        raise AssertionError("decoy state source/sink escaped machine proof")
    final = directory / "linked-decoy-state.final.json"
    refused = run([*checker, changed, report, "--check-joint-caller-flow",
                   "--output", final], succeeds=False)
    if final.exists(): raise AssertionError(f"decoy state escaped final gate: {refused.stderr}")
    print(f"linked PE decoy-state refused: {refused.stderr.strip()}")

    # The caller-only diagnostic must not claim a protected second-call pointer:
    # a white-box first helper can write the caller's prepared scope slot.
    second_rcx = _unique(instructions, lambda item: item.opcode == "movq" and
                         item.operands[0].endswith("(%rsp)") and
                         item.operands[1] == "%rcx" and
                         first.address < item.address < second.address,
                         "second helper scope reload")
    caller_slot = int(second_rcx.operands[0].split("(", 1)[0], 0)
    helper_code = subprocess.check_output([str(objdump), "-d",
        f"--disassemble-symbols={OWNED}", str(binary)], text=True, timeout=20).lower()
    helper_lines = helper_code.splitlines()
    entry = _unique(list(enumerate(helper_lines)),
        lambda pair: pair[1].strip().endswith(f"<{OWNED}>:"), "owned helper entry")[0]
    target = _unique(list(enumerate(helper_lines)),
        lambda pair: "48 8b 8c 24 b8 00 00 00" in pair[1] and
                     "\tmovq\t0xb8(%rsp), %rcx" in pair[1], "owned helper writable span")
    prologue = helper_lines[entry + 1:target[0]]
    if sum("\tpushq\t" in line for line in prologue) != 7 or not any(
            "\tsubq\t$0x40, %rsp" in line for line in prologue):
        raise AssertionError("owned helper stack frame changed")
    helper_address = int(target[1].split(":", 1)[0], 16)
    helper_instruction = Instruction(helper_address, bytes.fromhex("48 8b 8c 24 b8 00 00 00"),
                                     "movq", ("0xb8(%rsp)", "%rcx"))
    # Seven pushes, a 0x40-byte frame, and the return address place the caller's
    # current RSP at helper RSP+0x80 at this instruction.
    displacement = 0x80 + caller_slot
    changed_bytes = _replace(image, layout, helper_instruction,
                             bytes.fromhex("48 89 84 24") + struct.pack("<I", displacement))
    changed = directory / "linked-helper-writes-caller-scope.exe"
    changed.write_bytes(changed_bytes)
    diagnostic = verify_joint_machine(changed_bytes, code, document, row)
    if (diagnostic.get("joint_caller_pointer_provenance_verified") is not False or
            "helper-write-effects-unverified" not in diagnostic.get("joint_machine_scope", "")):
        raise AssertionError("helper mutation received overstated pointer provenance")
    final = directory / "linked-helper-writes-caller-scope.final.json"
    run([*checker, changed, report, "--check-joint-caller-flow", "--output", final])
    final_proof = next(item["runtime_contribution"] for item in json.loads(final.read_text())["functions"]
                       if item.get("function") == "mixed_site_body")
    if (final_proof.get("joint_caller_pointer_provenance_verified") is not False or
            final_proof.get("cross_provider_owner_binding_verified") is not False):
        raise AssertionError("helper mutation promoted an unproved linked claim")
    print("linked PE helper write remains unproved by caller-only diagnostic")
