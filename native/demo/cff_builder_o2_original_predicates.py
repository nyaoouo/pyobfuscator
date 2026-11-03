"""Selected O2 original-predicate routes in the archive-backed mixed POST build.

The earlier archive publication proof establishes the two compute comparisons.
This module adds the wrapper's original generation/subject decision and joins
all three routes to the requested, optimized and materialized IR. It deliberately
does not infer observation, callback, decoder, or runtime payload effects.
"""

from __future__ import annotations

import hashlib
import re

from cff_builder_entry_states import _expected_state
from cff_builder_original_predicates import (_block_start, _dispatcher_destination,
    _document, _encoded_immediate, _ir_contract, _ir_function, _mix, _only_stack_write,
    _predicate_groups, _slot, _states, _wrapper_source, RSP)
from cff_builder_subjects import verify_builder_subjects
from cff_joint_machine_evidence import DIRECT, _dispatcher_state, _entry_spills, _graph, _instructions
from payload_binding import OWNER, WRAPPER
from post_mixed_binding import _plan


SCOPE = "selected-o2-three-original-predicate-routes-win64-v1"
OBSERVATION = "_ZNK12pyobfuscator6native12contribution6scoped5Scope11observationEv"
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _fail(reason: str) -> None:
    raise ValueError(f"builder O2 original predicates: {reason}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ir(raw: bytes, label: str) -> tuple[str, str]:
    if type(raw) is not bytes or not raw or len(raw) > 16 << 20:
        _fail(f"{label} IR must be bounded bytes")
    try:
        module = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError(f"builder O2 original predicates: invalid {label} IR") from error
    return module, _ir_function(module, WRAPPER)


def _metadata(module: str, site: str) -> str:
    matches = re.findall(r"(?m)^!" + re.escape(site) + r" = !\{!\"(original\.[^\"]+)\"\}$", module)
    if len(matches) != 1:
        _fail("wrapper branch lacks one original-edge metadata identity")
    return matches[0]


def _source(raw: bytes, label: str, kind: str) -> tuple[str, str]:
    module, body = _ir(raw, label)
    comparisons = re.findall(r"(?m)^\s*(%[\w.]+) = icmp (ne|eq) i64 (%[\w.]+), (%[\w.]+), !pyobf\.cff\.site !(\d+)\s*$", body)
    if len(comparisons) != 1 or len(re.findall(r"\bicmp\b", body)) != 1 or comparisons[0][1] != kind:
        _fail(f"{label} wrapper has an unsupported original comparison")
    reference, _, generation, subject, compare_site = comparisons[0]
    branch = re.findall(r"(?m)^\s*br i1 " + re.escape(reference) +
                        r", label %(\d+), label %(\d+), !pyobf\.cff\.site !(\d+)\s*$", body)
    if len(branch) != 1:
        _fail(f"{label} wrapper comparison lacks one direct branch")
    first, second, branch_site = branch[0]
    comparison_identity = _metadata(module, compare_site)
    if kind == "ne":
        expected_source = (r"getelementptr[^\n]*PayloadHandoff[^\n]*ptr %\d+, i32 0, i32 2.*?"
                           r"\n\s*" + re.escape(generation) + r" = load i64.*?"
                           r"call[^\n]*@" + OBSERVATION + r".*?"
                           r"getelementptr[^\n]*Observation[^\n]*i32 0, i32 3.*?"
                           r"\n\s*" + re.escape(subject) + r" = load i64")
    else:
        expected_source = (r"getelementptr[^\n]*ptr %3, i64 8.*?"
                           r"\n\s*" + re.escape(generation) + r" = load i64.*?"
                           r"call[^\n]*@" + OBSERVATION + r"\([^\n]*%1\).*?"
                           r"getelementptr[^\n]*i64 88.*?"
                           r"\n\s*" + re.escape(subject) + r" = load i64")
    if re.search(expected_source, body, re.S) is None:
        _fail(f"{label} wrapper no longer reads generation and parent observation subject")
    if (kind == "ne" and (not re.search(r'PayloadHandoff" = type \{ i32, i32, i64, ptr', module) or
                            not re.search(r'Observation" = type \{', module))):
        _fail("requested wrapper field layout differs")
    # The true branch of ne denies; O2 inverts it to eq and exchanges arms.
    allow, deny = (second, first) if kind == "ne" else (first, second)
    blocks = dict(re.findall(r"(?m)^(\d+):[^\n]*\n(.*?)(?=^\d+:|\Z)", body, re.S))
    if allow not in blocks or deny not in blocks:
        _fail(f"{label} wrapper branch targets are not distinct local blocks")
    if ("@pyobf_demo_bound_compute(" not in blocks[allow] or
            "@pyobf_demo_bound_compute(" in blocks[deny] or
            (kind == "ne" and "store i32 -104" not in blocks[deny]) or
            (label == "optimized" and not re.search(
                r"phi i32 \[ [^,]+, %" + re.escape(allow) + r" \], \[ -104, %5 \]", body)) or
            (label == "prepared" and not re.search(
                r"(?m)^\s*(%[\w.]+) = load i32, ptr @__pyobf_archive_storage_record-35, align 4\s*$",
                body))):
        _fail(f"{label} wrapper allow/deny successors changed")
    if label == "prepared":
        denial = re.findall(
            r"(?m)^\s*(%[\w.]+) = load i32, ptr @__pyobf_archive_storage_record-35, align 4\s*$",
            body)
        if (len(denial) != 1 or not re.search(
                r"phi i32 \[ [^,]+, %" + re.escape(allow) + r" \], \[ " +
                re.escape(denial[0]) + r", %5 \]", body) or
                body.count("ptr @__pyobf_archive_storage_record-35, i64 4)") != 1):
            _fail("prepared wrapper denial no longer uses its archived return slot")
    return _metadata(module, branch_site), comparison_identity


def _proofs(publication: dict, predecessor: dict, object_bytes: bytes,
            image_bytes: bytes, requested: bytes, optimized: bytes) -> tuple[str, str]:
    if type(publication) is not dict or type(predecessor) is not dict:
        _fail("archive and O2 predecessor proofs are required")
    conditions = publication.get("conditions")
    if (publication.get("verified") is not True or
            publication.get("publication_route_verified") is not True or
            publication.get("decoder_effect_verified") is not False or
            publication.get("original_predicate_equivalence_verified") is not False or
            publication.get("object_sha256") != _sha(object_bytes) or
            publication.get("image_sha256") != _sha(image_bytes) or
            type(conditions) is not list or len(conditions) != 2 or
            [(row.get("record_index"), row.get("condition")) for row in conditions
             if type(row) is dict] != [(28, "slt-archive-i32-zero"), (30, "eq-archive-i32-zero")]):
        _fail("two selected archive predicate routes are not established for this product")
    if (predecessor.get("verified") is not True or
            predecessor.get("optimizer_replay_verified") is not True or
            predecessor.get("archive_input_join_verified") is not True or
            predecessor.get("requested_ir_sha256") != _sha(requested) or
            predecessor.get("optimized_ir_sha256") != _sha(optimized)):
        _fail("O2 predecessor does not bind requested and optimized IR")
    archive_record = publication.get("archive_record_sha256")
    o2_record = predecessor.get("record_sha256")
    if (type(archive_record) is not str or SHA.fullmatch(archive_record) is None or
            type(o2_record) is not str or SHA.fullmatch(o2_record) is None):
        _fail("predecessor record digests are missing")
    return archive_record, o2_record


def _machine_source(instructions, index: int, state_slot: int) -> None:
    """Track the source through archive setup and the post-call comparison reloads."""
    compare = instructions[index]
    start = _block_start(instructions, index)
    prior = instructions[:index]
    observation = [item for item in prior if start <= item.address < compare.address and
                   item.opcode in ("call", "callq") and len(item.operands) == 1 and
                   (match := DIRECT.fullmatch(item.operands[0])) is not None and
                   match[2] == OBSERVATION.lower()]
    if len(observation) != 1:
        _fail("wrapper has no unique parent observation call in its comparison body")
    writes = [item for item in prior if observation[0].address < item.address and
              item.opcode == "movq" and len(item.operands) == 2 and
              item.operands[0] == "%rax" and RSP.fullmatch(item.operands[1])]
    subject_writes = [item for item in writes if item.address == observation[0].address + len(observation[0].raw) + 4]
    # The observed lowering reads Observation+88 immediately after the call.
    read = next((item for item in prior if item.address == observation[0].address + len(observation[0].raw)), None)
    if (read is None or read.raw != b"\x48\x8b\x40\x58" or
            len(subject_writes) != 1):
        _fail("wrapper observation subject is not retained in one private slot")
    subject_write = subject_writes[0]
    subject_slot = _slot(subject_write.operands[1])
    reloads = [(position, item) for position, item in enumerate(prior) if
               subject_write.address < item.address and item.opcode == "movq" and
               item.operands == (f"{subject_slot:#x}(%rsp)", "%r9")]
    if len(reloads) != 1:
        _fail("wrapper subject has no unique post-archive reload")
    reload_index, subject_reload = reloads[0]
    generation_reload = instructions[reload_index + 1]
    if (generation_reload.opcode != "movq" or
            len(generation_reload.operands) != 2 or
            generation_reload.operands[1] != "%r8" or
            RSP.fullmatch(generation_reload.operands[0]) is None):
        _fail("wrapper generation has no adjacent post-archive reload")
    generation_slot = _slot(generation_reload.operands[0])
    if generation_slot == subject_slot:
        _fail("wrapper generation and subject alias one stack slot")
    generation_writes = [item for item in prior if start <= item.address < observation[0].address and
                         item.opcode == "movq" and
                         item.operands == ("%rax", f"{generation_slot:#x}(%rsp)" )]
    if len(generation_writes) != 1:
        _fail("wrapper generation has no unique handoff-field storage")
    _only_stack_write(instructions, subject_slot, 8, {subject_write.address})
    _only_stack_write(instructions, generation_slot, 8, {generation_writes[0].address})
    intervening = instructions[instructions.index(subject_write) + 1:reload_index]
    calls = [item for item in intervening if item.opcode in ("call", "callq")]
    if (len(calls) != 1 or
            any(item.opcode in ("jmp", "jmpq", "jae", "ret", "retq") for item in intervening)):
        _fail("wrapper archive setup is not a straight-line single-call interval")
    call_index = instructions.index(calls[0])
    call_target = DIRECT.fullmatch(calls[0].operands[0]) if len(calls[0].operands) == 1 else None
    key_address = instructions[call_index - 3]
    if (call_target is None or
            re.fullmatch(r"__pyobf_archive_[0-9a-f]{32}_35", call_target[2]) is None or
            key_address.opcode != "leaq" or len(key_address.operands) != 2 or
            key_address.operands[1] != "%rcx" or
            RSP.fullmatch(key_address.operands[0]) is None):
        _fail("wrapper archive call lacks its selected private key frame")
    key_slot = _slot(key_address.operands[0])
    if (key_slot != 0xb8 or key_slot < max(subject_slot, generation_slot) + 8 or
            key_slot + 32 > state_slot - 8):
        _fail("wrapper archive key frame overlaps comparison source or control slots")
    # The only pre-reload work in this selected lowering is eight independent
    # state-derived key words, followed by the one archive call. In particular,
    # writes to the state slot and changes to RSP cannot hide in the arithmetic.
    if len(intervening) != 8 * 11 + 4:
        _fail("wrapper pre-reload key material interval differs")
    for number in range(8):
        group = intervening[number * 11:(number + 1) * 11]
        slot = key_slot + 4 * number
        exact = (
            b"\x8b\x84\x24" + state_slot.to_bytes(4, "little"), None,
            b"\x89\xc1", b"\xc1\xe9\x10", b"\x31\xc8",
            b"\x69\xc0\x35\xae\xb2\xc2", b"\x89\xc1",
            b"\xc1\xe9\x0d", b"\x31\xc8", None,
            b"\x89\x84\x24" + slot.to_bytes(4, "little"),
        )
        if (any(expected is not None and item.raw != expected
                for item, expected in zip(group, exact)) or
                group[0].operands != (f"{state_slot:#x}(%rsp)", "%eax") or
                group[-1].operands != ("%eax", f"{slot:#x}(%rsp)")):
            _fail("wrapper pre-reload key word reads or writes a different slot")
        for position in (1, 9):
            if group[position].opcode != "xorl" or group[position].operands[1:] != ("%eax",):
                _fail("wrapper pre-reload key word has unmodeled arithmetic")
            _encoded_immediate(group[position], b"\x35")
    key_lea, storage_lea, size, actual_call = intervening[88:]
    if (key_lea is not key_address or actual_call is not calls[0] or
            key_lea.raw != b"\x48\x8d\x8c\x24" + key_slot.to_bytes(4, "little") or
            storage_lea.opcode != "leaq" or len(storage_lea.raw) != 7 or
            not storage_lea.raw.startswith(b"\x48\x8d\x15") or
            storage_lea.operands[1:] != ("%rdx",) or
            re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)\(%rip\)",
                         storage_lea.operands[0]) is None or
            size.raw != b"\x41\xb8\x04\0\0\0" or
            size.operands != ("$0x4", "%r8d") or
            actual_call.raw[:1] != b"\xe8" or len(actual_call.raw) != 5):
        _fail("wrapper pre-reload archive call setup differs")
    # This selected O2 lowering has eight post-call key clears, a storage read
    # and spill, then a state read and two encoded arms. Check every PE byte in
    # the interval; a different stack destination can overwrite the CFF state.
    window = instructions[reload_index + 2:index]
    if len(window) != 13:
        _fail("wrapper comparison window differs from the selected O2 lowering")
    for number, item in enumerate(window[:8]):
        slot = key_slot + 4 * number
        expected = b"\xc7\x84\x24" + slot.to_bytes(4, "little") + b"\0" * 4
        if (item.opcode != "movl" or item.raw != expected or
                item.operands != ("$0x0", f"{slot:#x}(%rsp)")):
            _fail("wrapper comparison window clears a different cache or control slot")
    storage_read, storage_spill, state_read, first_arm, second_arm = window[8:]
    if (storage_read.opcode != "movl" or len(storage_read.raw) != 6 or
            not storage_read.raw.startswith(b"\x8b\x05") or
            storage_read.operands[1:] != ("%eax",) or
            re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)\(%rip\)",
                         storage_read.operands[0]) is None or
            storage_spill.opcode != "movl" or
            storage_spill.operands != ("%eax", f"{state_slot - 8:#x}(%rsp)") or
            state_read.opcode != "movl" or
            state_read.operands != (f"{state_slot:#x}(%rsp)", "%eax") or
            [item.opcode for item in (first_arm, second_arm)] != ["movl", "movl"] or
            first_arm.operands[1:] != ("%ecx",) or
            second_arm.operands[1:] != ("%edx",)):
        _fail("wrapper comparison window storage or state setup differs")
    # Reuse the strict source tracer on just the source-carrying instructions;
    # the excluded archive arithmetic has been checked for source-slot writes,
    # address escapes and control transfers above.
    source = [item for item in instructions if item.address < start or
              start <= item.address <= subject_write.address or
              item.address in (subject_reload.address, generation_reload.address,
                               compare.address)]
    _wrapper_source(source, len(source) - 1)


def _inline_transition(instructions, index: int, state_slot: int):
    """The O2 wrapper falls through into a fresh dispatcher after its state write."""
    previous = instructions[index - 3:index]
    if (len(previous) != 3 or previous[0].opcode != "movl" or
            previous[0].operands != (f"{state_slot:#x}(%rsp)", "%eax") or
            [item.opcode for item in previous[1:]] != ["movl", "movl"] or
            previous[1].operands[1] != "%ecx" or previous[2].operands[1] != "%edx"):
        _fail("wrapper comparison lacks its encoded state choice")
    false_arm = _encoded_immediate(previous[1], b"\xb9")
    true_arm = _encoded_immediate(previous[2], b"\xba")
    condition = instructions[index + 1]
    if condition.operands != ("%edx", "%ecx") or condition.raw != b"\x0f\x44\xca":
        _fail("wrapper equality does not select the expected state arm")
    expected = [
        ("movl", ("%eax", "%edx")), ("xorl", None),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0x10", "%r8d")),
        ("xorl", ("%r8d", "%edx")),
        ("imull", ("$0x7feb352d", "%edx", "%edx")),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0xf", "%r8d")),
        ("xorl", ("%r8d", "%edx")),
        ("imull", ("$0x846ca68b", "%edx", "%edx")),
        ("movl", ("%edx", "%r8d")), ("shrl", ("$0x10", "%r8d")),
        ("xorl", ("%r8d", "%edx")), ("xorl", ("%edx", "%ecx")),
        ("addl", ("%ecx", "%eax")),
        ("movl", ("%eax", f"{state_slot:#x}(%rsp)")),
    ]
    span = instructions[index + 2:index + 2 + len(expected)]
    if len(span) != len(expected) or any(
            item.opcode != opcode or operands is not None and item.operands != operands
            for item, (opcode, operands) in zip(span, expected)):
        _fail("wrapper state mixer is truncated or changed")
    salt = _encoded_immediate(span[1], b"\x81\xf2")
    if (span[0].operands != ("%eax", "%edx") or
            span[1].operands[1] != "%edx" or
            span[5].raw != b"\x69\xd2\x2d\x35\xeb\x7f" or
            span[9].raw != b"\x69\xd2\x8b\xa6\x6c\x84" or
            span[-2].operands != ("%ecx", "%eax") or
            span[-1].operands != ("%eax", f"{state_slot:#x}(%rsp)")):
        _fail("wrapper state mixer does not update its dispatcher slot")
    next_index = index + 2 + len(expected)
    if next_index >= len(instructions) or instructions[next_index].operands != \
            (f"{state_slot:#x}(%rsp)", "%eax") or instructions[next_index].opcode != "movl":
        _fail("wrapper state write does not enter its inline dispatcher")
    return false_arm, true_arm, salt, instructions[next_index].address


def verify_builder_o2_original_predicates(object_bytes, image_bytes, report_bytes,
    edge_plan_bytes, requested_ir_bytes, optimized_ir_bytes, prepared_ir_bytes,
    owner_codes, publication_proof, o2_predecessor_proof) -> dict:
    """Verify only the three selected original branch routes in the fixed O2 product."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(owner_codes) is not dict or set(owner_codes) != {OWNER, WRAPPER} or
            any(type(value) is not str or not value for value in owner_codes.values())):
        _fail("actual COFF, PE and both owner disassemblies are required")
    archive_record, o2_record = _proofs(publication_proof, o2_predecessor_proof,
        object_bytes, image_bytes, requested_ir_bytes, optimized_ir_bytes)
    verify_builder_subjects(object_bytes, image_bytes)
    requested_sites = _ir_contract(requested_ir_bytes)
    if len(requested_sites[OWNER]) != 2 or len(requested_sites[WRAPPER]) != 1:
        _fail("requested IR lacks the selected three original decisions")
    requested_site, requested_compare = _source(requested_ir_bytes, "requested", "ne")
    optimized_site, optimized_compare = _source(optimized_ir_bytes, "optimized", "eq")
    prepared_site, prepared_compare = _source(prepared_ir_bytes, "prepared", "eq")
    if (requested_site != requested_sites[WRAPPER][0] or
            optimized_site != requested_site or prepared_site != requested_site or
            optimized_compare != requested_compare or prepared_compare != requested_compare):
        _fail("wrapper original-edge metadata changes across O2 or archive preparation")
    plan = _plan(edge_plan_bytes)
    report = _document(report_bytes, 8 << 20, "compiler report")
    if report.get("original_edge_plan_sha256") != _sha(edge_plan_bytes):
        _fail("compiler report differs from frozen edge plan")
    _, compute_pairs = _predicate_groups(plan, report, OWNER, requested_sites[OWNER])
    if [(row["true_state"], row["false_state"]) for row in
            publication_proof["conditions"]] != [
            (pair[0], pair[1]) for pair in compute_pairs]:
        _fail("two published compute routes differ from this report")
    planned, pairs = _predicate_groups(plan, report, WRAPPER, [requested_site])
    pair = pairs[0]
    instructions = _instructions(owner_codes[WRAPPER], image_bytes, WRAPPER)
    _, graph, _ = _graph(instructions, allow_indirect=True)
    frame, _ = _entry_spills(instructions, image_bytes)
    state_slot = _dispatcher_state(instructions, graph, frame) + frame
    first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq"))
    dispatcher = graph[first_branch.address][0]
    compares = [(index, item) for index, item in enumerate(instructions)
                if item.opcode in ("cmpl", "cmpq") and index + 1 < len(instructions) and
                instructions[index + 1].opcode in ("cmovll", "cmovel", "cmovnel")]
    if len(compares) != 1:
        _fail("wrapper has an extra, missing or unmodeled original comparison")
    index, item = compares[0]
    _machine_source(instructions, index, state_slot)
    chosen = instructions[index + 1]
    if chosen.opcode != "cmovel" or chosen.raw != b"\x0f\x44\xca":
        _fail("optimized wrapper equality polarity differs")
    false_arm, true_arm, salt, inline_dispatcher = _inline_transition(
        instructions, index, state_slot)
    start = _block_start(instructions, index)
    found = []
    for before in _states(WRAPPER, planned["recipe"]):
        if _dispatcher_destination(instructions, dispatcher, before, state_slot) != start:
            continue
        mask = _mix(before ^ salt)
        # Equality chooses successor zero (allow); inequality chooses one (deny).
        false_state = (before + (false_arm ^ mask)) & 0xffffffff
        true_state = (before + (true_arm ^ mask)) & 0xffffffff
        if (true_state, false_state) == (pair[0], pair[1]):
            if (_dispatcher_destination(instructions, inline_dispatcher, true_state,
                                        state_slot) ==
                    _dispatcher_destination(instructions, inline_dispatcher, false_state,
                                            state_slot)):
                _fail("wrapper encoded arms merge in its inline dispatcher")
            found.append(before)
    if len(found) != 1 or found[0] != _expected_state(WRAPPER, planned["recipe"]):
        _fail("wrapper comparison does not route to frozen allow/deny states")
    return {"verified": True, "wrapper_source_route_verified": True,
            "wrapper_machine_route_verified": True,
            "three_selected_predicate_routes_verified": True,
            "observation_body_effect_verified": False,
            "callback_effect_verified": False,
            "decoder_cache_effect_verified": False,
            "runtime_loaded_bytes_verified": False,
            "general_o2_equivalence_verified": False, "scope": SCOPE,
            "object_sha256": _sha(object_bytes), "image_sha256": _sha(image_bytes),
            "report_sha256": _sha(report_bytes), "edge_plan_sha256": _sha(edge_plan_bytes),
            "requested_ir_sha256": _sha(requested_ir_bytes),
            "optimized_ir_sha256": _sha(optimized_ir_bytes),
            "prepared_ir_sha256": _sha(prepared_ir_bytes),
            "o2_record_sha256": o2_record, "archive_record_sha256": archive_record}
