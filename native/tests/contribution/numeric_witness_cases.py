"""Linked two-site numeric cancellation fixture for the bounded G2h checker."""

import json
from pathlib import Path
import struct
import subprocess
from unittest.mock import patch

import cff_source_mixed_site_map
from cff_joint_machine_evidence import (_dispatcher_state, _entry_spills, _graph,
                                        _instructions, _stack, Instruction, State)
from cff_source_mixed_numeric import (_constant_states, _prelude_tokens, Machine,
                                      check_numeric_sensitivity)
from linked_machine_mutations import _replace
from pe_layout import parse_image


def cancellation_ir(source):
    start = "  %pyobf.state = alloca i32, align 4, !pyobf.contribution.root !8"
    input_word = "  %68 = xor i32 %pyobf.contribution.word7, -1640531527"
    if source.count(start) != 1 or source.count(input_word) != 1:
        raise AssertionError("expected actual two-site lowering is absent")
    source = source.replace(start, start + "\n  %numeric.probe = alloca i32, align 4", 1)
    return source.replace(input_word, "\n".join((
        "  store volatile i32 %pyobf.contribution.word7, ptr %numeric.probe, align 4",
        "  %numeric.loaded = load volatile i32, ptr %numeric.probe, align 4",
        "  %numeric.complement = xor i32 %numeric.loaded, -1",
        "  %numeric.cancel = add i32 %pyobf.contribution.word7, %numeric.complement",
        "  %68 = xor i32 %numeric.cancel, -1640531527")), 1)


def check_numeric_cancelled(args, directory, protected, report, checker, core,
                            includes, successful_final, run):
    """Keep a genuine linked PE red with all old site/source/route checks intact."""
    changed = directory / "numeric-cancel.ll"
    changed.write_text(cancellation_ir(protected.read_text()))
    body, binary, final = (directory / f"numeric-cancel.{suffix}" for suffix in
                           ("obj", "exe", "final.json"))
    run([args.compiler, "-O0", "-fno-lto", "-c", changed, "-o", body])
    run([args.compiler, "-std=c++17", "-O2", "-DPYOBF_TWO_MIXED_SITES",
         "-DPYOBF_THREE_OWNED_WORDS", body,
         Path(__file__).with_name("mixed_site_probe.cpp"), *core, *includes,
         "-lbcrypt", "-o", binary])
    image = binary.read_bytes()
    code = subprocess.check_output([str(args.objdump), "-d",
                                    "--disassemble-symbols=mixed_site_body", str(binary)],
                                   text=True, timeout=20).lower()
    row = next(item for item in json.loads(report.read_text())["functions"]
               if item.get("function") == "mixed_site_body")
    with patch.object(cff_source_mixed_site_map, "check_numeric_sensitivity"):
        cff_source_mixed_site_map.check_two_site_map(
            code, row["runtime_contribution"], "mixed_site_body", image)
    final.write_bytes(successful_final.read_bytes())
    rejected = run([*checker, binary, report, "--output", final], succeeds=False)
    if final.exists() or "has no exhibited numeric effect" not in rejected.stderr:
        raise AssertionError(f"linked numeric cancellation escaped: {rejected.stderr}")
    print("actual linked two-site numeric cancellation rejected", flush=True)


def check_unknown_linked(checker, binary, report, directory, objdump,
                         successful_final, run):
    """A real PE shadow-space read must not acquire a fabricated local value."""
    image = binary.read_bytes()
    code = subprocess.check_output([str(objdump), "-d",
                                    "--disassemble-symbols=mixed_site_body", str(binary)],
                                   text=True, timeout=20).lower()
    instructions = _instructions(code, image, "mixed_site_body")
    _, graph, callers = _graph(instructions)
    frame, _ = _entry_spills(instructions)
    dispatcher_slot = _dispatcher_state(instructions, graph, frame)
    helper_calls = [item for item in callers if "pyobf_native_mixed_" in item.operands[0]]
    if len(helper_calls) not in (4, 5):
        raise AssertionError("unknown-read mutation needs two linked site groups")
    first_return_end = next(item.address for item in instructions if
                            item.address > helper_calls[1].address and
                            item.opcode in ("jmp", "jmpq"))
    candidates = [item for item in instructions if helper_calls[1].address < item.address <
                  first_return_end and item.opcode == "movl" and
                  len(item.operands) == 2 and item.operands[1] == "%eax" and
                  _stack(item.operands[0], State(-frame, {}, {}, {}, {}, {}, {}, 0)) ==
                  dispatcher_slot and item.raw.startswith(b"\x8b\x84\x24") and
                  len(item.raw) == 7]
    if len(candidates) != 1:
        raise AssertionError("unknown-read mutation lost its unique state input")
    target = candidates[0]
    changed = _replace(image, parse_image(image), target,
                       target.raw[:-4] + struct.pack("<I", 0x10))
    mutated = directory / "numeric-unknown-shadow.exe"
    final = directory / "numeric-unknown-shadow.final.json"
    mutated.write_bytes(changed)
    changed_code = subprocess.check_output([str(objdump), "-d",
                                            "--disassemble-symbols=mixed_site_body", str(mutated)],
                                           text=True, timeout=20).lower()
    row = next(item for item in json.loads(report.read_text())["functions"]
               if item.get("function") == "mixed_site_body")
    with patch.object(cff_source_mixed_site_map, "check_numeric_sensitivity"):
        cff_source_mixed_site_map.check_two_site_map(
            changed_code, row["runtime_contribution"], "mixed_site_body", changed)
    final.write_bytes(successful_final.read_bytes())
    rejected = run([*checker, mutated, report, "--output", final], succeeds=False)
    if final.exists() or "unknown or aliased 32-bit memory read" not in rejected.stderr:
        raise AssertionError(f"linked unknown read escaped numeric gate: {rejected.stderr}")
    print("actual linked two-site unknown shadow read rejected", flush=True)


def check_unknown_semantics():
    state = State(-0xc8, {}, {}, {}, {}, {}, {}, 0)
    probes = ((lambda machine: machine.read("%eax"), "unknown 32-bit register"),
              (lambda machine: machine.read("0x54(%rsp)"), "unknown or aliased"),
              (lambda machine: machine.step(
                  Instruction(0, b"\x0f\x44\xc1", "cmovel", ("%ecx", "%eax")),
                  set(), {}, -4), "unknown condition flags"))
    for probe, reason in probes:
        try:
            probe(Machine(state))
        except ValueError as error:
            if reason in str(error): continue
            raise
        raise AssertionError(f"numeric model accepted {reason}")
    same_origin = State(-0xc8, {}, {}, {}, {}, {"rax": -4},
                        {-4: -4, -8: -4}, 0)
    token = ("live-in", ("slot", -4))
    machine = Machine(same_origin, tokens={
        ("register", "rax"): token, ("slot", -4): token, ("slot", -8): token})
    if machine.read("%eax") != machine.read("0xc4(%rsp)") or (
            machine.read("%eax") != machine.read("0xc0(%rsp)")):
        raise AssertionError("copied origins acquired independent numeric seeds")
    same_copy_gate = State(-0xc8, {}, {}, {}, {}, {},
                           {-0x58: -0x58, -0x54: -0x58}, 0)
    route = [Instruction(index, b"\x90", opcode, operands) for index, opcode, operands in (
        (0, "callq", ("0x100 <pyobf_native_mixed_owned_contribution_word_v1>",)),
        (1, "movl", ("0x70(%rsp)", "%edx")),
        (2, "movl", ("0x74(%rsp)", "%ecx")),
        (3, "cmpl", ("%ecx", "%edx")),
        (4, "movl", ("$0", "%r8d")),
        (5, "cmovel", ("%r8d", "%eax")),
        (6, "movl", ("%eax", "0xc4(%rsp)")),
        (7, "jmp", ("0x20",)))]
    try:
        graph = {index: (index + 1,) for index in range(7)}
        graph[7] = ()
        check_numeric_sensitivity(route, graph, route[:1], same_copy_gate,
                                  0xc8, 0x20, -4)
    except ValueError as error:
        if "ambiguous reused initial word origin" not in str(error): raise
    else:
        raise AssertionError("equal copied origins fabricated a sensitive CMOV path")
    unresolved = State(-0xc8, {}, {}, {}, {-4: 1}, {}, {}, 0)
    try:
        Machine(unresolved)
    except ValueError as error:
        if "unknown initial word origin" not in str(error): raise
    else:
        raise AssertionError("unresolved initial word acquired a fabricated value")
    prelude = [Instruction(index, b"\x90", opcode, operands) for index, opcode, operands in (
        (0, "movl", ("$0x2a", "0xc4(%rsp)")),
        (1, "movl", ("0xc4(%rsp)", "%r10d")),
        (2, "movl", ("%r10d", "0x5c(%rsp)")),
        (3, "callq", ("0x100 <pyobf_native_mixed_owned_contribution_word_v1>",)))]
    prelude_graph = {0: (1,), 1: (2,), 2: (3,), 3: ()}
    constants = _constant_states(prelude, prelude_graph, 0xc8)[3]
    tokens = _prelude_tokens(prelude, prelude_graph, prelude[3], 0xc8)
    if (constants.get(("slot", -4)) != 42 or
            constants.get(("slot", -108)) != 42 or
            tokens.get(("slot", -108)) != ("constant", 42)):
        raise AssertionError("pre-call immediate and copy did not retain their value")
    bypass = {**prelude_graph, 0: (1, 3)}
    try:
        _prelude_tokens(prelude, bypass, prelude[3], 0xc8)
    except ValueError as error:
        if "first helper call bypasses its pre-call copy interval" not in str(error):
            raise
    else:
        raise AssertionError("a first helper call bypassed pre-call token formation")
    signed = Machine(state)
    for instruction in (
            Instruction(0, b"", "movl", ("$0x80000000", "%eax")),
            Instruction(0, b"", "movl", ("$0x1234", "%edx")),
            Instruction(0, b"", "cmpl", ("$1", "%eax")),
            Instruction(0, b"", "cmovll", ("%edx", "%eax"))):
        signed.step(instruction, set(), {}, -4)
    if signed.read("%eax") != 0x1234:
        raise AssertionError("signed CMOV ignored subtraction overflow")
    equal = Machine(state)
    for instruction in (
            Instruction(0, b"", "movl", ("$0", "%eax")),
            Instruction(0, b"", "movl", ("$0xabcd", "%edx")),
            Instruction(0, b"", "cmpl", ("$0", "%eax")),
            Instruction(0, b"", "cmovel", ("%edx", "%eax"))):
        equal.step(instruction, set(), {}, -4)
    if equal.read("%eax") != 0xabcd:
        raise AssertionError("equality CMOV ignored zero flag")
