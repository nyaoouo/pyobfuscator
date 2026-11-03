"""Actual linked helper call mutants and focused route-CFG refusals."""

import struct
import subprocess

from cff_joint_machine_evidence import DIRECT, HEADER, Instruction, MEASURED, OWNED, _instructions
from cff_source_mixed_helper_routes import (BINDING, FAILURE, OWNED_QUERY,
                                            _check_route, _target, check_helper_routes)
from linked_machine_mutations import _replace
from pe_layout import parse_image


BINDING_STATUS = ("_ZNK12pyobfuscator6native12contribution6scoped5Scope"
                  "14binding_statusERKNS0_21BootstrapContextLeaseE")


def _call(address, target, symbol):
    raw = b"\xe8" + struct.pack("<i", target - address - 5)
    return Instruction(address, raw, "callq", (f"0x{target:x} <{symbol}>",))


def check_helper_route_internal_cases():
    flattened = (
        Instruction(0x100, b"\xeb\x12", "jmp", ("0x114",)),
        _call(0x102, 0x400, FAILURE),
        Instruction(0x107, b"\xcc", "int3", ()),
        _call(0x108, 0x200, BINDING),
        _call(0x10d, 0x300, OWNED_QUERY),
        Instruction(0x112, b"\xc3", "retq", ()),
        Instruction(0x113, b"\x90", "nop", ()),
        Instruction(0x114, b"\x3d\x01\x00\x00\x00", "cmpl", ("$0x1", "%eax")),
        Instruction(0x119, b"\x73\xe7", "jae", ("0x102",)),
        Instruction(0x11b, b"\xeb\xeb", "jmp", ("0x108",)),
    )
    _check_route(flattened, OWNED)
    bypass = list(flattened)
    bypass[-1] = Instruction(0x11b, b"\xeb\xf0", "jmp", ("0x10d",))
    try:
        _check_route(tuple(bypass), OWNED)
    except ValueError as error:
        if "query bypasses binding call" not in str(error):
            raise AssertionError(f"flattened binding bypass lacked a bounded reason: {error}") from error
    else:
        raise AssertionError("flattened binding bypass escaped")

    routed = (
        Instruction(0x100, b"\x74\x05", "je", ("0x107",)),
        _call(0x102, 0x200, BINDING),
        _call(0x107, 0x300, OWNED_QUERY),
        Instruction(0x10c, b"\x75\x01", "jne", ("0x10f",)),
        Instruction(0x10e, b"\xc3", "retq", ()),
        _call(0x10f, 0x400, FAILURE),
        Instruction(0x114, b"\xcc", "int3", ()),
    )
    try:
        _check_route(routed, OWNED)
    except ValueError as error:
        if "query bypasses binding call" not in str(error):
            raise AssertionError(f"branch-bypassed binding lacked bounded reason: {error}") from error
    else:
        raise AssertionError("branch-bypassed binding escaped")

    changed = list(routed)
    changed[1] = Instruction(0x102, routed[1].raw, "callq",
                             (f"0x201 <{BINDING}>",))
    try:
        _check_route(tuple(changed), OWNED)
    except ValueError as error:
        if "call target differs from its PE bytes" not in str(error):
            raise AssertionError(f"forged call target lacked bounded reason: {error}") from error
    else:
        raise AssertionError("forged call target escaped")

    changed = list(routed)
    changed[0] = Instruction(0x100, routed[0].raw, "jmp", ("0x107",))
    try:
        _check_route(tuple(changed), OWNED)
    except ValueError as error:
        if "branch has unsupported relative lowering" not in str(error):
            raise AssertionError(f"forged branch opcode lacked bounded reason: {error}") from error
    else:
        raise AssertionError("forged branch opcode escaped")


def _symbol_address(objdump, binary, symbol):
    code = subprocess.check_output(
        [str(objdump), "-d", f"--disassemble-symbols={symbol}", str(binary)],
        text=True, timeout=20).lower()
    found = [int(match[1], 16) for line in code.splitlines()
             if (match := HEADER.match(line)) and match[2] == symbol.lower()]
    if len(found) != 1:
        raise AssertionError(f"linked helper mutation target is absent: {symbol}")
    return found[0]


def check_helper_route_mutations(checker, binary, report, private, directory, objdump):
    check_helper_route_internal_cases()
    image = binary.read_bytes()
    layout = parse_image(image)
    codes = {name: subprocess.check_output(
        [str(objdump), "-d", f"--disassemble-symbols={name}", str(binary)],
        text=True, timeout=20).lower() for name in (OWNED, MEASURED)}
    check_helper_routes(image, codes)
    owned = _instructions(codes[OWNED], image, OWNED)
    measured = _instructions(codes[MEASURED], image, MEASURED)
    binding = [item for item in owned if item.opcode in ("call", "callq") and
               len(item.operands) == 1 and
               (match := DIRECT.fullmatch(item.operands[0])) and match[2] == BINDING]
    query = [item for item in owned if item.opcode in ("call", "callq") and
             len(item.operands) == 1 and
             (match := DIRECT.fullmatch(item.operands[0])) and match[2] == OWNED_QUERY]
    failure = [item for item in owned if item.opcode in ("call", "callq") and
               len(item.operands) == 1 and
               (match := DIRECT.fullmatch(item.operands[0])) and match[2] == FAILURE]
    measured_binding = [item for item in measured if item.opcode in ("call", "callq") and
                        len(item.operands) == 1 and
                        (match := DIRECT.fullmatch(item.operands[0])) and match[2] == BINDING]
    if len(binding) != 1 or len(query) != 1 or len(failure) != 1:
        raise AssertionError("owned helper mutation anchors changed")
    if len(measured_binding) != 1:
        raise AssertionError("measured helper binding mutation anchor changed")
    binding, query, failure = binding[0], query[0], failure[0]
    measured_binding = measured_binding[0]
    status = _symbol_address(objdump, binary, BINDING_STATUS)
    binding_target, _ = _target(binding, "call")
    mutations = (
        ("redirect-binding", binding,
         b"\xe8" + struct.pack("<i", status - binding.address - 5),
         "call target differs from required route"),
        ("redirect-measured-binding", measured_binding,
         b"\xe8" + struct.pack("<i", status - measured_binding.address - 5),
         "call target differs from required route"),
        ("skip-binding", binding, b"\xe9\x00\x00\x00\x00",
         "lacks a binding, query or failure call"),
        ("redirect-query", query,
         b"\xe8" + struct.pack("<i", status - query.address - 5),
         "call target differs from required route"),
        ("duplicate-binding", query,
         b"\xe8" + struct.pack("<i", binding_target - query.address - 5),
         "duplicate binding, query or failure calls"),
        ("skip-failure", failure, b"\xe9\x00\x00\x00\x00",
         "lacks a binding, query or failure call"),
    )
    for label, anchor, changed, reason in mutations:
        if len(changed) != len(anchor.raw):
            raise AssertionError(f"helper {label} mutation changed instruction length")
        mutant = directory / f"helper-route-{label}.exe"
        mutant.write_bytes(_replace(image, layout, anchor, changed))
        final = directory / f"helper-route-{label}.final.json"
        final.write_text("stale final output")
        result = subprocess.run([*map(str, checker), str(mutant), str(report),
                                 "--contribution-input", str(private), "--output", str(final)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 or final.exists() or reason not in result.stderr:
            raise AssertionError(f"linked helper {label} escaped bounded route: {result.stderr}")
        print(f"actual linked helper route {label} refused: {result.stderr.strip()}")
