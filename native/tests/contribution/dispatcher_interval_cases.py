"""Actual linked PE mutations for the bounded dispatcher interval gate."""

import struct
import subprocess

from cff_joint_machine_evidence import Instruction, _dispatcher_state, _entry_spills, _graph, _instructions
from cff_source_mixed_dispatcher import _leaf_groups, check_dispatcher_intervals
from linked_machine_mutations import _jump, _replace
from pe_layout import parse_image


def check_dispatcher_internal_rejections():
    # A same-length mutation cannot encode the production disp32 state+1 alias.
    # Keep this precise overlap rule pinned beside the actual PE mutations.
    frame = 0xc8
    read = Instruction(100, bytes.fromhex("8b 84 24 c4 00 00 00"),
                       "movl", ("0xc4(%rsp)", "%eax"))
    overlap = Instruction(107, bytes.fromhex("89 84 24 c5 00 00 00"),
                          "movl", ("%eax", "0xc5(%rsp)"))
    try:
        check_dispatcher_intervals((read, overlap), {100: read, 107: overlap},
                                   {}, 100, -4, frame, ())
    except ValueError as error:
        if "overwrites its state slot" not in str(error):
            raise AssertionError("dispatcher partial state alias lacked bounded reason") from error
    else:
        raise AssertionError("dispatcher partial state alias escaped")

    # CFG reachability on one arm cannot establish executable helper reachability.
    try:
        _leaf_groups(10, 100, {10: object(), 20: object(), 30: object()},
                     {10: (20, 30), 20: (), 30: ()}, {20: 0})
    except ValueError as error:
        if "conditional branch" not in str(error):
            raise AssertionError("conditional leaf route lacked bounded reason") from error
    else:
        raise AssertionError("conditional leaf route escaped")


def check_dispatcher_interval_mutations(checker, binary, report, private,
                                        directory, objdump):
    check_dispatcher_internal_rejections()
    image = binary.read_bytes()
    layout = parse_image(image)
    code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                    str(binary)], text=True, timeout=20).lower()
    instructions = _instructions(code, image, "mixed_site_body")
    by_address, graph, _ = _graph(instructions)
    frame, _ = _entry_spills(instructions)
    _dispatcher_state(instructions, graph, frame)
    first_branch = next(item for item in instructions if item.opcode in ("jmp", "jmpq", "jae"))
    dispatcher = graph[first_branch.address][0]
    comparisons = [item for item in instructions if item.address >= dispatcher and
                   item.opcode == "cmpl" and item.operands[-1:] == ("%eax",)]
    if len(comparisons) < 2 or any(item.raw[:1] != b"\x3d" or len(item.raw) != 5
                                   for item in comparisons):
        raise AssertionError("dispatcher mutation fixture lost its imm32 tree")
    root, inner = comparisons[:2]
    if int(root.operands[0][1:], 0) <= int(inner.operands[0][1:], 0):
        raise AssertionError("dispatcher mutation fixture lost its left interval")
    root_bytes = root.raw[:1] + struct.pack("<I", 0)
    inner_bytes = inner.raw[:1] + root.raw[1:]
    copies = [item for item in instructions if dispatcher <= item.address < root.address and
              item.opcode == "movl" and item.operands[0] == "%eax"]
    if len(copies) != 1 or copies[0].raw[:3] != bytes.fromhex("89 44 24"):
        raise AssertionError("dispatcher mutation fixture lost its state copy")
    copy = copies[0]
    alternate = copy.raw[:3] + bytes((copy.raw[3] ^ 4,))
    inner_branch = by_address[inner.address + len(inner.raw)]
    if inner_branch.opcode != "jae" or inner_branch.raw[:1] != b"\x73":
        raise AssertionError("dispatcher mutation fixture lost its short inner branch")
    skipped_copy = by_address[graph[inner_branch.address][0]]
    skipped_compare = by_address[skipped_copy.address + len(skipped_copy.raw)]
    if skipped_compare.opcode != "cmpl":
        raise AssertionError("dispatcher mutation fixture lost its bypassable comparison")
    skipped_branch = by_address[skipped_compare.address + len(skipped_compare.raw)]
    if skipped_branch.opcode != "jae":
        raise AssertionError("dispatcher mutation fixture lost its bypassable branch")
    bypass_target = graph[skipped_branch.address][0]
    displacement = bypass_target - inner_branch.address - 2
    if not -128 <= displacement <= 127:
        raise AssertionError("dispatcher mutation fixture lost its short bypass")
    bypass = b"\x73" + struct.pack("<b", displacement)
    leaves = [item for item in instructions if item.address >= dispatcher and
              item.opcode in ("jmp", "jmpq") and graph[item.address][0] < dispatcher]
    if len(leaves) < 4 or len(leaves[0].raw) != 5 or len(leaves[2].raw) != 5:
        raise AssertionError("dispatcher mutation fixture lost its leaf routes")
    mutations = (
        ("root-zero", root, root_bytes, "empty unsigned interval"),
        ("inner-equal-root", inner, inner_bytes, "empty unsigned interval"),
        ("state-copy", copy, alternate, "unknown state copy"),
        ("duplicate-leaf-target", leaves[0], _jump(leaves[0], graph[leaves[2].address][0]),
         "duplicate or missing leaves"),
        ("skipped-comparison", inner_branch, bypass,
         "unvisited comparison or leaf"),
    )
    for label, item, raw, reason in mutations:
        mutant = directory / f"dispatcher-{label}.exe"
        final = directory / f"dispatcher-{label}.final.json"
        mutant.write_bytes(_replace(image, layout, item, raw))
        result = subprocess.run([*map(str, checker), str(mutant), str(report),
                                 "--contribution-input", str(private), "--output", str(final)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 or final.exists() or reason not in result.stderr:
            raise AssertionError(f"linked dispatcher {label} escaped bounded gate: {result.stderr}")
        print(f"actual linked dispatcher {label} refused: {result.stderr.strip()}")
