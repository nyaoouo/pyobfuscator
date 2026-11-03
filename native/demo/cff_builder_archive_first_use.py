"""Bounded machine proof of the archive cache's conditional first-use arm.

The proof starts at the selected atomic load body. It does not establish that
normal acquisition reaches that body, or the effects of platform callees.
"""

from __future__ import annotations

import hashlib
import struct

from cff_builder_archive_decoder_linkage import (
    ACQUIRE, ARCHIVE_DECODER_CALLEES, DECODE, _branch_target, _cfg, _items,
    _recipes, _selected_call, _subjects, verify_builder_archive_decoder_linkage)
from cff_builder_original_predicates import (
    _dispatcher_destination, _encoded_immediate, _mix, _states, _transition)
from cff_joint_machine_evidence import DIRECT
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from pe_layout import parse_image


LOAD = "_ZN12pyobfuscator6native8platform13atomic_load32EPKNSt3__16atomicIjEE"
CAS = "_ZN12pyobfuscator6native8platform25atomic_compare_exchange32EPNSt3__16atomicIjEEjj"
STORE = "_ZN12pyobfuscator6native8platform14atomic_store32EPNSt3__16atomicIjEEj"
ERASE = "_ZN12pyobfuscator6native8platform5eraseEPvy"
MASK32 = 0xffffffff
STATE_SLOT = "0xbc(%rsp)"
TERMINAL = {"jmp", "jmpq", "ret", "retq"}


def _fail(reason):
    raise ValueError(f"archive first-use arm: {reason}")


def _exact(items, expected, label):
    if len(items) != len(expected) or any(
            item.opcode != opcode or item.operands != operands
            for item, (opcode, operands) in zip(items, expected)):
        _fail(f"{label} has an unsupported instruction route")


def _root(obj, name):
    found = [symbol for symbol in obj.symbols if symbol.name == name and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    if len(found) != 1:
        _fail(f"missing unique COFF root: {name}")
    return found[0]


def _call(object_bytes, obj, resolver, image, span, item, callee):
    match = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    target_rva = resolver.named(callee)
    target = image.preferred_base + target_rva
    if (item.opcode not in ("call", "callq") or len(item.raw) != 5 or
            item.raw[0] != 0xe8 or match is None or match[2] != callee.lower() or
            int(match[1], 16) != target or
            item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0] != target):
        _fail(f"{callee} call misses its exact PE target")
    section = obj.sections[_root(obj, ACQUIRE).section - 1]
    offset = item.address - image.preferred_base - span.rva
    if (not 0 <= offset <= section.size - 5 or
            object_bytes[section.offset + offset:section.offset + offset + 5] !=
            b"\xe8\0\0\0\0"):
        _fail(f"{callee} call misses its COFF instruction")
    relocations = [row for row in section.relocations if row.offset == offset + 1]
    if (len(relocations) != 1 or relocations[0].kind != 4 or
            relocations[0].target != _root(obj, callee).index):
        _fail(f"{callee} call lacks its exact COFF relocation")


def _body(items, successors, start, dispatcher):
    positions = {item.address: index for index, item in enumerate(items)}
    if start not in positions:
        _fail("selected state lacks an instruction boundary")
    begin = positions[start]
    if begin and items[begin - 1].opcode not in TERMINAL:
        _fail("selected state enters another body's interior")
    end = begin
    while end < len(items) and items[end].address != dispatcher:
        if items[end].opcode in TERMINAL:
            end += 1
            break
        end += 1
    body = items[begin:end]
    if not body or len(body) > 48:
        _fail("selected state body is missing or unbounded")
    interior = {item.address for item in body[1:]}
    if any(target in interior and source not in {item.address for item in body}
           for source, targets in successors.items() for target in targets):
        _fail("selected state body has an exterior interior-entry edge")
    for left, right in zip(body, body[1:]):
        if successors[left.address] != (right.address,):
            _fail("selected state body has a side exit")
    last = body[-1]
    if last.opcode in ("ret", "retq"):
        if successors[last.address]:
            _fail("selected return has a successor")
    elif successors[last.address] != (dispatcher,):
        _fail("selected state body misses its dispatcher return")
    return body


def _unconditional(body, state, dispatcher, target):
    falls_through = body[-1].address + len(body[-1].raw) == dispatcher
    tail = body[-17:] if falls_through else body[-18:]
    transition = tail if falls_through else tail[:-1]
    expected = [
        ("movl", (STATE_SLOT, "%eax")),
        ("movl", ("%eax", "%ecx")),
        ("xorl", (transition[2].operands[0], "%ecx")),
        ("movl", ("%ecx", "%edx")),
        ("shrl", ("$0x10", "%edx")),
        ("xorl", ("%edx", "%ecx")),
        ("imull", ("$0x7feb352d", "%ecx", "%ecx")),
        ("movl", ("%ecx", "%edx")),
        ("shrl", ("$0xf", "%edx")),
        ("xorl", ("%edx", "%ecx")),
        ("imull", ("$0x846ca68b", "%ecx", "%ecx")),
        ("movl", ("%ecx", "%edx")),
        ("shrl", ("$0x10", "%edx")),
        ("xorl", ("%edx", "%ecx")),
        ("xorl", (transition[14].operands[0], "%ecx")),
        ("addl", ("%ecx", "%eax")),
        ("movl", ("%eax", STATE_SLOT)),
    ]
    _exact(transition, expected, "unconditional encoded transition")
    salt = _encoded_immediate(transition[2], b"\x81\xf1")
    encoded = _encoded_immediate(transition[14], b"\x81\xf1")
    if (transition[6].raw != b"\x69\xc9\x2d\x35\xeb\x7f" or
            transition[10].raw != b"\x69\xc9\x8b\xa6\x6c\x84" or
            (not falls_through and (tail[17].opcode not in ("jmp", "jmpq") or
             _branch_target(tail[17], {item.address for item in body} | {dispatcher}) != dispatcher)) or
            (state + (_mix(state ^ salt) ^ encoded)) & MASK32 != target):
        _fail("unconditional encoded successor differs from selected state")


def _choice(items, body, state, dispatcher, compare, prefix, false_target,
            true_target, state_slot=0xbc):
    _exact(body[:len(prefix)], prefix, "conditional source")
    item = body[len(prefix) + 3]
    if item.opcode != compare[0] or item.operands != compare[1]:
        _fail("conditional source comparison differs")
    false_arm, true_arm, salt, written = _transition(
        items, items.index(item), dispatcher, state_slot)
    if body[-2].address != written or body[-1] != items[items.index(item) + 18]:
        _fail("conditional transition has extra or missing instructions")
    destinations = [(state + (_mix(state ^ salt) ^ arm)) & MASK32
                    for arm in (false_arm, true_arm)]
    if destinations != [false_target, true_target]:
        _fail("conditional encoded successors differ from selected states")


def verify_builder_archive_first_use(object_bytes: bytes, image_bytes: bytes,
                                     report_bytes: bytes, codes: dict[str, str]) -> dict:
    """Verify one selected Win64 conditional first-use arm, not cache effects."""
    try:
        if (type(object_bytes) is not bytes or type(image_bytes) is not bytes or
                type(report_bytes) is not bytes or type(codes) is not dict or
                set(codes) != set(ARCHIVE_DECODER_CALLEES) or
                any(type(code) is not str for code in codes.values())):
            _fail("unsupported artifact or five-symbol disassembly input")
        if verify_builder_archive_decoder_linkage(
                object_bytes, image_bytes, report_bytes, codes)["verified"] is not True:
            _fail("decoder linkage prerequisite is incomplete")
        recipes = _recipes(report_bytes)
        obj, image = parse_object(object_bytes), parse_image(image_bytes)
        resolver = Resolver(obj, image, image_symbols(image_bytes, image))
        spans = _subjects(object_bytes, image_bytes, image)
        items = _items(codes[ACQUIRE], image_bytes, image, ACQUIRE, spans[ACQUIRE])
        dispatcher = _branch_target(items[13], {item.address for item in items})
        protected = tuple((image.preferred_base + span.rva,
                           image.preferred_base + span.rva + span.size)
                          for span in spans.values())
        selected_calls = {_selected_call(items, name).address
                          for name in ARCHIVE_DECODER_CALLEES[2:]}
        successors = _cfg(items, protected, selected_calls, route=True)
        states = _states(ACQUIRE, recipes[ACQUIRE])[:21]
        starts = [_dispatcher_destination(items, dispatcher, state, 0xbc)
                  for state in states]
        if (len(states) != 21 or len(set(starts)) != 21 or
                recipes[ACQUIRE]["coverage"] != "whole"):
            _fail("unsupported selected real/routing-state inventory")
        bodies = {index: _body(items, successors, starts[index], dispatcher)
                  for index in (8, 9, 10, 11, 12, 14, 18, 20)}

        load, cas, decode, erase, store = (
            bodies[8], bodies[9], bodies[10], bodies[11], bodies[12])
        # The decoder prerequisite pins slot 0x58 to the sixth Win64 argument
        # and excludes later writes to that slot, including frame aliases.
        _exact(load[:5], [
            ("movq", ("0x58(%rsp)", "%rcx")),
            (load[1].opcode, load[1].operands),
            ("movl", ("%eax", "0xb4(%rsp)")),
            ("movl", ("0xb4(%rsp)", "%eax")),
            ("movl", ("%eax", "0xb8(%rsp)"))], "state load and snapshot")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE], load[1], LOAD)
        if len(load) != 23:
            _fail("atomic-load body has extra instructions")
        _unconditional(load, states[8], dispatcher, states[20])

        _choice(items, bodies[20], states[20], dispatcher,
                ("cmpl", ("$0x0", "%r8d")),
                [("movl", ("0xb8(%rsp)", "%r8d"))],
                states[19], states[9])
        _exact(cas[:5], [
            ("movq", ("0x58(%rsp)", "%rcx")),
            ("xorl", ("%edx", "%edx")),
            ("movl", ("$0x1", "%r8d")),
            (cas[3].opcode, cas[3].operands),
            ("movl", ("%eax", "%r8d"))], "CAS zero-to-one and result")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE], cas[3], CAS)
        if len(cas) != 27:
            _fail("CAS body has extra instructions")
        _choice(items, cas, states[9], dispatcher,
                ("cmpl", ("$0x0", "%r8d")), [
                    ("movq", ("0x58(%rsp)", "%rcx")),
                    ("xorl", ("%edx", "%edx")),
                    ("movl", ("$0x1", "%r8d")),
                    (cas[3].opcode, cas[3].operands),
                    ("movl", ("%eax", "%r8d"))], states[14], states[10])
        if cas[8].raw != b"\x41\x83\xf8\x00":
            _fail("CAS result zero comparison encoding differs")
        _unconditional(bodies[14], states[14], dispatcher, states[8])
        if len(bodies[14]) != 18:
            _fail("CAS retry body has extra instructions")

        _call(object_bytes, obj, resolver, image, spans[ACQUIRE], decode[13], DECODE)
        if len(decode) != 39:
            _fail("decode-result body has extra instructions")
        _exact(decode[14:17], [
            ("movb", ("%al", "%r8b")),
            ("movl", ("$0x0", "0x9c(%rsp)")),
            ("movl", ("$0x2", "0xa0(%rsp)"))], "decode result and ready publication")
        _choice(items, decode, states[10], dispatcher,
                ("testb", ("$0x1", "%r8b")),
                [(item.opcode, item.operands) for item in decode[:17]],
                states[11], states[12])
        _exact(erase[:5], [
            ("movq", ("0x30(%rsp)", "%rcx")),
            ("movq", ("0xa8(%rsp)", "%rdx")),
            (erase[2].opcode, erase[2].operands),
            ("movl", ("$0x4", "0x9c(%rsp)")),
            ("movl", ("$0x3", "0xa0(%rsp)"))], "decode failure erase and failed publication")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE], erase[2], ERASE)
        if len(erase) != 22:
            _fail("erase body has extra instructions")
        _unconditional(erase, states[11], dispatcher, states[12])
        _exact(store[:7], [
            ("movq", ("0x58(%rsp)", "%rcx")),
            ("movl", ("0xa0(%rsp)", "%edx")),
            ("movl", ("0x9c(%rsp)", "%eax")),
            ("movl", ("%eax", "0x2c(%rsp)")),
            (store[4].opcode, store[4].operands),
            ("movl", ("0x2c(%rsp)", "%eax")),
            ("movl", ("%eax", "0xa4(%rsp)"))], "state publication and return status")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE], store[4], STORE)
        if len(store) != 25:
            _fail("state-publication body has extra instructions")
        _unconditional(store, states[12], dispatcher, states[18])
        _exact(bodies[18], [
            ("movl", ("0xa4(%rsp)", "%eax")),
            ("addq", ("$0xc0", "%rsp")),
            ("popq", ("%rsi",)),
            (bodies[18][3].opcode, ())], "first-use status return")
        return {
            "verified": True,
            "conditional_first_use_arm_verified": True,
            "state_zero_cas_route_verified": True,
            "decode_result_route_verified": True,
            "failure_erase_route_verified": True,
            "state_publish_route_verified": True,
            "normal_first_use_reachability_verified": False,
            "decoder_effect_verified": False,
            "cache_effect_verified": False,
            "platform_crypto_verified": False,
            "cache_content_integrity_verified": False,
            "external_destination_integrity_verified": False,
            "transitive_archive_effect_closed": False,
            "scope": "selected-archive-conditional-first-use-arm-win64-v1",
            "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
            "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        }
    except (AttributeError, IndexError, KeyError, OverflowError, StopIteration,
            TypeError, struct.error) as error:
        raise ValueError("archive first-use arm: unsupported artifact shape") from error
