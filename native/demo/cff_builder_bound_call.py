"""Bounded call-site proof for the Windows x64 bound-bootstrap route.

This proves caller instructions and their selected COFF contributions only.
The publication source and the effects of called functions remain outside
this local witness.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_builder_binding_status_effects import (_at, _boundaries, _check_plain_unwind,
                                                 _exact, _imm, _plain_transition)
from cff_builder_original_predicates import _mix, _states, _transition
from cff_joint_machine_evidence import DIRECT, Instruction, _graph, _instructions
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image


BOUND_CALL = ("_ZN12pyobfuscator6native20call_bound_bootstrapERKNS0_"
              "21BootstrapContextLeaseERKNS0_23BootstrapContextRequestE")
GETTER = "_ZN12pyobfuscator6native6detail19context_publicationEv"
LOCK = "_ZN12pyobfuscator6native6detail12context_lockERNSt3__16atomicIjEE"
UNLOCK = "_ZN12pyobfuscator6native6detail14context_unlockERNSt3__16atomicIjEE"
RETAIN = "_ZN12pyobfuscator6native6detail14retain_contextEPNS1_21BootstrapContextStateEb"
CTOR = ("_ZN12pyobfuscator6native21BootstrapContextLeaseC1EPNS0_6detail"
        "21BootstrapContextStateENS0_22BootstrapContextStatusE")
CTOR_ALIAS = CTOR.replace("LeaseC1", "LeaseC2")
INVOKE = ("_ZNK12pyobfuscator6native21BootstrapContextLease6invokeERKNS0_"
          "23BootstrapContextRequestE")
DTOR = "_ZN12pyobfuscator6native21BootstrapContextLeaseD1Ev"
DTOR_ALIAS = DTOR.replace("LeaseD1", "LeaseD2")
PUBLICATION = "_ZN12pyobfuscator6native6detail12_GLOBAL__N_111publicationE"
SALT = 0x49f1adc3
MASK32 = 0xffffffff


def _fail(reason):
    raise ValueError(f"bound-call route: {reason}")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate raw report key")
        result[key] = value
    return result


def _recipe(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8_000_000:
        _fail("bounded raw compiler report is required")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                            parse_constant=lambda _: _fail("nonfinite report number"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("bound-call route: invalid raw compiler report") from error
    rows = report.get("functions") if type(report) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        _fail("raw compiler report lacks bounded function rows")
    selected = [row for row in rows if type(row) is dict and row.get("function") == BOUND_CALL]
    if (len(selected) != 1 or selected[0].get("selected") is not True or
            selected[0].get("status") != "transformed" or
            selected[0].get("strategy") != "relative-tree" or
            selected[0].get("coverage_kind") != "decision-flow"):
        _fail("raw report lacks one transformed bound-call owner")
    row = selected[0]
    recipe = row.get("effective_recipe")
    totals = row.get("site_totals")
    roles = totals.get("body_roles") if type(totals) is dict else None
    real = roles.get("real") if type(roles) is dict else None
    if (type(recipe) is not dict or recipe.get("coverage") != "whole" or
            recipe.get("strategy") != "relative-tree" or
            type(real) is not int or real not in (9, 11)):
        _fail("unsupported bound-call recipe or real-body count")
    return recipe, real


def _subject(object_bytes, image_bytes, image, name, tag, aliases=()):
    try:
        subject = function_subject(object_bytes, image_bytes, image, tag, name,
                                   aliases=aliases)
    except ValueError as error:
        _fail(f"{name} COFF/PE contribution: {error}")
    if subject.kind != "function-contribution" or len(subject.ranges) != 1:
        _fail(f"{name} has an unsupported contribution extent")
    return subject.ranges[0]


def _call_target(item):
    target = DIRECT.fullmatch(item.operands[0]) if len(item.operands) == 1 else None
    if (item.opcode not in ("call", "callq") or len(item.raw) != 5 or
            item.raw[:1] != b"\xe8" or target is None):
        _fail("indirect or malformed bound-call callee")
    numeric = item.address + 5 + struct.unpack_from("<i", item.raw, 1)[0]
    if numeric != int(target[1], 16):
        _fail("call display differs from raw PE displacement")
    return numeric


def _relocations(object_bytes, image_bytes, image, owner, items, profile):
    obj = parse_object(object_bytes)
    names = {symbol.index: symbol for symbol in obj.symbols}
    roots = [symbol for symbol in obj.symbols if symbol.name == BOUND_CALL and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    if len(roots) != 1:
        _fail("missing unique bound-call COFF root")
    section = obj.sections[roots[0].section - 1]
    if section.size != owner.size:
        _fail("bound-call COFF/PE extents differ")
    resolver = Resolver(obj, image, image_symbols(image_bytes, image))
    expected_names = ([CTOR, INVOKE, DTOR, GETTER, LOCK, UNLOCK, RETAIN]
                      if profile == "none" else
                      [PUBLICATION, UNLOCK, CTOR_ALIAS, INVOKE, DTOR_ALIAS,
                       PUBLICATION, LOCK, PUBLICATION, RETAIN, PUBLICATION, UNLOCK])
    seen = []
    calls = {}
    data = []
    for rel in section.relocations:
        symbol = names.get(rel.target)
        if symbol is None or rel.kind != 4 or rel.offset < 1:
            _fail("unsupported bound-call relocation")
        name = symbol.name
        seen.append(name)
        field_offset = 3 if name == PUBLICATION else 1
        matching = [item for item in items if item.address - image.preferred_base - owner.rva +
                    field_offset == rel.offset]
        if len(matching) != 1:
            _fail("relocation lacks one decoded instruction")
        item = matching[0]
        offset = item.address - image.preferred_base - owner.rva
        addend = struct.unpack_from("<i", object_bytes, section.offset + rel.offset)[0]
        if addend != (8 if name == PUBLICATION and item.opcode == "movq" else 0):
            _fail("bound-call relocation has an unsupported COFF addend")
        target = image.preferred_base + resolver.target(rel.target) + addend
        if item.opcode in ("call", "callq"):
            if rel.offset != offset + 1 or _call_target(item) != target:
                _fail("call lacks exact root-symbol REL32 target")
            if name not in (GETTER, LOCK, UNLOCK, RETAIN, CTOR, CTOR_ALIAS,
                            INVOKE, DTOR, DTOR_ALIAS):
                _fail("call target is outside the closed callee set")
            if not any(symbol.name == name and symbol.type == 0x20 and
                       symbol.section > 0 and symbol.value == 0 for symbol in obj.symbols):
                _fail("call target has no unique COFF function root")
            calls[item.address] = name
        elif name == PUBLICATION and profile == "o2":
            if (item.opcode not in ("leaq", "movq") or
                    not item.raw.startswith(b"\x48\x8d\x0d" if item.opcode == "leaq"
                                            else b"\x48\x8b\x05") or
                    item.operands[1] != ("%rcx" if item.opcode == "leaq" else "%rax") or
                    rel.offset != offset + 3 or
                    int.from_bytes(item.raw[-4:], "little", signed=True) !=
                    target - (item.address + len(item.raw))):
                _fail("private publication RIP source differs from exact relocation")
            data.append((item, target))
        else:
            _fail("unrecognized bound-call data relocation")
    if seen != expected_names or len(calls) != (7 if profile == "none" else 7):
        _fail("bound-call relocation inventory differs from selected profile")
    all_calls = [item.address for item in items if item.opcode in ("call", "callq")]
    if set(all_calls) != set(calls):
        _fail("bound-call has an unbound direct or indirect call")
    if profile == "o2":
        if len(data) != 4 or len({target - (8 if item.opcode == "movq" else 0)
                                   for item, target in data}) != 1:
            _fail("publication lock and context reads use different globals")
    return calls, data


def _prefix(body, expected, label):
    try:
        return _exact(body, 0, expected, label)
    except ValueError as error:
        _fail(str(error))


def _choice(items, body, prefix, dispatcher, state_slot, current, expected,
            comparison, selector):
    item = body[prefix]
    if item.opcode != comparison[0] or item.operands != comparison[1] or \
            item.raw != comparison[2] or body[prefix + 1].opcode != selector:
        _fail("bound-call guard compares another value or selects another state")
    index = _at(items, item.address)
    checked = items
    root_index = _at(items, dispatcher)
    if (items[root_index - 1].opcode == "movl" and
            items[root_index - 1].operands == ("%eax", state_slot)):
        checked = items[:root_index] + [Instruction(dispatcher, b"\xeb\x00",
                                                   "jmp", (f"{dispatcher:#x}",))]
    try:
        false_arm, true_arm, salt, last = _transition(
            checked, index, dispatcher, int(state_slot.split("(")[0], 0))
    except ValueError as error:
        _fail(f"guard state mixer: {error}")
    if salt != SALT:
        _fail("guard uses another state salt")
    actual = tuple((current + (arm ^ _mix(current ^ salt))) & MASK32
                   for arm in (false_arm, true_arm))
    if actual != expected:
        _fail("guard reaches another report-derived state")
    after = _at(items, last) + 1
    if body[-1].address == last:
        if after >= len(items) or items[after].address != dispatcher:
            _fail("guard fallthrough misses dispatcher")
    elif (after >= len(items) or items[after].address != body[-1].address or
          body[-1].opcode not in ("jmp", "jmpq")):
        _fail("guard has a trailing operation or misses dispatcher")


def _plain(items, body, prefix, state_slot, dispatcher, current, next_state):
    try:
        observed = _plain_transition(body, prefix, state_slot, dispatcher,
                                     current, SALT)
    except ValueError as error:
        _fail(f"plain state mixer: {error}")
    if observed != next_state or body[-1].opcode not in ("jmp", "jmpq"):
        _fail("plain body reaches another report-derived state")
    if len(body) != prefix + 18:
        _fail("plain body has an unmodeled trailing operation")


def _check_sites(items, routes, states, slot, dispatcher, profile, calls, data):
    by_role = {number: [item for item in items if address <= item.address <
                        min(candidate for candidate in (*routes, dispatcher)
                            if candidate > address)]
               for number, address in enumerate(routes)}
    if any(not body for body in by_role.values()):
        _fail("report-derived body has no decoded instructions")
    s = states
    st = slot
    if profile == "none":
        patterns = {
            0: [("movq", ("0x30(%rsp)", "%rax")), ("movq", ("0x38(%rsp)", "%rcx")),
                ("movq", ("0x40(%rsp)", "%rdx")), ("movq", ("%rdx", "0x50(%rsp)")),
                ("movq", ("%rcx", "0x58(%rsp)")), ("movq", ("%rax", "0x60(%rsp)")),
                ("movq", ("0x58(%rsp)", "%rax")), ("movq", ("(%rax)", "%r8"))],
            2: [("callq", None), ("movq", ("%rax", "0x68(%rsp)")),
                ("movq", ("0x68(%rsp)", "%rcx")), ("callq", None),
                ("movl", ("$0x1", "0x74(%rsp)")), ("movq", ("0x68(%rsp)", "%rax")),
                ("movq", ("0x8(%rax)", "%rax")), ("movq", ("%rax", "0x78(%rsp)")),
                ("movq", ("0x78(%rsp)", "%r8"))],
            3: [("movq", ("0x78(%rsp)", "%r8")), ("movq", ("0x58(%rsp)", "%rax")),
                ("movq", ("(%rax)", "%r9"))],
            4: [("movq", ("0x78(%rsp)", "%rcx")), ("xorl", ("%edx", "%edx")),
                ("callq", None), ("movl", ("%eax", "0x90(%rsp)"))],
            5: [("movl", ("$0xa", "0x90(%rsp)"))],
            6: [("movl", ("0x90(%rsp)", "%eax")),
                ("movl", ("%eax", "0x74(%rsp)"))],
            7: [("movq", ("0x68(%rsp)", "%rcx")), ("callq", None),
                ("movl", ("0x74(%rsp)", "%r8d"))],
            8: [("movq", ("0x40(%rsp)", "%rax")),
                ("movl", ("0x74(%rsp)", "%ecx")), ("movl", ("%ecx", "(%rax)")),
                ("movq", ("$0x0", "0x8(%rax)"))],
            9: [("movq", ("0x78(%rsp)", "%rdx")),
                ("movl", ("0x74(%rsp)", "%r8d")),
                ("leaq", ("0x80(%rsp)", "%rcx")), ("callq", None),
                ("movq", ("0x40(%rsp)", "%rcx")),
                ("movq", ("0x60(%rsp)", "%r8")),
                ("leaq", ("0x80(%rsp)", "%rdx")), ("callq", None),
                ("leaq", ("0x80(%rsp)", "%rcx")), ("callq", None)],
        }
        for role, expected in patterns.items():
            _prefix(by_role[role], expected, f"source-none body {role}")
        checks = [(0, 8, (2, 1), "cmpq", ("$0x0", "%r8"), b"\x49\x83\xf8\x00", "cmovel"),
                  (2, 9, (7, 3), "cmpq", ("$0x0", "%r8"), b"\x49\x83\xf8\x00", "cmovnel"),
                  (3, 3, (5, 4), "cmpq", ("%r9", "%r8"), b"\x4d\x39\xc8", "cmovel"),
                  (7, 3, (9, 8), "cmpl", ("$0x0", "%r8d"), b"\x41\x83\xf8\x00", "cmovnel")]
        for role, prefix, arms, opcode, operands, raw, selector in checks:
            _choice(items, by_role[role], prefix + 3, dispatcher, st, s[role],
                    tuple(s[index] for index in arms), (opcode, operands, raw), selector)
        for role, prefix, following in ((1, 5, 10), (4, 4, 6), (5, 1, 6),
                                        (6, 2, 7), (8, 4, 10), (9, 10, 10)):
            _plain(items, by_role[role], prefix, st, dispatcher, s[role], s[following])
        call_roles = [(2, 0, GETTER), (2, 3, LOCK), (4, 2, RETAIN),
                      (7, 1, UNLOCK), (9, 3, CTOR), (9, 7, INVOKE),
                      (9, 9, DTOR)]
    else:
        patterns = {
            0: [("movq", ("0x38(%rsp)", "%rax")), ("movq", ("(%rax)", "%r8"))],
            1: [("movq", ("0x40(%rsp)", "%rax")),
                ("movq", ("0x38(%rsp)", "%rcx")),
                ("movl", ("0x8(%rcx)", "%ecx")), ("movl", ("%ecx", "(%rax)")),
                ("movq", ("$0x0", "0x8(%rax)"))],
            2: [("leaq", None), ("callq", None), ("movq", None),
                ("movq", ("%rax", "0x68(%rsp)")),
                ("movq", ("0x68(%rsp)", "%r8")),
                ("movl", ("$0x1", "0x60(%rsp)"))],
            3: [("movq", ("0x38(%rsp)", "%rax")),
                ("movq", ("(%rax)", "%r9")),
                ("movq", ("0x68(%rsp)", "%r8")),
                ("movl", ("$0xa", "0x60(%rsp)"))],
            4: [("movl", ("0x60(%rsp)", "%eax")),
                ("movl", ("%eax", "0x2c(%rsp)")), ("leaq", None),
                ("callq", None), ("movl", ("0x2c(%rsp)", "%eax")),
                ("movl", ("%eax", "0x64(%rsp)"))],
            5: [("movq", ("0x68(%rsp)", "%rcx")),
                ("xorl", ("%edx", "%edx")), ("callq", None),
                ("movl", ("%eax", "0x28(%rsp)")), ("leaq", None),
                ("callq", None), ("movl", ("0x28(%rsp)", "%r8d")),
                ("movl", ("%r8d", "0x64(%rsp)"))],
            6: [("movq", ("0x40(%rsp)", "%rax")),
                ("movl", ("0x64(%rsp)", "%ecx")),
                ("movl", ("%ecx", "(%rax)")),
                ("movq", ("$0x0", "0x8(%rax)"))],
            7: [("movq", ("0x68(%rsp)", "%rdx")),
                ("leaq", ("0x50(%rsp)", "%rcx")),
                ("xorl", ("%r8d", "%r8d")), ("callq", None),
                ("movq", ("0x40(%rsp)", "%rcx")),
                ("movq", ("0x30(%rsp)", "%r8")),
                ("leaq", ("0x50(%rsp)", "%rdx")), ("callq", None),
                ("leaq", ("0x50(%rsp)", "%rcx")), ("callq", None)],
        }
        for role, expected in patterns.items():
            _prefix(by_role[role], expected, f"optimized body {role}")
        checks = [(0, 2, (2, 1), "cmpq", ("$0x0", "%r8"), b"\x49\x83\xf8\x00", "cmovel"),
                  (2, 6, (3, 4), "cmpq", ("$0x0", "%r8"), b"\x49\x83\xf8\x00", "cmovel"),
                  (3, 4, (4, 5), "cmpq", ("%r9", "%r8"), b"\x4d\x39\xc8", "cmovel"),
                  (5, 8, (6, 7), "cmpl", ("$0x0", "%r8d"), b"\x41\x83\xf8\x00", "cmovel")]
        for role, prefix, arms, opcode, operands, raw, selector in checks:
            _choice(items, by_role[role], prefix + 3, dispatcher, st, s[role],
                    tuple(s[index] for index in arms), (opcode, operands, raw), selector)
        for role, prefix, following in ((1, 5, 8), (4, 6, 6),
                                        (6, 4, 8), (7, 10, 8)):
            _plain(items, by_role[role], prefix, st, dispatcher, s[role], s[following])
        call_roles = [(2, 1, LOCK), (4, 3, UNLOCK), (5, 2, RETAIN),
                      (5, 5, UNLOCK), (7, 3, CTOR_ALIAS), (7, 7, INVOKE),
                      (7, 9, DTOR_ALIAS)]
        if len(data) != 4 or [item.address for item, _ in data] != [
                by_role[4][2].address, by_role[2][0].address,
                by_role[2][2].address, by_role[5][4].address]:
            _fail("private publication data routes differ from expected body sites")
    for role, index, name in call_roles:
        if calls.get(by_role[role][index].address) != name:
            _fail(f"body {role} calls a different exact root: {name}")
    if set(calls) != {by_role[role][index].address for role, index, _ in call_roles}:
        _fail("call route has an unmodeled site")
    exit_role = 10 if profile == "none" else 8
    exit_body = by_role[exit_role]
    if ([(item.opcode, item.operands) for item in exit_body] !=
            [("movq", ("0x48(%rsp)", "%rax")),
             ("addq", ("$0x98" if profile == "none" else "$0x78", "%rsp")),
             ("retq", ())]):
        _fail("bound-call exit changes hidden-result return or frame")


def _dispatcher_contract(items, dispatcher, state_slot, profile, body_starts):
    """Constrain even unselected tree arms to read-only state routing."""
    tree = items[_at(items, dispatcher):]
    copy_slot = "0x2c(%rsp)" if profile == "none" else "0x24(%rsp)"
    if (len(tree) < 5 or
            (tree[0].opcode, tree[0].operands) !=
            ("movl", (state_slot, "%eax")) or
            (tree[1].opcode, tree[1].operands) !=
            ("movl", ("%eax", copy_slot))):
        _fail("dispatcher does not copy its encoded state into a separate tree slot")
    for item in tree[2:]:
        if item.opcode == "movl":
            if item.operands != (copy_slot, "%eax"):
                _fail("dispatcher has another state read or an indirect stack write")
        elif item.opcode == "cmpl":
            if (len(item.operands) != 2 or item.operands[1] != "%eax" or
                    not item.operands[0].startswith("$") or
                    not item.raw.startswith(b"\x3d") or len(item.raw) != 5):
                _fail("dispatcher compares an unmodeled value")
        elif item.opcode == "jae":
            continue  # _graph requires one exact in-interval instruction boundary.
        elif item.opcode in ("jmp", "jmpq"):
            target = DIRECT.fullmatch(item.operands[0])
            if target is None or (int(target[1], 16) < dispatcher and
                                  int(target[1], 16) not in body_starts):
                _fail("dispatcher enters a protected body after its guard")
        else:
            _fail("dispatcher contains an unmodeled operation")


def verify_builder_bound_call(object_bytes: bytes, image_bytes: bytes,
                              report_bytes: bytes, codes: dict) -> dict:
    """Prove the local route from expected lease and retained context to invoke."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes or
            type(codes) is not dict or set(codes) != {BOUND_CALL} or
            type(codes[BOUND_CALL]) is not str or not codes[BOUND_CALL]):
        _fail("exact object, image and bound-call disassembly are required")
    recipe, count = _recipe(report_bytes)
    profile = "none" if count == 11 else "o2"
    image = parse_image(image_bytes)
    owner = _subject(object_bytes, image_bytes, image, BOUND_CALL, 0xbc00)
    for index, (name, aliases) in enumerate(((GETTER, ()), (LOCK, ()),
                                            (UNLOCK, ()), (RETAIN, ()),
                                            (CTOR, (CTOR_ALIAS,)), (INVOKE, ()),
                                            (DTOR, (DTOR_ALIAS,)))):
        if name == GETTER and profile == "o2":
            continue
        _subject(object_bytes, image_bytes, image, name, 0xbc01 + index, aliases)
    try:
        items = _instructions(codes[BOUND_CALL], image_bytes, BOUND_CALL.lower())
    except ValueError as error:
        _fail(f"bound-call disassembly: {error}")
    if (not items or items[0].address != image.preferred_base + owner.rva or
            items[-1].address + len(items[-1].raw) !=
            image.preferred_base + owner.rva + owner.size):
        _fail("disassembly misses exact bound-call contribution")
    frame = 0x98 if profile == "none" else 0x78
    if (items[0].opcode != "subq" or items[0].operands !=
            (f"${frame:#x}", "%rsp")):
        _fail("unsupported Win64 frame allocation")
    try:
        _check_plain_unwind(image_bytes, image, owner, items[0], frame)
    except ValueError as error:
        _fail(f"Win64 frame/unwind: {error}")
    states = _states(BOUND_CALL, recipe)
    entry = [("movq", ("%r8", "0x30(%rsp)")),
             ("movq", ("%rdx", "0x38(%rsp)")),
             ("movq", ("%rcx", "0x40(%rsp)")),
             ("movq", ("%rcx", "0x48(%rsp)"))]
    _exact(items, 1, entry, "Win64 bound-call entry spills")
    state_item = items[5]
    slot = "0x94(%rsp)" if profile == "none" else "0x74(%rsp)"
    if (state_item.opcode != "movl" or state_item.operands !=
            (f"${states[0]:#x}", slot) or
            _imm(state_item, state_item.raw[:-4]) != states[0]):
        _fail("bound-call entry state differs from frozen report")
    jump = items[6]
    target = DIRECT.fullmatch(jump.operands[0]) if len(jump.operands) == 1 else None
    if jump.opcode not in ("jmp", "jmpq") or target is None:
        _fail("entry does not reach the relative-tree dispatcher")
    dispatcher = int(target[1], 16)
    try:
        routes = [_boundaries(items, dispatcher, states[:count], slot)[state]
                  for state in states[:count]]
    except ValueError as error:
        _fail(f"report-derived dispatcher route: {error}")
    if len(set(routes)) != count:
        _fail("two states alias a bound-call body")
    by_address, edges, call_items = _graph(items)
    if len(call_items) != 7 or dispatcher not in by_address:
        _fail("bound-call CFG has unsupported call or dispatcher inventory")
    body_starts = set(routes)
    for address, successors in edges.items():
        if address < dispatcher and address not in body_starts:
            for successor in successors:
                if successor in body_starts and successor != address + len(by_address[address].raw):
                    _fail("CFG bypasses dispatcher into a protected body")
    _dispatcher_contract(items, dispatcher, slot, profile, body_starts)
    calls, data = _relocations(object_bytes, image_bytes, image, owner, items, profile)
    _check_sites(items, routes, states, slot, dispatcher, profile, calls, data)
    return {
        "verified": True,
        "pointer_guard_verified": True,
        "retain_status_route_verified": True,
        "captured_lease_route_verified": True,
        "invoke_argument_route_verified": True,
        "publication_source_verified": False,
        "retain_effect_verified": False,
        "invoke_body_verified": False,
        "platform_lock_effect_verified": False,
        "transitive_binding_closed": False,
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
