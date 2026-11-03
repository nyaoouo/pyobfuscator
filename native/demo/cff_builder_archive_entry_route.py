"""Bounded Win64 proof from the selected archive entry to its first-use arm.

The route is conditional on successful, nonfaulting parse/storage/access
guards. Callee effects, arbitrary runtime memory, and the atomic operation
remain outside it.
"""

from __future__ import annotations

import hashlib
import struct

from cff_builder_archive_decoder_linkage import (
    ACQUIRE, ARCHIVE_DECODER_CALLEES, PARSE, _branch_target, _cfg, _items,
    _recipes, _selected_call, _subjects)
from cff_builder_archive_first_use import (
    LOAD, _body, _call, _choice, verify_builder_archive_first_use)
from cff_builder_original_predicates import _dispatcher_destination, _states
from coff_layout import parse_object
from coff_relocations import Resolver
from coff_symbols import image_symbols
from pe_layout import parse_image


OVERLAPS = "_ZN12pyobfuscator6native7archive12_GLOBAL__N_18overlapsEPKvyS4_y"
ACCESS = "_ZN12pyobfuscator6native7archive12_GLOBAL__N_113verify_accessERKNS1_10RecordViewEPKh"
SCOPE = "selected-archive-entry-success-to-first-use-win64-v1"


def _fail(reason: str) -> None:
    raise ValueError(f"archive entry route: {reason}")


def _exact(items, expected, label):
    if len(items) != len(expected) or any(
            item.opcode != opcode or item.operands != operands
            for item, (opcode, operands) in zip(items, expected)):
        _fail(f"{label} has an unsupported instruction route")


def _guard(items, body, state, dispatcher, prefix, comparison, raw_comparison,
           selection, raw_selection, false_target, true_target):
    # _choice pins the complete straight-line body, including all mixer and
    # state-write instructions. Pin the raw flag producer and cmov polarity as
    # well: the predecessor proof intentionally leaves these guards open.
    _choice(items, body, state, dispatcher, comparison, prefix,
            false_target, true_target)
    compare, selector = body[len(prefix) + 3:len(prefix) + 5]
    if (compare.raw != raw_comparison or selector.opcode != selection or
            selector.operands != ("%edx", "%ecx") or
            selector.raw != raw_selection):
        _fail("guard comparison or selector polarity differs")


def _prerequisites(object_bytes, image_bytes, report_bytes, codes,
                   decoder_proof, first_use_proof):
    if (type(object_bytes) is not bytes or type(image_bytes) is not bytes or
            type(report_bytes) is not bytes or type(codes) is not dict or
            set(codes) != set(ARCHIVE_DECODER_CALLEES) or
            any(type(code) is not str for code in codes.values()) or
            type(decoder_proof) is not dict or type(first_use_proof) is not dict):
        _fail("unsupported artifact, disassembly, or predecessor proof input")
    digests = {
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    expected_decoder = {
        "verified": True,
        "decoder_linkage_verified": True,
        "require_to_acquire_verified": True,
        "acquire_to_children_verified": True,
        "argument_chain_verified": True,
        "decoder_effect_verified": False,
        "cache_effect_verified": False,
        "platform_crypto_verified": False,
        "acquire_inter_state_reachability_verified": False,
        **digests,
    }
    if decoder_proof != expected_decoder:
        _fail("decoder predecessor proof does not bind these artifacts")
    # The first-use verifier itself recomputes decoder linkage on these bytes,
    # so forged predecessor dictionaries cannot bypass the earlier machine gate.
    if first_use_proof != verify_builder_archive_first_use(
            object_bytes, image_bytes, report_bytes, codes):
        _fail("first-use predecessor proof does not bind these artifacts")
    return digests


def verify_builder_archive_entry_route(object_bytes: bytes, image_bytes: bytes,
                                       report_bytes: bytes, codes: dict[str, str],
                                       decoder_proof: dict,
                                       first_use_proof: dict) -> dict:
    """Verify one selected success route into the proved atomic-load body."""
    try:
        digests = _prerequisites(object_bytes, image_bytes, report_bytes, codes,
                                 decoder_proof, first_use_proof)
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
                  for index in range(9)}

        parse = bodies[0]
        _exact(parse[:11], [
            ("leaq", ("0x68(%rsp)", "%rcx")),
            ("xorl", ("%edx", "%edx")),
            ("movl", ("$0x30", "%r8d")),
            (parse[3].opcode, parse[3].operands),
            ("movq", ("0x48(%rsp)", "%rcx")),
            ("movq", ("0x40(%rsp)", "%rdx")),
            ("movl", ("0x3c(%rsp)", "%r8d")),
            ("leaq", ("0x68(%rsp)", "%r9")),
            (parse[8].opcode, parse[8].operands),
            ("movl", ("%eax", "%r8d")),
            ("movl", ("$0x1", "0xa4(%rsp)")),
        ], "parse setup and result")
        if (parse[3] != _selected_call(items, "memset") or
                parse[8] != _selected_call(items, PARSE)):
            _fail("parse body misses its selected calls")
        _guard(items, parse, states[0], dispatcher,
               [(item.opcode, item.operands) for item in parse[:11]],
               ("cmpl", ("$0x0", "%r8d")), b"\x41\x83\xf8\x00",
               "cmovel", b"\x0f\x44\xca", states[18], states[1])

        key = bodies[1]
        key_prefix = [("movq", ("0x50(%rsp)", "%r8")),
                      ("movl", ("$0x2", "0xa4(%rsp)"))]
        _guard(items, key, states[1], dispatcher, key_prefix,
               ("cmpq", ("$0x0", "%r8")), b"\x49\x83\xf8\x00",
               "cmovel", b"\x0f\x44\xca", states[2], states[18])

        capacity = bodies[2]
        capacity_prefix = [
            ("movq", ("0x60(%rsp)", "%r8")),
            ("movq", ("0x80(%rsp)", "%rax")),
            ("movq", ("%rax", "0xa8(%rsp)")),
            ("movq", ("0xa8(%rsp)", "%r9")),
            ("movl", ("$0x2", "0xa4(%rsp)")),
        ]
        _guard(items, capacity, states[2], dispatcher, capacity_prefix,
               ("cmpq", ("%r9", "%r8")), b"\x4d\x39\xc8",
               "cmovbl", b"\x0f\x42\xca", states[3], states[18])

        destination = bodies[3]
        destination_prefix = [
            ("movq", ("0x30(%rsp)", "%rcx")),
            ("cmpq", ("$0x0", "0xa8(%rsp)")),
            ("setne", ("%al",)),
            ("cmpq", ("$0x0", "%rcx")),
            ("sete", ("%r8b",)),
            ("andb", ("%al", "%r8b")),
            ("movl", ("$0x2", "0xa4(%rsp)")),
        ]
        _guard(items, destination, states[3], dispatcher, destination_prefix,
               ("testb", ("$0x1", "%r8b")), b"\x41\xf6\xc0\x01",
               "cmovnel", b"\x0f\x45\xca", states[4], states[18])

        alignment = bodies[4]
        alignment_prefix = [
            ("movq", ("0x30(%rsp)", "%rax")),
            ("movl", ("0x90(%rsp)", "%ecx")),
            ("xorl", ("%edx", "%edx")),
            ("divq", ("%rcx",)),
            ("movq", ("%rdx", "%r8")),
            ("movl", ("$0x2", "0xa4(%rsp)")),
        ]
        _guard(items, alignment, states[4], dispatcher, alignment_prefix,
               ("cmpq", ("$0x0", "%r8")), b"\x49\x83\xf8\x00",
               "cmovel", b"\x0f\x44\xca", states[18], states[5])

        package_overlap = bodies[5]
        package_prefix = [
            ("movq", ("0x40(%rsp)", "%r9")),
            ("movq", ("0x48(%rsp)", "%r8")),
            ("movq", ("0x30(%rsp)", "%rcx")),
            ("movq", ("0xa8(%rsp)", "%rdx")),
            (package_overlap[4].opcode, package_overlap[4].operands),
            ("movb", ("%al", "%r8b")),
            ("movl", ("$0x2", "0xa4(%rsp)")),
        ]
        _exact(package_overlap[:7], package_prefix, "package overlap source")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE],
              package_overlap[4], OVERLAPS)
        _guard(items, package_overlap, states[5], dispatcher, package_prefix,
               ("testb", ("$0x1", "%r8b")), b"\x41\xf6\xc0\x01",
               "cmovnel", b"\x0f\x45\xca", states[6], states[18])

        cache_overlap = bodies[6]
        cache_prefix = [
            ("movq", ("0x58(%rsp)", "%r8")),
            ("movq", ("0x30(%rsp)", "%rcx")),
            ("movq", ("0xa8(%rsp)", "%rdx")),
            ("movl", ("$0x30", "%r9d")),
            (cache_overlap[4].opcode, cache_overlap[4].operands),
            ("movb", ("%al", "%r8b")),
            ("movl", ("$0x2", "0xa4(%rsp)")),
        ]
        _exact(cache_overlap[:7], cache_prefix, "cache overlap source")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE],
              cache_overlap[4], OVERLAPS)
        _guard(items, cache_overlap, states[6], dispatcher, cache_prefix,
               ("testb", ("$0x1", "%r8b")), b"\x41\xf6\xc0\x01",
               "cmovnel", b"\x0f\x45\xca", states[7], states[18])

        access = bodies[7]
        access_prefix = [
            ("movq", ("0x50(%rsp)", "%rdx")),
            ("leaq", ("0x68(%rsp)", "%rcx")),
            (access[2].opcode, access[2].operands),
            ("movb", ("%al", "%r8b")),
            ("movl", ("$0x3", "0xa4(%rsp)")),
        ]
        _exact(access[:5], access_prefix, "access verification source")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE],
              access[2], ACCESS)
        _guard(items, access, states[7], dispatcher, access_prefix,
               ("testb", ("$0x1", "%r8b")), b"\x41\xf6\xc0\x01",
               "cmovnel", b"\x0f\x45\xca", states[18], states[8])

        _exact(bodies[8][:2], [("movq", ("0x58(%rsp)", "%rcx")),
                              (bodies[8][1].opcode, bodies[8][1].operands)],
               "first-use join")
        _call(object_bytes, obj, resolver, image, spans[ACQUIRE],
              bodies[8][1], LOAD)
        return {
            "verified": True,
            "selected_success_path_to_first_use_verified": True,
            "parse_guard_route_verified": True,
            "storage_guard_route_verified": True,
            "access_guard_route_verified": True,
            "first_use_join_verified": True,
            "parse_effect_verified": False,
            "overlap_effect_verified": False,
            "access_effect_verified": False,
            "platform_atomic_effect_verified": False,
            "cache_effect_verified": False,
            "all_runtime_inputs_reach_arm_verified": False,
            "transitive_archive_effect_closed": False,
            "scope": SCOPE,
            **digests,
        }
    except (AttributeError, IndexError, KeyError, OverflowError, StopIteration,
            TypeError, struct.error) as error:
        raise ValueError("archive entry route: unsupported artifact shape") from error
