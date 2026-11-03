"""Independent private release descriptors, available before compiling a child."""
from __future__ import annotations

import json
import secrets

import path_fold_reference as fold

ROLES = ("environment", "support", "release")


def _object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f"private release {label} has missing or unknown fields")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate private release field")
        result[key] = value
    return result


def validate_material(material):
    _object(material, ("schema_version", "seed", "events"), "material")
    if type(material["schema_version"]) is not int or material["schema_version"] != 1:
        raise ValueError("private release material version is unsupported")
    _object(material["events"], ROLES, "event map")
    words, tags = [material["seed"]], []
    for role in ROLES:
        event = material["events"][role]
        _object(event, ("tag", "word"), "event")
        tags.append(event["tag"]); words.extend((event["tag"], event["word"]))
    if any(type(word) is not int or not 0 <= word < 1 << 32 for word in words):
        raise ValueError("private release event values must be unsigned32 integers")
    if len(set(tags)) != len(tags):
        raise ValueError("private release event tags must be distinct")
    return material


def parse_material(source: bytes):
    if type(source) is not bytes or len(source) > 16384:
        raise ValueError("private release material must be bounded JSON bytes")
    return validate_material(json.loads(source, object_pairs_hook=_unique))


def create_material():
    values = []
    while len(values) != 7:
        word = secrets.randbits(32)
        if word not in values: values.append(word)
    return validate_material({"schema_version": 1, "seed": values[0],
        "events": {role: {"tag": values[1 + index * 2], "word": values[2 + index * 2]}
                   for index, role in enumerate(ROLES)}})


def render_material_header(material, namespace="path_events") -> str:
    validate_material(material)
    if namespace not in ("path_events", "decoy_events"):
        raise ValueError("private release event namespace is unsupported")
    source = "#pragma once\n\n#include <cstdint>\n\n// Private generated build input.\n"
    source += f"namespace pyobfuscator::native::demo::{namespace} {{\n"
    source += f"inline constexpr std::uint32_t seed = 0x{material['seed']:08x}u;\n"
    for role in ROLES:
        for name in ("tag", "word"):
            source += f"inline constexpr std::uint32_t {role}_{name} = 0x{material['events'][role][name]:08x}u;\n"
    return source + "}\n"


def material_fold(material) -> tuple[int, ...]:
    validate_material(material)
    state = fold.initialize(material["seed"])
    for role in ROLES:
        event = material["events"][role]
        state = fold.advance(state, event["tag"], event["word"])
    return state
