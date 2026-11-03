"""Immutable symbolic selection and identity, fixed before observing-image codegen."""
from dataclasses import dataclass
import hashlib
import json

from reference_identity import Identity, identity_bytes

MAX_PLAN = 256 * 1024
BUILD_DOMAIN = b"pyobf.native.code.reference.build.v1\0"


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("reference plan has missing or unknown fields")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate reference plan field")
        result[key] = value
    return result


def _role(value):
    if type(value) is not str or len(value) != 32:
        raise ValueError("reference role needs nonzero16 bytes in canonical lowercase hex")
    try: decoded = bytes.fromhex(value)
    except ValueError as error: raise ValueError("invalid reference role hex") from error
    if len(decoded) != 16 or not any(decoded) or decoded.hex() != value:
        raise ValueError("reference role needs nonzero16 bytes in canonical lowercase hex")
    return decoded


def _symbol(value):
    if type(value) is not str or not 0 < len(value) <= 256 or any(ord(char) < 32 for char in value):
        raise ValueError("reference selector needs a bounded exact symbol")
    return value


@dataclass(frozen=True)
class Selection:
    identity: Identity
    symbol: str = ""
    aliases: tuple[str, ...] = ()
    fragments: tuple[str, ...] = ()
    generated_helpers: bool = False


@dataclass(frozen=True)
class Plan:
    canonical: bytes
    digest: bytes
    container: bytes
    records: tuple[Selection, ...]
    scope_materials: tuple[int, ...] = ()


def parse_plan(source):
    if type(source) is not bytes or not 0 < len(source) <= MAX_PLAN:
        raise ValueError("reference plan needs bounded JSON bytes")
    raw = json.loads(source, object_pairs_hook=_unique)
    if type(raw) is not dict or type(raw.get("schema_version")) is not int or raw["schema_version"] not in (1, 2):
        raise ValueError("unsupported reference plan version")
    _object(raw, ("schema_version", "build_seed", "container", "records",
        *(("scope_materials",) if raw["schema_version"] == 2 else ())))
    _role(raw["build_seed"]); container = _role(raw["container"])
    if type(raw["records"]) is not list or not 1 <= len(raw["records"]) <= 64:
        raise ValueError("reference plan needs1..64 records")
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(canonical).digest()
    build = hashlib.sha256(BUILD_DOMAIN + canonical).digest()[:16]
    records, seen = [], set()
    for entry in raw["records"]:
        _object(entry, ("image", "owner", "subject", "kind", "stage", "capacity", "selector"))
        identity = Identity(build, _role(entry["image"]), *(entry[name] for name in
            ("owner", "subject", "kind", "stage", "capacity")))
        identity_bytes(identity)
        key = (identity.image, identity.owner, identity.subject, identity.stage)
        if key in seen: raise ValueError("duplicate reference identity")
        seen.add(key)
        selector = entry["selector"]
        if identity.kind == 1:
            _object(selector, ("section",))
            if selector["section"] != ".text": raise ValueError("reference section must be .text")
            selection = Selection(identity)
        elif identity.kind == 2:
            _object(selector, ("symbol",))
            selection = Selection(identity, _symbol(selector["symbol"]))
        else:
            _object(selector, ("symbol", "aliases", "fragments",
                *(("generated_helpers",) if type(selector) is dict and "generated_helpers" in selector else ())))
            generated = selector.get("generated_helpers", False)
            if type(generated) is not bool: raise ValueError("generated helper selection must be Boolean")
            names = []
            for field in ("aliases", "fragments"):
                if type(selector[field]) is not list or len(selector[field]) > 1024:
                    raise ValueError("reference aliases/fragments need bounded explicit lists")
                names.append(tuple(_symbol(name) for name in selector[field]))
            all_names = (_symbol(selector["symbol"]), *names[0], *names[1])
            if len(set(all_names)) != len(all_names): raise ValueError("duplicate reference function anchor")
            selection = Selection(identity, all_names[0], *names, generated)
        records.append(selection)
    materials = raw.get("scope_materials", [])
    if raw["schema_version"] == 2 and (type(materials) is not list or not materials or
            any(type(index) is not int or not 0 <= index < len(records) for index in materials) or
            materials != sorted(set(materials)) or any(records[index].identity.stage != 2 for index in materials)):
        raise ValueError("scoped material indices must be distinct ordered post-release records")
    return Plan(canonical, digest, container, tuple(records), tuple(materials))
