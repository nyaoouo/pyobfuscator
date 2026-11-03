"""Seal a private typed plan into one pool, generated source and private key bindings."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from archive_format import (ACCESS_DOMAIN, BODY_DOMAIN, CORE, HEADER, MAGIC,
                            MAX_PACKAGE_BYTES, MAX_RECORDS, RECORD_BYTES, Kind, Record, parse_plan,
                            validate_record)


@dataclass(frozen=True)
class Package:
    data: bytes
    identity: bytes
    keys: tuple[bytes, ...]
    wrappers: tuple[str, ...]


def verify_bytes(package: bytes, expected: bytes, key: bytes) -> None:
    """Authenticate one exact typed bytes envelope without replacing its random nonces."""
    overhead = HEADER.size + RECORD_BYTES
    if (type(package) is not bytes or type(expected) is not bytes or type(key) is not bytes or
            len(key) != 32 or len(package) != overhead + len(expected)):
        raise ValueError("existing bytes envelope has invalid immutable inputs or capacity")
    header, core = package[:HEADER.size], package[HEADER.size:HEADER.size + CORE.size]
    magic, version, count, _, total = HEADER.unpack(header)
    if ((magic, version, count, total) != (MAGIC, 1, 1, len(package)) or
            CORE.unpack(core) != (0, Kind.bytes, 8, 1, len(expected), overhead, 0, 0)):
        raise ValueError("existing bytes envelope has a different typed archive profile")
    cursor = HEADER.size + CORE.size
    nonce, tag = package[cursor:cursor + 12], package[cursor + 12:cursor + 28]
    access_nonce, access_tag = package[cursor + 28:cursor + 40], package[cursor + 40:cursor + 56]
    try:
        AESGCM(key).decrypt(access_nonce, access_tag, ACCESS_DOMAIN + header + core + nonce + tag)
        actual = AESGCM(key).decrypt(nonce, package[overhead:] + tag, BODY_DOMAIN + header + core)
    except InvalidTag as error:
        raise ValueError("existing bytes envelope authentication failed") from error
    if actual != expected:
        raise ValueError("existing bytes envelope is stale for current material")


def seal(records: list[Record], *, keys: tuple[bytes, ...] | None = None) -> Package:
    if not 1 <= len(records) <= MAX_RECORDS or len({item.identity for item in records}) != len(records):
        raise ValueError("archive record count or identities are invalid")
    for record in records:
        validate_record(record)
    if keys is not None and (type(keys) is not tuple or len(keys) != len(records) or
            any(type(key) is not bytes or len(key) != 32 for key in keys)):
        raise ValueError("explicit archive keys must match the records with32 bytes each")
    total = HEADER.size + len(records) * RECORD_BYTES + sum(len(item.data) for item in records)
    if total > MAX_PACKAGE_BYTES:
        raise ValueError("archive package exceeds the format's byte budget")
    identity = secrets.token_bytes(16)
    header = HEADER.pack(MAGIC, 1, len(records), identity, total)
    supplied = keys
    descriptors, bodies, keys, wrappers = [], [], [], []
    offset = HEADER.size + len(records) * RECORD_BYTES
    for index, record in enumerate(records):
        key, nonce = supplied[index] if supplied is not None else secrets.token_bytes(32), secrets.token_bytes(12)
        access_nonce = secrets.token_bytes(12)
        while access_nonce == nonce:
            access_nonce = secrets.token_bytes(12)
        core = CORE.pack(index, record.kind, record.bit_width, record.alignment,
                         len(record.data), offset, record.byte_order, 0)
        sealed = AESGCM(key).encrypt(nonce, record.data, BODY_DOMAIN + header + core)
        body, tag = sealed[:-16], sealed[-16:]
        access_tag = AESGCM(key).encrypt(access_nonce, b"", ACCESS_DOMAIN + header + core + nonce + tag)
        descriptors.append(core + nonce + tag + access_nonce + access_tag)
        bodies.append(body)
        keys.append(key)
        wrappers.append(f"__pyobf_archive_{identity.hex()}_{index}")
        offset += len(body)
    return Package(header + b"".join(descriptors) + b"".join(bodies), identity, tuple(keys), tuple(wrappers))


def cpp_source(package: Package, records: list[Record]) -> str:
    rows = [", ".join(f"0x{byte:02x}" for byte in package.data[start:start + 16])
            for start in range(0, len(package.data), 16)]
    source = ('#include "archive/runtime.hpp"\n'
              '#include "pyobfuscator_native/cff_marker.hpp"\n\nnamespace {\n'
              'alignas(16) const std::uint8_t package_bytes[] = {\n    ' + ",\n    ".join(rows) + "\n};\n")
    source += "\n".join(f"pyobfuscator::native::archive::Cache cache_{index};" for index in range(len(records)))
    source += "\n}\n"
    for index, name in enumerate(package.wrappers):
        source += (f'extern "C" PYOBF_NATIVE_CFF_SDK void {name}(const std::uint8_t *key, '
                   'std::uint8_t *destination, std::size_t capacity) noexcept {\n'
                   f'    pyobfuscator::native::archive::require_record(package_bytes, sizeof(package_bytes), '
                   f'{index}, destination, capacity, cache_{index}, key);\n}}\n')
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("input", "package", "source", "bindings"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--allow-empty-plan", action="store_true",
                        help="emit a no-pool compiler handoff for a plan with zero records")
    args = parser.parse_args()
    if len({path.resolve() for path in (args.input, args.package, args.source, args.bindings)}) != 4:
        parser.error("input, package, source and private bindings paths must differ")
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_PACKAGE_BYTES * 3 + 1)
        if len(raw) > MAX_PACKAGE_BYTES * 3:
            raise ValueError("private archive plan exceeds its byte budget")
        records = parse_plan(json.loads(raw), allow_empty=args.allow_empty_plan)
        if records:
            package = seal(records)
            source = cpp_source(package, records)
        else:
            package = Package(b"", bytes(16), (), ())
            source = "// Empty compiler plan: no runtime archive, keys, caches or wrappers.\n"
        bindings = {"schema_version": 1, "plan_sha256": hashlib.sha256(raw).hexdigest(),
                    "archive_id": package.identity.hex(), "package_sha256": hashlib.sha256(package.data).hexdigest(),
                    "records": [{"id": record.identity, "index": index, "wrapper": package.wrappers[index],
                                 "key_hex": package.keys[index].hex(), "size": len(record.data),
                                 "alignment": record.alignment} for index, record in enumerate(records)]}
        args.package.write_bytes(package.data)
        args.source.write_text(source, encoding="utf-8")
        args.bindings.write_text(json.dumps(bindings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps({"records": len(records), "package_bytes": len(package.data),
                      "archive_id": package.identity.hex()}))


if __name__ == "__main__":
    main()
