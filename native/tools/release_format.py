"""Fixed v1 public release-key mask records; this is not issuer authorization."""

from __future__ import annotations

import hashlib
import struct

from path_fold_reference import serialize

MAGIC = b"PYOBF-RELKEY-v1\0"
VERSION = 1
SIZE = 64
MASK_OFFSET = 24
DOMAIN = b"pyobf.native.release.fold.v1\0"
_RECORD = struct.Struct("<16sII32s8s")
PLACEHOLDER = _RECORD.pack(MAGIC, VERSION, SIZE, bytes(32), bytes(8))


def expansion(state) -> bytes:
    return hashlib.sha256(DOMAIN + serialize(state)).digest()


def record_mask(record: bytes) -> bytes:
    if type(record) is not bytes or len(record) != SIZE:
        raise ValueError("release record must contain exactly64 bytes")
    magic, version, size, mask, reserved = _RECORD.unpack(record)
    if magic != MAGIC or version != VERSION or size != SIZE or reserved != bytes(8):
        raise ValueError("release record has an unsupported header or reserved data")
    return mask


def build_record(key: bytes, state) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("release content key must contain exactly32 bytes")
    mask = bytes(left ^ right for left, right in zip(key, expansion(state)))
    return _RECORD.pack(MAGIC, VERSION, SIZE, mask, bytes(8))
