"""Explicit v2 release mask using the complete canonical observation and fixed identity."""
import hashlib
import struct

from path_fold_reference import serialize
from reference_identity import identity_bytes
from release_format import expansion as fold_expansion, record_mask as fold_mask

MAGIC = b"PYOBF-RELKEY-v2\0"
DOMAIN = b"pyobf.native.release.measured.v1\0"
RECORD = struct.Struct("<16sII32s8s")
PLACEHOLDER = RECORD.pack(MAGIC, 2, RECORD.size, bytes(32), bytes(8))


def expansion(state, identity, digest):
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("measured release needs exactly32 immutable digest bytes")
    return hashlib.sha256(DOMAIN + serialize(state) + identity_bytes(identity) + digest).digest()


def record_mask(record):
    if type(record) is not bytes or len(record) != RECORD.size:
        raise ValueError("measured release needs exactly64 record bytes")
    magic, version, size, mask, reserved = RECORD.unpack(record)
    if (magic, version, size, reserved) != (MAGIC, 2, RECORD.size, bytes(8)):
        raise ValueError("measured release refuses fold-only or malformed records")
    return mask


def build_record(key, state, identity, digest):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("measured release key needs exactly32 immutable bytes")
    mask = bytes(a ^ b for a, b in zip(key, expansion(state, identity, digest)))
    return RECORD.pack(MAGIC, 2, RECORD.size, mask, bytes(8))


def bind_draft(draft, state, identity, digest):
    key = bytes(left ^ right for left, right in zip(fold_mask(draft), fold_expansion(state)))
    return build_record(key, state, identity, digest)
