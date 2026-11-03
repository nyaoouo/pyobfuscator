"""Seal final canonical code references as one existing typed archive bytes record."""
import struct

from archive_format import HEADER as ARCHIVE_HEADER, RECORD_BYTES, Kind, Record
from code_observation import reference_digest
from code_subject import KINDS, validate_subject
from pack_archive import seal, verify_bytes
from pe_layout import parse_image
from pe_relocations import relocations
from reference_identity import derive_key, identity_bytes

MAGIC = b"PYOBF-CODEREF1\0\0"
HEADER = struct.Struct("<16s10IQ32s8s")
OVERHEAD = ARCHIVE_HEADER.size + RECORD_BYTES
assert len(MAGIC) == 16 and HEADER.size == 104 and OVERHEAD == 136


def plaintext(data, subject, identity):
    identity_bytes(identity)
    image = parse_image(data)
    validate_subject(image, subject)
    if KINDS[subject.kind] != identity.kind or subject.tag != identity.subject:
        raise ValueError("code reference identity differs from its declared canonical subject")
    fixups = relocations(data, image)
    body = HEADER.pack(MAGIC, 1, HEADER.size, 1, identity.kind, identity.subject, identity.owner,
        identity.stage, len(subject.ranges), len(fixups), image.layout.image_size,
        image.preferred_base, reference_digest(data, image, subject, identity.owner), bytes(8))
    body += b"".join(struct.pack("<II", span.rva, span.size) for span in subject.ranges)
    body += b"".join(struct.pack("<I", target) for target in fixups)
    capacity = identity.capacity - OVERHEAD
    if len(body) > capacity: raise ValueError("code reference descriptor exceeds its reserved slot")
    return body + bytes(capacity - len(body))


def build_reference(data, subject, identity, private_words):
    body = plaintext(data, subject, identity)
    record = Record("code-reference-v1", Kind.bytes, 8, 1, 0, body)
    return seal([record], keys=(derive_key(identity, private_words),)).data


def verify_reference(package, expected, identity, private_words):
    """Authenticate an already filled slot without replacing its random envelope."""
    if type(package) is not bytes or len(package) != identity.capacity or len(expected) != len(package) - OVERHEAD:
        raise ValueError("existing reference slot has invalid capacity")
    verify_bytes(package, expected, derive_key(identity, private_words))
