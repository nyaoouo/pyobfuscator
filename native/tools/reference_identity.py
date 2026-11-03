"""Independent pre-codegen identity and path-material key domain for code references."""
from dataclasses import dataclass
import hashlib
import struct

DOMAIN = b"pyobf.native.code.reference.key.v1\0"
IDENTITY = struct.Struct("<16s16sIIIII")
MAX_SLOT = 512 * 1024
MIN_SLOT = 248


@dataclass(frozen=True)
class Identity:
    build: bytes
    image: bytes
    owner: int
    subject: int
    kind: int
    stage: int
    capacity: int


def identity_bytes(identity):
    if (type(identity) is not Identity or
            any(type(value) is not bytes or len(value) != 16 or not any(value) for value in (identity.build, identity.image)) or
            any(type(value) is not int or not 0 < value < 1 << 32
                for value in (identity.owner, identity.subject, identity.kind, identity.stage, identity.capacity)) or
            identity.kind not in (1, 2, 3) or identity.stage not in (1, 2) or
            not MIN_SLOT <= identity.capacity <= MAX_SLOT):
        raise ValueError("code reference needs a bounded independent build/image/owner/subject/stage identity")
    return IDENTITY.pack(identity.build, identity.image, identity.owner, identity.subject,
        identity.kind, identity.stage, identity.capacity)


def derive_key(identity, private_words):
    encoded = identity_bytes(identity)
    if (type(private_words) is not tuple or len(private_words) != 8 or
            any(type(word) is not int or not 0 <= word < 1 << 32 for word in private_words)):
        raise ValueError("code reference key needs eight private unsigned32 words")
    return hashlib.sha256(DOMAIN + encoded + struct.pack("<8I", *private_words)).digest()
