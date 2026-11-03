"""Owner-domain canonical host digest model; no native observation/cache authority."""
import hashlib
import struct

from code_subject import KINDS, Subject, _word, validate_subject
from pe_layout import Image, _disjoint, read_rva, rva_section
from pe_relocations import MAX_RELOCATIONS, relocations

SCHEME = "pe-amd64-dir64-owner-sha256-v1"
DOMAIN = b"pyobf.native.code.observation.v1\0"


def _digest(image: Image, subject: Subject, fixups: tuple[int, ...], owner: int,
        loaded_base: int, reader) -> bytes:
    """Hash this owner's fresh reader calls; never reuse another owner's digest/read."""
    validate_subject(image, subject)
    _word(owner, "owner")
    if (type(loaded_base) is not int or not 0 <= loaded_base < 1 << 64 or
            loaded_base + image.layout.image_size > 1 << 64 or
            image.preferred_base + image.layout.image_size > 1 << 64):
        raise ValueError("code observation has an invalid module base")
    if type(fixups) is not tuple or len(fixups) > MAX_RELOCATIONS:
        raise ValueError("code observation exceeds its relocation budget")
    for target in fixups:
        rva_section(image, target, 8)
    _disjoint([(target, 8) for target in fixups], "base relocation fields")
    kind = KINDS[subject.kind]
    digest = hashlib.sha256(DOMAIN + struct.pack("<IIIII", 1, kind, subject.tag, owner, len(subject.ranges)))
    for span in subject.ranges:
        digest.update(struct.pack("<II", span.rva, span.size))
    delta = loaded_base - image.preferred_base
    for span in subject.ranges:
        raw = reader(span.rva, span.size)
        if type(raw) is not bytes or len(raw) != span.size:
            raise ValueError("code observation reader returned an incomplete span")
        content = bytearray(raw)
        for target in fixups:
            if target >= span.rva + span.size or target + 8 <= span.rva:
                continue
            relative = target - span.rva
            if relative < 0 or relative + 8 > span.size:
                raise ValueError("base relocation straddles a code subject boundary")
            value = (int.from_bytes(content[relative:relative + 8], "little") - delta) & ((1 << 64) - 1)
            struct.pack_into("<Q", content, relative, value)
        digest.update(content)
    return digest.digest()


def observation_digest(image: Image, subject: Subject, fixups: tuple[int, ...], owner: int,
        loaded_base: int, reader) -> bytes:
    if type(loaded_base) is not int or loaded_base <= 0:
        raise ValueError("code observation needs a nonzero actual module base")
    return _digest(image, subject, fixups, owner, loaded_base, reader)


def reference_digest(data: bytes, image: Image, subject: Subject, owner: int) -> bytes:
    # A linker may choose ImageBase zero; this logical file view is not a loaded module.
    return _digest(image, subject, relocations(data, image), owner, image.preferred_base,
        lambda rva, size: read_rva(data, image, rva, size))
