"""Bounded data-only PE writes, shared by late record finalizers."""
from dataclasses import dataclass
import hashlib

from pe_layout import _disjoint, _span, parse_image


@dataclass(frozen=True)
class Write:
    offset: int
    data: bytes


def apply_writes(image, writes):
    before = parse_image(image)
    if type(writes) is not tuple or not writes:
        raise ValueError("PE data patch needs explicit nonempty writes")
    for write in writes:
        if type(write) is not Write or type(write.offset) is not int or type(write.data) is not bytes or not write.data:
            raise ValueError("PE data patch needs typed bounded byte writes")
        _span(image, write.offset, len(write.data), "data write")
        matches = [section for section in before.layout.sections if write.offset >= section.raw_offset and
            write.offset + len(write.data) <= section.raw_offset + min(section.raw_size, section.virtual_size or section.raw_size)]
        if len(matches) != 1 or matches[0].flags & 0xa20000a0 or matches[0].flags & 0x40000040 != 0x40000040:
            raise ValueError("PE data writes need one read-only non-executable initialized section")
    _disjoint([(write.offset, len(write.data)) for write in writes], "data writes")
    ordered = sorted(writes, key=lambda write: write.offset)
    result = bytearray(image)
    for write in ordered: result[write.offset:write.offset + len(write.data)] = write.data
    finalized = bytes(result)
    cursor = 0
    for write in ordered:
        if finalized[cursor:write.offset] != image[cursor:write.offset]:
            raise AssertionError("PE data patch changed bytes outside its declared writes")
        cursor = write.offset + len(write.data)
    if (len(finalized) != len(image) or finalized[cursor:] != image[cursor:] or parse_image(finalized) != before):
        raise AssertionError("PE data patch changed length, layout or bytes outside its writes")
    for section in before.layout.sections:
        if section.flags & 0x20000020:
            span = slice(section.raw_offset, section.raw_offset + section.raw_size)
            if image[span] != finalized[span]: raise AssertionError("PE data patch changed executable bytes")
    return finalized, {"layout_verified_unchanged": True, "executable_bytes_verified_unchanged": True,
        "image_before_sha256": hashlib.sha256(image).hexdigest(),
        "image_after_sha256": hashlib.sha256(finalized).hexdigest(),
        "write_regions": [{"offset": write.offset, "size": len(write.data)} for write in ordered]}
