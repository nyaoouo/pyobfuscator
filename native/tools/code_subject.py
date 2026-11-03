"""Canonical build references and host observation model; not a native integrity provider."""
from __future__ import annotations

from dataclasses import dataclass
import struct

from pe_layout import Image, _disjoint, data_directory, read_rva, rva_section

MAX_BYTES = 64 * 1024 * 1024
MAX_RANGES = 1024
MAX_RUNTIME_FUNCTIONS = 65536
KINDS = {"section": 1, "unwind-interval": 2, "function-contribution": 3}


@dataclass(frozen=True)
class Range:
    rva: int
    size: int


@dataclass(frozen=True)
class Subject:
    tag: int
    kind: str
    label: str
    ranges: tuple[Range, ...]


def _word(value, label):
    if type(value) is not int or not 0 < value < 1 << 32:
        raise ValueError(f"code subject {label} must be nonzero unsigned32")


def _executable(image: Image, span: Range):
    section = rva_section(image, span.rva, span.size, logical=True)
    if section.flags & 0x60000000 != 0x60000000 or section.flags & 0x82000000:
        raise ValueError("code subject needs stable readable executable non-discardable bytes")


def validate_subject(image: Image, subject: Subject):
    _word(subject.tag, "tag")
    if subject.kind not in KINDS:
        raise ValueError("unsupported code subject scope; complete function closure is not implicit")
    if type(subject.label) is not str or not 0 < len(subject.label) <= 256:
        raise ValueError("code subject needs a bounded diagnostic label")
    if type(subject.ranges) is not tuple or not 0 < len(subject.ranges) <= MAX_RANGES:
        raise ValueError("code subject exceeds its range budget")
    for span in subject.ranges:
        if type(span) is not Range:
            raise ValueError("code subject needs typed ranges")
        _executable(image, span)
    if list(subject.ranges) != sorted(subject.ranges, key=lambda span: span.rva):
        raise ValueError("code subject ranges must have canonical ascending order")
    _disjoint([(span.rva, span.size) for span in subject.ranges], "code subject ranges")
    if sum(span.size for span in subject.ranges) > MAX_BYTES:
        raise ValueError("code subject exceeds its byte budget")
    return subject


def text_subject(image: Image, tag: int) -> Subject:
    matches = [section for section in image.layout.sections if section.name == b".text"]
    if len(matches) != 1:
        raise ValueError("code subject needs exactly one .text section")
    section = matches[0]
    return validate_subject(image, Subject(tag, "section", ".text",
        (Range(section.rva, section.virtual_size or section.raw_size),)))


def unwind_interval(data: bytes, image: Image, tag: int, begin_rva: int) -> Subject:
    """An exact RUNTIME_FUNCTION interval, not inferred full function/fragment ownership."""
    _word(begin_rva, "entry RVA")
    rva, size = data_directory(image, 3)
    if not size or rva % 4 or size % 12 or size // 12 > MAX_RUNTIME_FUNCTIONS:
        raise ValueError("code subject needs a bounded AMD64 runtime-function directory")
    rows = tuple(struct.iter_unpack("<III", read_rva(data, image, rva, size)))
    if list(rows) != sorted(rows, key=lambda row: row[0]):
        raise ValueError("runtime-function intervals are not ordered")
    for begin, end, _ in rows:
        _executable(image, Range(begin, end - begin))
    _disjoint([(begin, end - begin) for begin, end, _ in rows], "runtime-function intervals")
    matches = [row for row in rows if row[0] == begin_rva]
    if len(matches) != 1:
        raise ValueError("code subject entry lacks one exact runtime-function interval")
    begin, end, unwind = matches[0]
    if unwind % 4:
        raise ValueError("runtime-function unwind information is unaligned")
    header = read_rva(data, image, unwind, 4)
    version, flags = header[0] & 7, header[0] >> 3
    if version != 1 or flags & ~7 or flags & 4:
        raise ValueError("unwind version/chained fragments need unsupported closure metadata")
    extent = (4 + header[2] * 2 + 3) & ~3
    read_rva(data, image, unwind, extent + (4 if flags & 3 else 0))
    return validate_subject(image, Subject(tag, "unwind-interval", f"rva:{begin:x}", (Range(begin, end - begin),)))
