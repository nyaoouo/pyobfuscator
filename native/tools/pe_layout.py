"""Bounded unsigned AMD64 PE layout shared by finalizers and code references."""
from __future__ import annotations

from dataclasses import dataclass
import struct

@dataclass(frozen=True)
class Section:
    name: bytes
    virtual_size: int
    rva: int
    raw_size: int
    raw_offset: int
    flags: int


@dataclass(frozen=True)
class Layout:
    headers_size: int
    image_size: int
    sections: tuple[Section, ...]


def _span(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"PE {label} is outside the file")


def _number(data: bytes, offset: int, width: int) -> int:
    _span(data, offset, width, "header field")
    return int.from_bytes(data[offset:offset + width], "little")


def _disjoint(spans, label: str) -> None:
    ordered = sorted((start, start + size) for start, size in spans if size)
    if any(right[0] < left[1] for left, right in zip(ordered, ordered[1:])):
        raise ValueError(f"PE {label} overlap")


@dataclass(frozen=True)
class Image:
    layout: Layout
    preferred_base: int
    directories: tuple[tuple[int, int], ...]


def parse_image(data: bytes) -> Image:
    if type(data) is not bytes or len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("release finalization needs an AMD64 PE image")
    pe = _number(data, 60, 4)
    _span(data, pe, 24, "COFF header")
    if pe < 64 or data[pe:pe + 4] != b"PE\0\0" or _number(data, pe + 4, 2) != 0x8664:
        raise ValueError("release finalization supports AMD64 PE32+ only")
    count, optional_size = _number(data, pe + 6, 2), _number(data, pe + 20, 2)
    characteristics = _number(data, pe + 22, 2)
    if not 1 <= count <= 96 or not characteristics & 2 or characteristics & 0x1000:
        raise ValueError("release finalization needs a bounded user-mode executable image")
    optional = pe + 24
    _span(data, optional, optional_size, "optional header")
    if optional_size < 112 or _number(data, optional, 2) != 0x20b:
        raise ValueError("release finalization supports a complete PE32+ optional header")
    section_alignment = _number(data, optional + 32, 4)
    file_alignment = _number(data, optional + 36, 4)
    if (not 512 <= file_alignment <= 65536 or file_alignment & (file_alignment - 1) or
            section_alignment < max(4096, file_alignment) or section_alignment & (section_alignment - 1)):
        raise ValueError("PE section or file alignment is unsupported")
    image_size, headers_size = _number(data, optional + 56, 4), _number(data, optional + 60, 4)
    if (not image_size or image_size % section_alignment or not headers_size or
            headers_size % file_alignment or headers_size > len(data)):
        raise ValueError("PE image or header extent is invalid")
    if _number(data, optional + 64, 4) or _number(data, optional + 68, 2) not in (2, 3):
        raise ValueError("finalize a zero-checksum GUI/console image before checksumming or signing")
    directories = _number(data, optional + 108, 4)
    if directories > 16 or 112 + directories * 8 > optional_size:
        raise ValueError("PE data directories exceed the optional header")
    if directories > 4 and data[optional + 144:optional + 152] != bytes(8):
        raise ValueError("finalize an unsigned image before signing")
    table = optional + optional_size
    _span(data, table, count * 40, "section table")
    if table + count * 40 > headers_size:
        raise ValueError("PE section table exceeds its declared headers")
    sections = []
    for index in range(count):
        offset = table + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<4I", data, offset + 8)
        flags = _number(data, offset + 36, 4)
        if raw_size:
            _span(data, raw_offset, raw_size, "section data")
            if raw_offset < headers_size or raw_offset % file_alignment or raw_size % file_alignment:
                raise ValueError("PE section raw extent is invalid")
        mapped = max(virtual_size, raw_size)
        if mapped and (rva < headers_size or rva % section_alignment or rva + mapped > image_size):
            raise ValueError("PE section virtual extent is invalid")
        sections.append(Section(data[offset:offset + 8].rstrip(b"\0"), virtual_size, rva,
                                raw_size, raw_offset, flags))
    _disjoint([(section.raw_offset, section.raw_size) for section in sections], "raw section ranges")
    _disjoint([(section.rva, max(section.virtual_size, section.raw_size)) for section in sections],
              "virtual section ranges")
    return Image(Layout(headers_size, image_size, tuple(sections)),
        _number(data, optional + 24, 8),
        tuple(struct.unpack_from("<II", data, optional + 112 + index * 8) for index in range(directories)))


def rva_section(image: Image, rva: int, size: int, *, logical=False) -> Section:
    if (type(rva) is not int or type(size) is not int or rva < 0 or size <= 0 or
            rva > image.layout.image_size or size > image.layout.image_size - rva):
        raise ValueError("PE RVA span is outside the image")
    matches = []
    for section in image.layout.sections:
        extent = (section.virtual_size or section.raw_size) if logical else max(section.virtual_size, section.raw_size)
        if rva >= section.rva and rva - section.rva <= extent and size <= extent - (rva - section.rva):
            matches.append(section)
    if len(matches) != 1:
        raise ValueError("PE RVA span needs one unambiguous section")
    return matches[0]


def read_rva(data: bytes, image: Image, rva: int, size: int) -> bytes:
    section = rva_section(image, rva, size)
    delta = rva - section.rva
    available = min(size, max(0, section.raw_size - delta))
    start = section.raw_offset + delta
    return data[start:start + available] + bytes(size - available)


def data_directory(image: Image, index: int) -> tuple[int, int]:
    if type(index) is not int or not 0 <= index < 16:
        raise ValueError("PE data directory index is invalid")
    rva, size = image.directories[index] if index < len(image.directories) else (0, 0)
    if bool(rva) != bool(size):
        raise ValueError("PE data directory has an incomplete span")
    if size:
        rva_section(image, rva, size)
    return rva, size
