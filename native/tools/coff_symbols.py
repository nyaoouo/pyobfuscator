"""Bounded classic COFF symbol/string decoding, shared by objects and final PE images."""
from dataclasses import dataclass
import struct

MAX_SYMBOLS = 1 << 20


def span(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"COFF {label} is outside the file")


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    value: int
    section: int
    type: int
    storage: int
    auxiliaries: tuple[bytes, ...]


def string_table(data, offset, count):
    if not offset or not 0 < count <= MAX_SYMBOLS:
        raise ValueError("COFF needs a bounded symbol table")
    span(data, offset, count * 18 + 4, "symbol/string tables")
    start = offset + count * 18
    size = struct.unpack_from("<I", data, start)[0]
    if size < 4: raise ValueError("COFF string table has an invalid length")
    span(data, start, size, "string table")
    return data[start:start + size]


def long_name(strings, offset):
    if not 4 <= offset < len(strings): raise ValueError("COFF string offset is invalid")
    end = strings.find(b"\0", offset, min(len(strings), offset + 4097))
    if end < 0 or end - offset > 4096: raise ValueError("COFF string is unterminated or over budget")
    try: return strings[offset:end].decode("utf-8")
    except UnicodeDecodeError as error: raise ValueError("COFF symbol is not UTF-8") from error


def short_name(raw):
    try: return raw.split(b"\0", 1)[0].decode("utf-8")
    except UnicodeDecodeError as error: raise ValueError("COFF symbol is not UTF-8") from error


def symbols(data, offset, count, section_count):
    strings = string_table(data, offset, count)
    result = []; index = 0; names = {}
    while index < count:
        position = offset + 18 * index
        name, value, section, kind, storage, auxiliaries = struct.unpack_from("<8sIhHBB", data, position)
        if section < -2 or section > section_count or index + auxiliaries >= count:
            raise ValueError("COFF symbol has an invalid section or auxiliary count")
        if name not in names:
            names[name] = long_name(strings, int.from_bytes(name[4:], "little")) if name[:4] == bytes(4) else short_name(name)
        decoded = names[name]
        aux = tuple(data[position + 18 * step:position + 18 * (step + 1)] for step in range(1, auxiliaries + 1))
        result.append(Symbol(index, decoded, value, section, kind, storage, aux))
        index += auxiliaries + 1
    return tuple(result), strings


def image_symbols(data, image):
    pe = struct.unpack_from("<I", data, 60)[0]
    offset, count = struct.unpack_from("<II", data, pe + 12)
    result, strings = symbols(data, offset, count, len(image.layout.sections))
    from pe_layout import _disjoint
    _disjoint([(0, image.layout.headers_size), (offset, count * 18 + len(strings)),
        *((section.raw_offset, section.raw_size) for section in image.layout.sections)], "COFF final symbol spans")
    return result
