"""Classic AMD64 object contributions and explicit associative ownership."""
from dataclasses import dataclass
import struct

from coff_symbols import Symbol, long_name, short_name, span, symbols
from pe_layout import _disjoint

MAX_OBJECT_BYTES = 128 * 1024 * 1024
MAX_SECTIONS = 8192


@dataclass(frozen=True)
class Relocation:
    offset: int
    target: int
    kind: int


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    offset: int
    size: int
    flags: int
    selection: int
    parent: int
    relocations: tuple[Relocation, ...]


@dataclass(frozen=True)
class Object:
    sections: tuple[Section, ...]
    symbols: tuple[Symbol, ...]
    owners: tuple[int, ...]


def parse_object(data):
    if len(data) > MAX_OBJECT_BYTES: raise ValueError("COFF object exceeds the byte budget")
    span(data, 0, 20, "header")
    machine, count, _, table, nsyms, optional, flags = struct.unpack_from("<HHIIIHH", data)
    if machine != 0x8664 or optional or flags & 2 or not 0 < count <= MAX_SECTIONS:
        raise ValueError("COFF needs a bounded classic AMD64 relocatable object")
    span(data, 20, count * 40, "section headers")
    syms, strings = symbols(data, table, nsyms, count)
    symbol_indices = {symbol.index for symbol in syms}
    definitions = {}
    for symbol in syms:
        if symbol.storage == 3 and symbol.type == 0 and symbol.value == 0:
            definitions.setdefault((symbol.section, symbol.name), []).append(symbol)
    result = []; extents = [(0, 20 + count * 40), (table, nsyms * 18 + len(strings))]
    for index in range(1, count + 1):
        row = struct.unpack_from("<8sIIIIIIHHI", data, 20 + (index - 1) * 40)
        raw_name, virtual_size, address, size, offset, relocations, lines, nrelocs, nlines, attributes = row
        if virtual_size or address or lines or nlines or attributes & 0x1000000 or nrelocs == 0xffff:
            raise ValueError("COFF section uses unsupported address/line/overflow metadata")
        if raw_name.startswith(b"/"):
            number = raw_name[1:].split(b"\0", 1)[0]
            if not number.isdigit(): raise ValueError("COFF section name reference is invalid")
            name = long_name(strings, int(number))
        else: name = short_name(raw_name)
        if size and not attributes & 0x80:
            span(data, offset, size, "section bytes"); extents.append((offset, size))
        if nrelocs:
            span(data, relocations, nrelocs * 10, "relocations"); extents.append((relocations, nrelocs * 10))
        entries = tuple(Relocation(*struct.unpack_from("<IIH", data, relocations + step * 10)) for step in range(nrelocs))
        if any(entry.target not in symbol_indices for entry in entries):
            raise ValueError("COFF relocation targets a missing or auxiliary symbol")
        definition = definitions.get((index, name), ())
        if len(definition) != 1 or len(definition[0].auxiliaries) != 1:
            raise ValueError("COFF section needs one authoritative auxiliary definition")
        aux = definition[0].auxiliaries[0]
        length, relocation_count, line_count, _, parent, selection = struct.unpack_from("<IHHIhB", aux)
        if (length != size or relocation_count != nrelocs or line_count or selection > 7 or aux[15:] != bytes(3) or
                bool(attributes & 0x1000) != bool(selection) or (selection == 5 and not 0 < parent <= count)):
            raise ValueError("COFF auxiliary section metadata disagrees with its contribution")
        result.append(Section(index, name, offset, size, attributes, selection, parent if selection == 5 else 0, entries))
    _disjoint(extents, "COFF file spans")
    if any(symbol.section > 0 and symbol.value > result[symbol.section - 1].size for symbol in syms):
        raise ValueError("COFF symbol points outside its input contribution")
    # Every association has a terminal owner; even an unused metadata cycle is refused.
    owners = {}
    for section in result:
        path = []; seen = set(); current = section
        while current.index not in owners:
            if current.index in seen: raise ValueError("COFF associative ownership is cyclic")
            seen.add(current.index); path.append(current.index)
            if not current.parent:
                owners[current.index] = current.index; break
            current = result[current.parent - 1]
        owner = owners[current.index]
        for index in path: owners[index] = owner
    return Object(tuple(result), syms, tuple(owners[index] for index in range(1, count + 1)))
