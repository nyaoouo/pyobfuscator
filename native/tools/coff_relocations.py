"""Evaluate admitted AMD64 link fixups; no masked or silently ignored code bytes."""
import struct

from pe_layout import _disjoint


class Resolver:
    def __init__(self, obj, image, linked_symbols):
        self.obj, self.image = obj, image
        self.inputs = {symbol.index: symbol for symbol in obj.symbols}
        self.anchors = {}
        self.data_anchors = {}
        for symbol in obj.symbols:
            if symbol.section > 0 and symbol.type == 0x20 and symbol.value == 0:
                self.anchors.setdefault(symbol.section, []).append(symbol)
            elif (symbol.section > 0 and symbol.type == 0 and symbol.storage in (2, 3) and not symbol.auxiliaries and
                    symbol.value < obj.sections[symbol.section - 1].size):
                section = obj.sections[symbol.section - 1]
                if section.flags & 0xc0 and not section.flags & 0x20000000:
                    self.data_anchors.setdefault(symbol.section, []).append(symbol)
        self.linked = {}
        for symbol in linked_symbols:
            if symbol.section > 0:
                section = image.layout.sections[symbol.section - 1]
                extent = section.virtual_size or section.raw_size
                if symbol.value >= extent:
                    # End/absolute linker symbols are not addressable contribution targets.
                    continue
                self.linked.setdefault(symbol.name, set()).add(section.rva + symbol.value)
            elif symbol.section == -1:
                self.linked.setdefault(symbol.name, set()).add(symbol.value - image.preferred_base)

    def named(self, name):
        values = self.linked.get(name, ())
        if len(values) != 1: raise ValueError(f"COFF final symbol is missing or ambiguous: {name}")
        return next(iter(values))

    def target(self, index):
        symbol = self.inputs[index]
        if symbol.section == -1: return symbol.value - self.image.preferred_base
        values = self.linked.get(symbol.name, ())
        if len(values) == 1: return next(iter(values))
        if symbol.section > 0:
            # A retained, unambiguous function anchor also maps private assembly labels.
            anchors = [candidate for candidate in self.anchors.get(symbol.section, ())
                if len(self.linked.get(candidate.name, ())) == 1]
            mapped = {self.named(anchor.name) + symbol.value for anchor in anchors}
            if len(mapped) == 1: return mapped.pop()
            section = self.obj.sections[symbol.section - 1]
            data_anchors = [anchor for anchor in self.data_anchors.get(symbol.section, ())
                if len(self.linked.get(anchor.name, ())) == 1]
            bases = {self.named(anchor.name) - anchor.value for anchor in data_anchors}
            if len(bases) == 1:
                base = bases.pop()
                # Retained data labels map an entire input contribution, including BSS.
                # Require the complete declared extent to fit one final virtual section;
                # no file bytes or neighboring symbol lengths define this address mapping.
                targets = [part for part in self.image.layout.sections if
                    part.rva <= base and base + section.size <= part.rva + (part.virtual_size or part.raw_size)]
                if len(targets) == 1: return base + symbol.value
        raise ValueError(f"COFF relocation lacks an exact final target: {symbol.name}")


def linked_bytes(data, obj, section, start, resolver):
    content = bytearray(data[section.offset:section.offset + section.size])
    fields = []
    for relocation in section.relocations:
        offset, kind = relocation.offset, relocation.kind
        width = 8 if kind == 1 else 4
        if kind not in (1, 2, 3, 4, 5, 6, 7, 8, 9):
            raise ValueError("COFF code relocation kind is unsupported")
        if offset > len(content) or width > len(content) - offset:
            raise ValueError("COFF code relocation crosses its contribution")
        fields.append((offset, width))
    _disjoint(fields, "COFF code relocation fields")
    for relocation in section.relocations:
        offset, kind = relocation.offset, relocation.kind
        target = resolver.target(relocation.target)
        if kind == 1:
            addend = int.from_bytes(content[offset:offset + 8], "little")
            struct.pack_into("<Q", content, offset, (resolver.image.preferred_base + target + addend) & ((1 << 64) - 1))
        else:
            addend = int.from_bytes(content[offset:offset + 4], "little", signed=True)
            if kind >= 4:
                value = target + addend - (start + offset + 4 + kind - 4)
                if not -(1 << 31) <= value < 1 << 31: raise ValueError("COFF final REL32 overflows")
                struct.pack_into("<i", content, offset, value)
            else:
                value = target + addend + (resolver.image.preferred_base if kind == 2 else 0)
                # COFF address fields retain their low32 bits, including signed addends.
                struct.pack_into("<I", content, offset, value & 0xffffffff)
    return bytes(content)
