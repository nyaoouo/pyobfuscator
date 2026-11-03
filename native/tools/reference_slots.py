"""Pre-codegen read-only storage; only fixed-capacity ciphertext slots may change."""
from dataclasses import dataclass
import struct

from pe_layout import data_directory, parse_image
from pe_relocations import relocations
from reference_identity import identity_bytes

MAGIC = b"PYOBF-REFSLOT1\0\0"
MATERIAL_MAGIC = b"PYOBF-REFSLOT2\0\0"
MATERIAL_BYTES = 168
HEADER = struct.Struct("<16s4I32s")
ENTRY = struct.Struct("<52sI8s")
MATERIAL_ENTRY = struct.Struct("<52sII4s")
assert len(MAGIC) == len(MATERIAL_MAGIC) == 16 and HEADER.size == ENTRY.size == MATERIAL_ENTRY.size == 64


@dataclass(frozen=True)
class Storage:
    prefix: bytes
    offsets: tuple[int, ...]
    size: int
    material_offsets: tuple[int, ...] = ()


def storage(plan):
    cursor = HEADER.size + ENTRY.size * len(plan.records)
    entries, offsets, material_offsets = [], [], []
    for index, record in enumerate(plan.records):
        cursor = (cursor + 15) & ~15
        offsets.append(cursor)
        cursor += record.identity.capacity
        material_offset = 0
        if index in plan.scope_materials:
            material_offset = (cursor + 15) & ~15
            cursor = material_offset + MATERIAL_BYTES
        material_offsets.append(material_offset)
        entries.append(MATERIAL_ENTRY.pack(identity_bytes(record.identity), offsets[-1], material_offset, bytes(4))
            if plan.scope_materials else ENTRY.pack(identity_bytes(record.identity), offsets[-1], bytes(8)))
    size = (cursor + 15) & ~15
    prefix = HEADER.pack(MATERIAL_MAGIC if plan.scope_materials else MAGIC,
        2 if plan.scope_materials else 1, len(entries), size, 0, plan.digest) + b"".join(entries)
    return Storage(prefix, tuple(offsets), size, tuple(material_offsets) if plan.scope_materials else ())


def _bytes(values): return "{" + ", ".join(f"0x{value:02x}" for value in values) + "}"


def render_header(plan):
    slots = storage(plan)
    source = '#pragma once\n#include "measurement/reference.hpp"\n\n'
    source += 'namespace pyobfuscator::native::measurement::reserved {\n'
    source += f'inline constexpr std::size_t size = {slots.size}, count = {len(plan.records)};\n'
    source += 'extern const std::uint8_t data[size];\n'
    source += 'inline constexpr std::size_t offsets[] = {' + ", ".join(map(str, slots.offsets)) + '};\n'
    if plan.scope_materials:
        source += f'inline constexpr std::size_t material_size = {MATERIAL_BYTES};\n'
        source += 'inline constexpr std::size_t material_offsets[] = {' + ", ".join(map(str, slots.material_offsets)) + '};\n'
    source += 'inline constexpr reference::Identity identities[] = {\n'
    for record in plan.records:
        ident = record.identity
        source += '    {' + _bytes(ident.build) + ', ' + _bytes(ident.image) + ', ' + ', '.join(str(value) + 'u'
            for value in (ident.owner, ident.subject, ident.kind, ident.stage, ident.capacity)) + '},\n'
    return source + '};\n}\n'


def render_source(plan):
    slots = storage(plan)
    rows = [", ".join(f"0x{byte:02x}" for byte in slots.prefix[start:start + 16])
        for start in range(0, len(slots.prefix), 16)]
    return ('#include "reference_slots.hpp"\n\n'
        '#if defined(_MSC_VER)\n#pragma section(".pyobm", read)\n'
        '#define PYOBF_REFERENCE_STORE __declspec(allocate(".pyobm"))\n#else\n'
        '#define PYOBF_REFERENCE_STORE __attribute__((section(".pyobm"), used))\n#endif\n'
        'namespace pyobfuscator::native::measurement::reserved {\n'
        'alignas(16) PYOBF_REFERENCE_STORE const std::uint8_t data[size] = {\n    ' +
        ",\n    ".join(rows) + '\n};\n}\n')


def locate(data, plan):
    image = parse_image(data); expected = storage(plan)
    matches = [section for section in image.layout.sections if section.name == b".pyobm"]
    if len(matches) != 1: raise ValueError("reference storage needs exactly one .pyobm section")
    section = matches[0]
    if (section.flags & 0xb20000a0 or section.flags & 0x40000040 != 0x40000040 or
            section.virtual_size != expected.size or section.raw_size < expected.size):
        raise ValueError("reference storage must be exact-size private read-only initialized data")
    content = data[section.raw_offset:section.raw_offset + section.raw_size]
    if content[:len(expected.prefix)] != expected.prefix:
        raise ValueError("reference storage differs from independently frozen plan")
    cursor = len(expected.prefix)
    intervals = [(offset, record.identity.capacity) for record, offset in zip(plan.records, expected.offsets)]
    intervals.extend((offset, MATERIAL_BYTES) for offset in expected.material_offsets if offset)
    for offset, capacity in sorted(intervals):
        if any(content[cursor:offset]): raise ValueError("reference storage has nonzero alignment gaps")
        cursor = offset + capacity
    if any(content[cursor:]): raise ValueError("reference storage has nonzero padding")
    begin, end = section.rva, section.rva + section.raw_size
    for index in range(16):
        rva, size = data_directory(image, index)
        if size and rva < end and begin < rva + size:
            raise ValueError("reference storage overlaps loader directory data")
    if any(target < end and begin < target + 8 for target in relocations(data, image)):
        raise ValueError("reference storage overlaps loader relocation writes")
    return image, section, expected
