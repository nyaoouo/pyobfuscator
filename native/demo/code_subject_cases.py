"""Independent malformed headers/metadata and canonical host-observation controls."""
from dataclasses import replace
import struct

from code_observation import observation_digest, reference_digest
from code_subject import Range, Subject, text_subject, unwind_interval, validate_subject
from pe_layout import data_directory, parse_image, read_rva
from pe_relocations import relocations
from release_record_cases import sections


def refuses(function):
    try: function()
    except ValueError: return
    raise AssertionError("malformed code subject or observation was accepted")


def check_cases(data, image, subject, entry):
    _, optional, _, table = sections(data)
    text_header = next(offset for offset, name in table if name == b".text")
    text = next(section for section in image.layout.sections if section.name == b".text")
    fixups = relocations(data, image)
    baseline = reference_digest(data, image, subject, 7)
    read = lambda rva, size: read_rva(data, image, rva, size)
    def changed(offset, form, value):
        copy = bytearray(data); struct.pack_into(form, copy, offset, value)
        return bytes(copy)
    for tag in (0, -1, True, 1 << 32):
        refuses(lambda tag=tag: text_subject(image, tag))
        refuses(lambda tag=tag: observation_digest(image, subject, fixups, tag, image.preferred_base, read))
    for ranges in ((), (Range(0, 8),), (Range(text.rva, 0),), (Range(text.rva, True),),
            (Range(text.rva, 16), Range(text.rva + 8, 16)),
            (Range(text.rva + 32, 8), Range(text.rva, 8)), (None,)):
        refuses(lambda ranges=ranges: validate_subject(image, replace(subject, ranges=ranges)))
    refuses(lambda: validate_subject(image, replace(subject, kind="function")))
    refuses(lambda: validate_subject(image, replace(subject, ranges=list(subject.ranges))))
    refuses(lambda: data_directory(image, 16))
    refuses(lambda: read_rva(data, image, image.layout.image_size, 1))
    for flags in (text.flags | 0x80000000, text.flags | 0x2000000, text.flags & ~0x20000000):
        bad = changed(text_header + 36, "<I", flags)
        refuses(lambda bad=bad: text_subject(parse_image(bad), 1))
    for base in (0, -1, True, 1 << 64, (1 << 64) - image.layout.image_size + 1):
        refuses(lambda base=base: observation_digest(image, subject, fixups, 7, base, read))
    refuses(lambda: observation_digest(image, subject, fixups, 7, image.preferred_base, lambda r, s: bytes(s - 1)))
    refuses(lambda: observation_digest(image, subject, fixups, 7, image.preferred_base, lambda r, s: bytearray(s)))
    refuses(lambda: observation_digest(image, subject, (fixups[0], fixups[0]), 7, image.preferred_base, read))
    refuses(lambda: observation_digest(image, subject, [], 7, image.preferred_base, read))
    target = next(rva for rva in fixups if text.rva <= rva and rva + 8 <= text.rva + text.virtual_size)
    partial = Subject(1, "section", "partial-fixup", (Range(target + 1, 4),))
    refuses(lambda: observation_digest(image, partial, fixups, 7, image.preferred_base, read))
    if observation_digest(image, subject, fixups, 8, image.preferred_base, read) == baseline:
        raise AssertionError("owner domains do not affect their full observed digest")
    modified = bytearray(read(subject.ranges[0].rva, subject.ranges[0].size)); modified[0] ^= 1
    if observation_digest(image, subject, fixups, 7, image.preferred_base, lambda r, s: bytes(modified)) == baseline:
        raise AssertionError("changed observed code bytes disappeared from the digest")
    _, reloc_size = data_directory(image, 5)
    reloc_rva, _ = image.directories[5]
    reloc_section = next(section for section in image.layout.sections
        if section.rva <= reloc_rva < section.rva + max(section.virtual_size, section.raw_size))
    reloc_offset = reloc_section.raw_offset + reloc_rva - reloc_section.rva
    for offset, form, value in ((optional + 112 + 5 * 8, "<I", 0),
            (optional + 112 + 5 * 8 + 4, "<I", 9), (reloc_offset, "<I", 1),
            (reloc_offset + 4, "<I", 0), (reloc_offset + 4, "<I", 10),
            (reloc_offset + 4, "<I", reloc_size + 4), (reloc_offset + 8, "<H", 0x3000)):
        bad = changed(offset, form, value)
        refuses(lambda bad=bad: relocations(bad, parse_image(bad)))
    refuses(lambda: unwind_interval(data, image, 2, entry + 1))
    copy = bytearray(data); struct.pack_into("<II", copy, optional + 112 + 3 * 8, 0, 0)
    refuses(lambda: unwind_interval(bytes(copy), parse_image(bytes(copy)), 2, entry))
    pdata_rva, pdata_size = data_directory(image, 3)
    pdata_section = next(section for section in image.layout.sections
        if section.rva <= pdata_rva < section.rva + max(section.virtual_size, section.raw_size))
    pdata_offset = pdata_section.raw_offset + pdata_rva - pdata_section.rva
    rows = tuple(struct.iter_unpack("<III", data[pdata_offset:pdata_offset + pdata_size]))
    row_index = next(index for index, row in enumerate(rows) if row[0] == entry)
    record_offset = pdata_offset + row_index * 12
    for offset, form, value in ((optional + 112 + 3 * 8 + 4, "<I", 13),
            (record_offset + 4, "<I", entry), (record_offset + 8, "<I", 0),
            (record_offset + 8, "<I", rows[row_index][2] + 1)):
        bad = changed(offset, form, value)
        refuses(lambda bad=bad: unwind_interval(bad, parse_image(bad), 2, entry))
    unwind_rva = rows[row_index][2]
    unwind_section = next(section for section in image.layout.sections
        if section.rva <= unwind_rva < section.rva + max(section.virtual_size, section.raw_size))
    unwind_offset = unwind_section.raw_offset + unwind_rva - unwind_section.rva
    for header in (0, 0x81, 0x21):
        bad = changed(unwind_offset, "<B", header)
        refuses(lambda bad=bad: unwind_interval(bad, parse_image(bad), 2, entry))
    # Duplicate a real DIR64 entry in its own block, including a padding slot if needed.
    block = reloc_offset
    while block < reloc_offset + reloc_size:
        block_size = struct.unpack_from("<I", data, block + 4)[0]
        entries = list(struct.unpack_from("<H", data, location)[0] for location in range(block + 8, block + block_size, 2))
        chosen = next((index for index, value in enumerate(entries) if value >> 12 == 10), None)
        if chosen is not None and len(entries) >= 2:
            other = (chosen + 1) % len(entries)
            bad = changed(block + 8 + other * 2, "<H", entries[chosen])
            refuses(lambda: relocations(bad, parse_image(bad)))
            break
        block += block_size
    else: raise AssertionError("fixture could not exercise duplicate relocation metadata")
    for directory_index in (3, 5):
        rva, size = image.directories[directory_index]
        section = next(section for section in image.layout.sections
            if section.rva <= rva < section.rva + max(section.virtual_size, section.raw_size))
        offset = section.raw_offset + rva - section.rva
        if offset + size + 1 > section.raw_offset + section.raw_size:
            raise AssertionError("fixture lacks metadata padding for the alignment control")
        copy = bytearray(data)
        copy[offset + 1:offset + size + 1] = data[offset:offset + size]
        struct.pack_into("<I", copy, optional + 112 + directory_index * 8, rva + 1)
        bad = bytes(copy)
        if directory_index == 3:
            refuses(lambda: unwind_interval(bad, parse_image(bad), 2, entry))
        else:
            refuses(lambda: relocations(bad, parse_image(bad)))
    # Raw alignment padding is explicitly outside the logical .text subject.
    if text.raw_size > text.virtual_size:
        padded = changed(text.raw_offset + text.virtual_size, "<B", 0xa5)
        if reference_digest(padded, parse_image(padded), subject, 7) != baseline:
            raise AssertionError("logical subject unexpectedly included raw file padding")
    for section in image.layout.sections:
        if section.raw_size == 0 and section.virtual_size:
            if read_rva(data, image, section.rva, section.virtual_size) != bytes(section.virtual_size):
                raise AssertionError("zero-fill RVA span read unrelated file bytes")
    print("typed/range/base/reader/relocation/unwind/owner/changed-byte/padding controls verified")
