"""PE mutation inputs derived independently from a real linked fixture's headers."""

import struct


def sections(image):
    pe = struct.unpack_from("<I", image, 60)[0]
    count = struct.unpack_from("<H", image, pe + 6)[0]
    optional = pe + 24
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    rows = [(table + index * 40, image[table + index * 40:table + index * 40 + 8].rstrip(b"\0"))
            for index in range(count)]
    return pe, optional, table, rows


def malformed_images(image):
    pe, optional, table, rows = sections(image)
    record = next(offset for offset, name in rows if name == b".pyobf")
    other = next(offset for offset, name in rows if name == b".text")
    data = struct.unpack_from("<I", image, record + 20)[0]
    raw_size = struct.unpack_from("<I", image, record + 16)[0]
    flags = struct.unpack_from("<I", image, record + 36)[0]
    def changed(offset, form, value):
        result = bytearray(image)
        struct.pack_into(form, result, offset, value)
        return bytes(result)
    cases = [
        ("not-pe", b"x" * 64), ("truncated", image[:63]),
        ("coff-outside", changed(60, "<I", len(image))),
        ("coff-inside-dos", changed(60, "<I", 0)),
        ("machine", changed(pe + 4, "<H", 0x14c)),
        ("zero-sections", changed(pe + 6, "<H", 0)),
        ("section-budget", changed(pe + 6, "<H", 97)),
        ("object-not-image", changed(pe + 22, "<H", 0)),
        ("kernel-image", changed(pe + 22, "<H", 0x1002)),
        ("optional-small", changed(pe + 20, "<H", 2)),
        ("optional-truncated", changed(pe + 20, "<H", 0xffff)),
        ("pe32", changed(optional, "<H", 0x10b)),
        ("file-alignment", changed(optional + 36, "<I", 3)),
        ("zero-section-alignment", changed(optional + 32, "<I", 0)),
        ("subpage-section-alignment", changed(optional + 32, "<I", 512)),
        ("empty-image", changed(optional + 56, "<I", 0)),
        ("oversized-headers", changed(optional + 60, "<I", len(image) + 512)),
        ("section-table-outside-headers", changed(optional + 60, "<I", 512)),
        ("checksum", changed(optional + 64, "<I", 1)),
        ("native-subsystem", changed(optional + 68, "<H", 1)),
        ("directory-budget", changed(optional + 108, "<I", 17)),
        ("signed", changed(optional + 144, "<Q", 8 << 32 | len(image))),
        ("raw-outside", changed(record + 20, "<I", len(image))),
        ("raw-unaligned", changed(record + 20, "<I", data + 1)),
        ("raw-missing", changed(record + 16, "<I", 0)),
        ("virtual-cardinality", changed(record + 8, "<I", 128)),
        ("virtual-outside", changed(record + 12, "<I", 0xfffff000)),
        ("virtual-overlap", changed(record + 12, "<I", struct.unpack_from("<I", image, other + 12)[0])),
        ("raw-overlap", changed(record + 20, "<I", struct.unpack_from("<I", image, other + 20)[0])),
        ("duplicate-section", changed(other, "8s", b".pyobf\0\0")),
        ("missing-section", changed(record, "8s", b".other\0\0")),
        ("wrong-magic", changed(data, "<B", 0)),
        ("wrong-version", changed(data + 16, "<I", 2)),
        ("wrong-size", changed(data + 20, "<I", 63)),
        ("reserved-data", changed(data + 56, "<B", 1)),
    ]
    if raw_size <= 64: raise AssertionError("fixture has no aligned record padding")
    cases.append(("extra-section-data", changed(data + 64, "<B", 1)))
    for name, bit in (("code", 0x20), ("execute", 0x20000000), ("write", 0x80000000),
                      ("discard", 0x2000000), ("uninitialized", 0x80)):
        cases.append((name, changed(record + 36, "<I", flags | bit)))
    for name, bit in (("unreadable", 0x40000000), ("not-initialized", 0x40)):
        cases.append((name, changed(record + 36, "<I", flags & ~bit)))
    return cases
