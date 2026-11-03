"""Bounded AMD64 DIR64 relocation metadata for canonical mapped code."""
import struct

from pe_layout import Image, _disjoint, data_directory, read_rva, rva_section

MAX_RELOCATIONS = 65536


def relocations(data: bytes, image: Image) -> tuple[int, ...]:
    rva, size = data_directory(image, 5)
    if not size:
        return ()
    if rva % 4:
        raise ValueError("base-relocation directory is not DWORD aligned")
    if size > MAX_RELOCATIONS * 12:
        raise ValueError("base-relocation directory exceeds its budget")
    content = read_rva(data, image, rva, size)
    result = []
    offset = 0
    while offset < len(content):
        if len(content) - offset < 8:
            raise ValueError("truncated base-relocation block")
        page, block_size = struct.unpack_from("<II", content, offset)
        if page % 4096 or page >= image.layout.image_size or block_size < 8 or block_size % 4 or block_size > len(content) - offset:
            raise ValueError("invalid base-relocation block")
        for (entry,) in struct.iter_unpack("<H", content[offset + 8:offset + block_size]):
            kind, relative = entry >> 12, entry & 0xfff
            if not kind:
                continue
            if kind != 10:
                raise ValueError("unsupported base relocation; canonical v1 admits DIR64 only")
            target = page + relative
            rva_section(image, target, 8)
            result.append(target)
            if len(result) > MAX_RELOCATIONS:
                raise ValueError("base relocations exceed their budget")
        offset += block_size
    _disjoint([(target, 8) for target in result], "base relocation fields")
    return tuple(sorted(result))
