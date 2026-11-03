"""Generate deterministic private C++ asset storage for later archive collection."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


def generate(identity: str, data: bytes, header_name: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", identity):
        raise ValueError("asset ID must be 1-64 lowercase identifier characters")
    if header_name != f"asset_{identity}.hpp":
        raise ValueError("asset header name must be asset_<id>.hpp")
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("asset exceeds the 16 MiB record budget")
    prefix = f"__pyobf_native_asset_{identity}"
    header = f'''#pragma once

#include "pyobfuscator_native/asset.hpp"

extern "C" const std::uint8_t *{prefix}_data() noexcept;
extern "C" std::size_t {prefix}_size() noexcept;

namespace pyobfuscator::native::assets {{
inline ByteView get_{identity}() noexcept {{
    return {{{prefix}_data(), {prefix}_size()}};
}}
}}  // namespace pyobfuscator::native::assets
'''
    # Portable C++ has no zero-length built-in array. Logical empty views use one
    # private sentinel byte while retaining size zero at the public accessor.
    storage = data or b"\0"
    rows = [", ".join(f"0x{byte:02x}" for byte in storage[start:start + 16])
            for start in range(0, len(storage), 16)]
    source = f'''#include "{header_name}"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" const std::uint8_t *__pyobf_native_asset_identity_v1(const std::uint8_t *) noexcept;

namespace {{
alignas(16) const std::uint8_t blob_{identity}[] = {{
    ''' + ",\n    ".join(rows) + f'''
}};
}}

extern "C" PYOBF_NATIVE_CFF const std::uint8_t *{prefix}_data() noexcept {{
    return __pyobf_native_asset_identity_v1(blob_{identity});
}}

extern "C" PYOBF_NATIVE_CFF std::size_t {prefix}_size() noexcept {{
    return {len(data)};
}}
'''
    return header, source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("identity")
    parser.add_argument("input", type=Path)
    parser.add_argument("header", type=Path)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    if len({path.resolve() for path in (args.input, args.header, args.source)}) != 3:
        parser.error("asset input and generated outputs must differ")
    try:
        with args.input.open("rb") as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        header, source = generate(args.identity, data, args.header.name)
        args.header.write_text(header, encoding="utf-8", newline="\n")
        args.source.write_text(source, encoding="utf-8", newline="\n")
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
