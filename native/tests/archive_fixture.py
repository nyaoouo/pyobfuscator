"""Generate private test-only expected bytes/keys and actual production package wrappers."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from archive_format import Kind, Record, validate_record
from pack_archive import cpp_source, seal


def records() -> list[Record]:
    return [
        Record("empty-first", Kind.bytes, 8, 1, 0, b""),
        Record("bytes", Kind.bytes, 8, 64, 0, b"protected-native-bytes\0\xff\x80"),
        Record("integer128", Kind.integer, 128, 16, 1, bytes.fromhex("dec0addeefbe37a168d327c9fa1065b8")),
        Record("integer33", Kind.integer, 33, 8, 1, bytes.fromhex("ffffffff01000000")),
        Record("negative-zero", Kind.binary64, 64, 8, 1, bytes.fromhex("0000000000000080")),
        Record("nan64", Kind.binary64, 64, 8, 1, bytes.fromhex("3412efbeadde f87f")),
        Record("nan32", Kind.binary32, 32, 4, 1, bytes.fromhex("4523c17f")),
        Record("float16", Kind.binary16, 16, 2, 1, bytes.fromhex("0080")),
        Record("bfloat16", Kind.bfloat16, 16, 2, 1, bytes.fromhex("c17f")),
        Record("x87", Kind.x87_80, 80, 16, 1, bytes.fromhex("01000000000000c0ff7f") + bytes(6)),
        Record("float128", Kind.binary128, 128, 16, 1, bytes.fromhex("3412000000000000000000000080ff7f")),
        Record("narrow", Kind.code_units8, 8, 1, 0, b"A\0B\0"),
        Record("wide16", Kind.code_units16, 16, 2, 1, bytes.fromhex("2d4e00d80000")),
        Record("wide32", Kind.code_units32, 32, 4, 1, bytes.fromhex("5a0000002d4e000000000000")),
        Record("empty-last", Kind.bytes, 8, 1, 0, b""),
    ]


def array(name: str, data: bytes) -> str:
    values = ",".join(f"0x{value:02x}" for value in data) or "0"
    return f"inline const std::uint8_t {name}[] = {{{values}}};\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("header", type=Path)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    items = records()
    for item in items: validate_record(item)
    package = seal(items)
    text = "#pragma once\n#include <cstddef>\n#include <cstdint>\nnamespace fixture {\n"
    text += array("package", package.data)
    incompatible = Record("big-endian", Kind.integer, 64, 8, 2, bytes.fromhex("8000000000000000"))
    incompatible_package = seal([incompatible])
    text += array("big_endian_package", incompatible_package.data)
    text += array("big_endian_key", incompatible_package.keys[0])
    for index, item in enumerate(items):
        text += array(f"expected_{index}", item.data)
        text += array(f"key_{index}", package.keys[index])
    text += ("struct Record {const std::uint8_t *data,*key;std::size_t size;};\n"
             "inline const Record records[]={\n")
    text += ",\n".join(f"{{expected_{index},key_{index},{len(item.data)}}}" for index, item in enumerate(items))
    text += "\n};\n}\n"
    for name in package.wrappers:
        text += f'extern "C" void {name}(const std::uint8_t*,std::uint8_t*,std::size_t) noexcept;\n'
    text += "namespace fixture {\nusing Wrapper=void(*)(const std::uint8_t*,std::uint8_t*,std::size_t) noexcept;\n"
    text += "inline const Wrapper wrappers[]={" + ",".join(package.wrappers) + "};\n}\n"
    args.header.write_text(text, encoding="utf-8")
    args.source.write_text(cpp_source(package, items), encoding="utf-8")


if __name__ == "__main__":
    main()
