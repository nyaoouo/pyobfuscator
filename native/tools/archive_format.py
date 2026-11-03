"""Canonical typed archive v1 metadata and strict private-plan validation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct


MAGIC = b"PYOBFAR1"
HEADER = struct.Struct("<8sII16sQ")
CORE = struct.Struct("<IIIIQQII")
RECORD_BYTES = 96
MAX_RECORDS = 65536
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
BODY_DOMAIN = b"pyobf-native-archive-body-v1"
ACCESS_DOMAIN = b"pyobf-native-archive-access-v1"


class Kind(IntEnum):
    integer = 1
    binary16 = 2
    bfloat16 = 3
    binary32 = 4
    binary64 = 5
    x87_80 = 6
    binary128 = 7
    bytes = 8
    code_units8 = 9
    code_units16 = 10
    code_units32 = 11


@dataclass(frozen=True)
class Record:
    identity: str
    kind: Kind
    bit_width: int
    alignment: int
    byte_order: int
    data: bytes


def validate_record(record: Record) -> None:
    width, length = record.bit_width, len(record.data)
    if (any(type(value) is not int for value in (width, record.alignment, record.byte_order)) or
            not isinstance(record.kind, Kind) or not isinstance(record.identity, str) or
            not isinstance(record.data, bytes) or not record.identity or len(record.identity) > 128 or
            not 1 <= record.alignment <= 4096 or record.alignment & (record.alignment - 1) or
            length > MAX_RECORD_BYTES or record.byte_order not in (0, 1, 2)):
        raise ValueError("invalid record identity, alignment, size or byte order")
    if record.kind == Kind.integer:
        valid = 1 <= width <= 128 and (width + 7) // 8 <= length <= 16 and record.byte_order in (1, 2)
    elif record.kind in (Kind.binary16, Kind.bfloat16, Kind.binary32, Kind.binary64, Kind.x87_80, Kind.binary128):
        bits = {Kind.binary16: 16, Kind.bfloat16: 16, Kind.binary32: 32,
                Kind.binary64: 64, Kind.x87_80: 80, Kind.binary128: 128}[record.kind]
        valid = width == bits and ((10 <= length <= 16) if bits == 80 else length == bits // 8) and record.byte_order in (1, 2)
    elif record.kind == Kind.bytes:
        valid = width == 8 and record.byte_order == 0
    else:
        unit = {Kind.code_units8: 1, Kind.code_units16: 2, Kind.code_units32: 4}[record.kind]
        valid = (width == unit * 8 and length >= unit and length % unit == 0 and
                 record.data[-unit:] == b"\0" * unit and
                 (record.byte_order == 0 if unit == 1 else record.byte_order in (1, 2)))
    if not valid:
        raise ValueError(f"record {record.identity!r} has an invalid typed storage representation")


def parse_plan(plan: object, *, allow_empty: bool = False) -> list[Record]:
    if (not isinstance(plan, dict) or set(plan) != {"schema_version", "records"} or
            type(plan["schema_version"]) is not int or plan["schema_version"] != 1):
        raise ValueError("archive plan needs schema_version 1 and records")
    entries = plan["records"]
    if not isinstance(entries, list) or not (0 if allow_empty else 1) <= len(entries) <= MAX_RECORDS:
        raise ValueError("archive plan record count is out of range")
    result, identities = [], set()
    fields = {"id", "kind", "bit_width", "alignment", "byte_order", "data_hex"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise ValueError("archive record fields do not match schema 1")
        if (not isinstance(entry["id"], str) or not isinstance(entry["kind"], str) or
                not isinstance(entry["data_hex"], str) or any(type(entry[name]) is not int
                    for name in ("bit_width", "alignment", "byte_order"))):
            raise ValueError("archive record fields have invalid types")
        if len(entry["data_hex"]) > MAX_RECORD_BYTES * 2 or len(entry["data_hex"]) % 2:
            raise ValueError("archive record hex length is invalid")
        try:
            kind = Kind[entry["kind"]]
            data = bytes.fromhex(entry["data_hex"])
        except (KeyError, ValueError) as error:
            raise ValueError("archive record kind or data hex is invalid") from error
        if len(data) * 2 != len(entry["data_hex"]):
            raise ValueError("archive record hex must not contain whitespace")
        record = Record(entry["id"], kind, entry["bit_width"], entry["alignment"], entry["byte_order"], data)
        validate_record(record)
        if record.identity in identities:
            raise ValueError("archive record IDs must be unique, including empty records")
        identities.add(record.identity)
        result.append(record)
    if HEADER.size + len(result) * RECORD_BYTES + sum(len(item.data) for item in result) > MAX_PACKAGE_BYTES:
        raise ValueError("archive package exceeds the format's byte budget")
    return result
