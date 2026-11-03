"""Bounded AMD64 PE32+ record filling that preserves every byte outside its mask."""

from __future__ import annotations

import hashlib

from pe_layout import Layout, Section, parse_image
from release_format import MASK_OFFSET, PLACEHOLDER, SIZE, record_mask
from pe_data_patch import Write, apply_writes


def _profile(version):
    if type(version) is not int or version not in (1, 2):
        raise ValueError("release finalizer needs an explicit supported record version")
    if version == 1: return record_mask, PLACEHOLDER
    from measured_release import record_mask as measured_mask, PLACEHOLDER as measured_placeholder
    return measured_mask, measured_placeholder


def locate_record(data: bytes, *, version=1) -> tuple[Layout, int]:
    validate, _ = _profile(version)
    layout = parse_image(data).layout
    sections = layout.sections
    matches = [section for section in sections if section.name == b".pyobf"]
    if len(matches) != 1:
        raise ValueError("PE needs exactly one dedicated .pyobf release-record section")
    section = matches[0]
    # Initialised, readable, immutable data; never code, discarded or zero-fill storage.
    if section.flags & 0xa20000a0 or section.flags & 0x40000040 != 0x40000040:
        raise ValueError("PE release record must be read-only non-executable initialized data")
    if section.virtual_size != SIZE or section.raw_size < SIZE:
        raise ValueError("PE release section must contain exactly one64-byte record")
    start = section.raw_offset
    validate(data[start:start + SIZE])
    if any(data[start + SIZE:start + section.raw_size]):
        raise ValueError("PE release section has nonzero data outside its record")
    return layout, start


def finalize_image(image: bytes, record: bytes, *, version=1) -> tuple[bytes, dict]:
    validate, placeholder = _profile(version)
    mask = validate(record)
    layout, start = locate_record(image, version=version)
    if image[start:start + SIZE] not in (placeholder, record):
        raise ValueError("PE release record is stale or already filled with different material")
    write_offset = start + MASK_OFFSET
    finalized, proof = apply_writes(image, (Write(write_offset, mask),))
    if locate_record(finalized, version=version) != (layout, start):
        raise AssertionError("release finalization changed bytes or layout outside its fixed mask")
    report = {"schema_version": 1, "format": "amd64-pe32+", "record_version": version,
              "record_offset": start, "write_offset": write_offset, "write_size": 32,
              "layout_verified_unchanged": proof["layout_verified_unchanged"],
              "executable_bytes_verified_unchanged": proof["executable_bytes_verified_unchanged"],
              "image_before_sha256": proof["image_before_sha256"],
              "image_after_sha256": proof["image_after_sha256"],
              "record_sha256": hashlib.sha256(record).hexdigest(), "idempotent": image == finalized}
    return finalized, report
