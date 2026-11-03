"""Independent byte/AEAD inspection for generated decoy test artifacts."""

import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from release_plan import expected_fold, parse_plan, render_header


def inspect_package(directory, image):
    directory, image = Path(directory), Path(image)
    payload = image.read_bytes()
    coverage = (directory / "decoy.coverage.json").read_bytes()
    final = (directory / "decoy.final.json").read_bytes()
    source, linked = json.loads(coverage), json.loads(final)
    assert source["domain"] == "decoy-payload"
    assert linked["image_sha256"] == hashlib.sha256(payload).hexdigest()
    assert linked["input_report_sha256"] == hashlib.sha256(coverage).hexdigest()
    selected = [row for row in linked["functions"] if row["selected"]]
    assert selected and all(row["final_binary_verified"] for row in selected)
    assert "pyobf_native_inner_entry" in {row["function"] for row in selected}
    plan_bytes = (directory / "decoy.private.json").read_bytes()
    plan = parse_plan(plan_bytes)
    assert plan["child_image_sha256"] == linked["image_sha256"]
    assert plan["child_report_sha256"] == hashlib.sha256(final).hexdigest()
    assert (directory / "decoy_events_generated.hpp").read_text() == render_header(plan, "decoy_events")
    header = (directory / "decoy_blob.hpp").read_bytes()
    rows = re.findall(rb"inline constexpr unsigned char (\w+)\[\] = \{(.*?)\};", header, re.S)
    assert len(rows) == 5 and {name for name, data in rows} == {b"nonce", b"tag", b"ciphertext", b"aad", b"record"}
    arrays = {name.decode(): bytes(int(byte, 16) for byte in re.findall(rb"0x([0-9a-f]{2})", data)) for name, data in rows}
    record = arrays["record"]
    assert len(record) == 64 and record[:16] == b"PYOBF-RELKEY-v1\0" and struct.unpack_from("<II", record, 16) == (1, 64)
    assert record[56:] == bytes(8)
    expected_aad = b"pyobf.native.decoy.v1\0" + hashlib.sha256(payload).digest() + hashlib.sha256(final).digest()
    assert arrays["aad"] == expected_aad
    state = struct.pack("<8I", *expected_fold(plan))
    digest = hashlib.sha256(b"pyobf.native.release.fold.v1\0" + state).digest()
    key = bytes(left ^ right for left, right in zip(digest, record[24:56]))
    assert AESGCM(key).decrypt(arrays["nonce"], arrays["ciphertext"] + arrays["tag"], expected_aad) == payload
    manifest = json.loads((directory / "decoy.package.json").read_text())
    assert manifest == {"schema_version": 1, "kind": "decoy", "image_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": hashlib.sha256(final).hexdigest(), "coverage_sha256": hashlib.sha256(coverage).hexdigest(),
        "private_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(), "header_sha256": hashlib.sha256(header).hexdigest()}
    return arrays, key, plan
