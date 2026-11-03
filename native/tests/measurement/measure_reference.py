"""Paired full reference decode costs on the same actual sealed DLL descriptor."""
import json
from pathlib import Path
from statistics import median
import struct
import sys

from check_reference import WORDS
from check_functions import prepare_fixture
from code_reference import build_reference
from code_subject import text_subject
from pe_layout import parse_image
from reference_identity import Identity, identity_bytes
from cff_build import run

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))
from measure_cff import digest, text_size


def measure(args, directory, plain, protected, combined, native):
    _, _, dll = prepare_fixture(args.compiler, directory)
    data = dll.read_bytes(); image = parse_image(data); subject = text_subject(image, 0x601)
    identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), 7, subject.tag, 1, 1, 4096)
    metadata, package = directory / "cost-metadata.bin", directory / "cost-package.bin"
    metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
    package.write_bytes(build_reference(data, subject, identity, WORDS))
    costs = {}
    for name, binary in (("plain", plain), ("protected", protected)):
        values = {1: [], 4: []}
        for line in run([binary, metadata, package, "0", "1", dll, "--cost"]).stdout.splitlines():
            if not line.startswith("cost "): continue
            _, count, ns = line.split(); values[int(count)].append(float(ns))
        if any(len(value) != 7 or min(value) <= 0 for value in values.values()):
            raise AssertionError("reference costs lack seven positive batches")
        costs[name] = {"image_sha256": digest(binary), "text_bytes": text_size(args.objdump, binary),
            "median_group_ns": {str(count): median(value) for count, value in values.items()}}
    args.measure_output.write_text(json.dumps({"scope": "one/four sequential full independent reference decodes and destruction; same encrypted4096-byte DLL descriptor; no code capture in timing",
        "optimization": args.optimization, "parent_ipo": args.ipo, "batches": 7, "groups_per_batch": 32,
        "compiler": run([args.compiler, "--version"]).stdout.splitlines()[0], "source_ir_sha256": digest(combined),
        "protected_object_sha256": digest(native), "sample_sha256": digest(dll), "package_sha256": digest(package),
        "costs": costs}, indent=2) + "\n", encoding="utf-8")
