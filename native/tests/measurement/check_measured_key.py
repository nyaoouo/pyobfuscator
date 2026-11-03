"""Independent all-input-bit KDF vectors and actual code-bound AEAD release."""
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from statistics import median
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from check_capture import ROOT
from check_reference import WORDS
from check_functions import prepare_fixture
from code_reference import build_reference
from code_subject import text_subject, unwind_interval
from code_observation import reference_digest
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image
from reference_identity import Identity, identity_bytes
from measured_scope import build_material, material_key
import measured_release as measured
import release_format as legacy

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run


def refused(function):
    try: function()
    except ValueError: return
    raise AssertionError("malformed measured release input accepted")


def vectors(probe, directory):
    identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), 7, 11, 1, 1, 4096)
    base = struct.pack("<8I", *WORDS) + identity_bytes(identity) + bytes(range(32))
    inputs = [base]
    for index in range(len(base)):
        for bit in range(8):
            changed = bytearray(base); changed[index] ^= 1 << bit; inputs.append(bytes(changed))
    expected = []
    for row in inputs:
        fold = struct.unpack("<8I", row[:32]); who = Identity(*struct.unpack("<16s16sIIIII", row[32:84]))
        try: digest = measured.expansion(fold, who, row[84:])
        except ValueError: expected.append("2 " + bytes(32).hex())
        else:
            independent = hashlib.sha256(b"pyobf.native.release.measured.v1\0" + row).digest()
            if digest != independent: raise AssertionError("measured host framing differs from independent SHA256")
            expected.append("0 " + independent.hex())
    if len({value for value in expected if value.startswith("0 ")}) != sum(value.startswith("0 ") for value in expected):
        raise AssertionError("some admissible input bit was canceled")
    path = directory / "vectors.bin"; path.write_bytes(b"".join(inputs))
    if run([probe, "vectors", path]).stdout.splitlines() != expected:
        raise AssertionError("native expansion/status differs from independent complete-input vectors")
    key = bytes(range(32)); digest = base[84:]; record = measured.build_record(key, WORDS, identity, digest)
    if len(record) != 64 or record[:16] != b"PYOBF-RELKEY-v2\0" or key in record:
        raise AssertionError("measured v2 record framing/raw-key boundary")
    if bytes(a ^ b for a, b in zip(measured.record_mask(record), measured.expansion(WORDS, identity, digest))) != key:
        raise AssertionError("measured host roundtrip")
    refused(lambda: measured.record_mask(legacy.build_record(key, WORDS)))
    refused(lambda: legacy.record_mask(record))
    for bad in (b"", bytes(31), bytes(33), bytearray(32), "x" * 32):
        refused(lambda bad=bad: measured.expansion(WORDS, identity, bad))
        refused(lambda bad=bad: measured.build_record(bad, WORDS, identity, digest))
    for bad in (record[:-1], record + b"\0", bytearray(record), bytes(64)):
        refused(lambda bad=bad: measured.record_mask(bad))
    for bad in ((0,) * 7, (0,) * 9, (True,) * 8, (-1,) * 8, (1 << 32,) * 8):
        refused(lambda bad=bad: measured.expansion(bad, identity, digest))
    refused(lambda: measured.expansion(WORDS, replace(identity, stage=3), digest))
    print(f"{len(inputs)} independent all-input-bit vectors, distinct complete input influence and v1/v2/type refusals pass")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "probe", "runtime_directory", "build_dir"): parser.add_argument(name, type=Path)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--measure-output", type=Path)
    parser.add_argument("--bypass", action="store_true")
    parser.add_argument("--contribution", action="store_true")
    parser.add_argument("--scope-negative", choices=("protected", "plain"))
    parser.add_argument("--scope", action="store_true")
    parser.add_argument("--scope-digest-bypass", action="store_true")
    args = parser.parse_args()
    if bool(args.compare) != bool(args.measure_output): parser.error("paired measurement requires both paths")
    if (args.scope_negative or args.scope_digest_bypass) and not args.scope: parser.error("scoped negatives require scoped material")
    if args.scope and not args.contribution: parser.error("scoped material requires contribution mode")
    if args.scope_digest_bypass and (args.bypass or args.compare or args.scope_negative): parser.error("choose one scoped negative mode")
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="measured-key-", dir=args.build_dir) as temporary:
        directory = Path(temporary); vectors(args.probe, directory)
        _, fragments, dll = prepare_fixture(args.compiler, directory)
        raw = dll.read_bytes(); image = parse_image(raw)
        symbol = next(item for item in image_symbols(raw, image) if item.name == "extent_eh")
        entry = image.layout.sections[symbol.section - 1].rva + symbol.value
        subjects = (text_subject(image, 0x901), unwind_interval(raw, image, 0x902, entry),
            function_subject(fragments.read_bytes(), raw, image, 0x903, "extent_split",
                aliases=("extent_alias",), fragments=("extent_cold",)))
        meta, package, record, sealed = [directory / name for name in ("meta", "package", "record", "sealed")]
        nonce, key = bytes(range(12)), bytes(range(32)); encrypted = AESGCM(key).encrypt(nonce, b"measured", b"measured-release-test-v1")
        sealed.write_bytes(nonce + encrypted[-16:] + encrypted[:-16]); costs = []
        contribution = directory / "contribution-vectors.bin"
        rows = ((0x1020, 1, 7, 11, 13, 0), (0x1020, 1, 7, 12, 14, 0xffffffff),
            (0xa1b2c3d4, 0x55443322, 9, 1, 0xfe, 0x99887766), (7, 3, 5, 7, 11, 13))
        contribution.write_bytes(b"".join(struct.pack("<7I", *row, int.from_bytes(hashlib.sha256(
            b"pyobf.native.contribution.context.v1\0" + struct.pack("<6I", *row) + key).digest()[:4], "little") or 1)
            for row in rows))
        for kind, subject in enumerate(subjects, 1):
            identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), 7, subject.tag, kind, 2 if args.contribution else 1, 4096)
            meta.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
            package.write_bytes(build_reference(raw, subject, identity, WORDS))
            record.write_bytes(measured.build_record(key, WORDS, identity, reference_digest(raw, image, subject, 7)))
            scope_material = directory / "scope-material.bin"
            if args.scope:
                observed = reference_digest(raw, image, subject, 7)
                independent = hashlib.sha256(b"pyobf.native.contribution.scope.material.v1\0" +
                    hashlib.sha256(b"pyobf.native.release.measured.v1\0" + struct.pack("<8I", *WORDS) +
                        identity_bytes(identity) + observed).digest()).digest()
                if material_key(WORDS, identity, observed) != independent:
                    raise AssertionError("scoped material host framing differs from independent SHA oracle")
                for bad in (bytes(31), bytes(33), bytearray(32)):
                    refused(lambda bad=bad: build_material(bad, WORDS, identity, observed))
                refused(lambda: build_material(key, WORDS, replace(identity, stage=1), observed))
                scope_material.write_bytes(build_material(key, WORDS, identity, observed))
            command = [meta, package, record, dll, sealed, *([contribution] if args.contribution else []),
                *([scope_material] if args.scope else [])]
            result = run([args.probe, *command, *(["bypass"] if args.bypass else ["scope-digest"] if args.scope_digest_bypass else ["cost"] if args.compare else [])])
            print(subject.kind, result.stdout.splitlines()[-1])
            if args.scope_negative:
                denied = subprocess.run(list(map(str, [args.probe, *command, "scope-bad"])),
                    capture_output=True, text=True, timeout=5)
                if (denied.returncode != 91 if args.scope_negative == "plain" else denied.returncode in (0, 91, 92)):
                    raise AssertionError(f"scope mask did not poison actual protected transition before effect: exit{denied.returncode}")
            if args.compare:
                values = {}
                for name, output in (("protected", result), ("plain", run([args.compare, *command, "cost"]))):
                    batches = [float(line.split()[1]) for line in output.stdout.splitlines()
                        if line.startswith("scope-cost " if args.scope else "cost ")]
                    if len(batches) != 7 or min(batches) <= 0: raise AssertionError("paired key costs lack seven positive batches")
                    values[name] = {"median_ns": median(batches), "batches_ns": batches}
                costs.append({"subject": subject.kind, "bytes": sum(span.size for span in subject.ranges), "costs": values,
                    "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                    "record_sha256": hashlib.sha256(record.read_bytes()).hexdigest()})
        if args.contribution:
            identity = replace(identity, stage=1)
            meta.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
            package.write_bytes(build_reference(raw, subject, identity, WORDS))
            record.write_bytes(measured.build_record(key, WORDS, identity, reference_digest(raw, image, subject, 7)))
            run([args.probe, meta, package, record, dll, sealed, contribution, *([scope_material] if args.scope else [])])
            print("post-release material-to-word: independent4site vectors,actual code/record/fold/origin and pre-stage refusal pass")
        if args.measure_output:
            description = "fresh per-use observation and complete function-invocation Scope, protected queries/AEAD/parent admission/erasure; persistent observer creation and child loading outside timing" if args.scope else (
                ("hot measured material-to-word derivation, SHA and final snapshot check" if args.contribution else "hot key reconstruction with pre/post observation checks, SHA and erasure") + "; retained snapshot; actual read/authentication/owner creation/child decrypt outside timing")
            args.measure_output.write_text(json.dumps({"scope": description,
                "batches": 7, "calls_per_batch": 64 if args.scope else 128, "subjects": costs,
                "compiler": run([args.compiler, "--version"]).stdout.splitlines()[0],
                "sample_sha256": hashlib.sha256(raw).hexdigest(),
                "protected_image_sha256": hashlib.sha256(args.probe.read_bytes()).hexdigest(),
                "plain_image_sha256": hashlib.sha256(args.compare.read_bytes()).hexdigest()}, indent=2) + "\n")


if __name__ == "__main__": main()
