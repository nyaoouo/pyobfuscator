"""Execute real immutable PE records before/after bounded data-only finalization."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
from pe_release_record import finalize_image
from release_format import DOMAIN, MAGIC, MASK_OFFSET, PLACEHOLDER, SIZE, build_record, expansion, record_mask
from release_record_cases import malformed_images, sections


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=45)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"release record command differs: {command}\n{result.stdout}\n{result.stderr[:4000]}")
    return result


def rejected(function):
    try:
        function()
    except ValueError:
        return
    raise AssertionError("malformed release material was accepted")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "readobj", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--ipo", action="store_true")
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    if MAGIC != b"PYOBF-RELKEY-v1\0" or DOMAIN != b"pyobf.native.release.fold.v1\0" or len(PLACEHOLDER) != 64:
        raise AssertionError("release v1 domain or record changed without a version transition")
    key, state = bytes(range(32)), tuple(range(8))
    expected = hashlib.sha256(b"pyobf.native.release.fold.v1\0" + struct.pack("<8I", *state)).digest()
    record = build_record(key, state)
    if expansion(state) != expected or record_mask(record) != bytes(a ^ b for a, b in zip(key, expected)):
        raise AssertionError("host expansion or mask does not match its defined standard digest")
    if bytes(a ^ b for a, b in zip(record_mask(record), expected)) != key or key in record:
        raise AssertionError("record round trip failed or serialized the raw fixture content key")
    for bad in (b"", bytes(31), bytes(33), bytearray(32), "x" * 32):
        rejected(lambda bad=bad: build_record(bad, state))
    for bad in ((0,) * 7, (0,) * 9, (True,) * 8, (-1,) * 8, (1 << 32,) * 8):
        rejected(lambda bad=bad: build_record(key, bad))
    for bad in (record[:-1], record + b"\0", bytearray(record), bytes(64)):
        rejected(lambda bad=bad: record_mask(bad))
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        includes = ["-I", ROOT / "src"]
        record_object = directory / "record.obj"
        run([args.compiler, "-std=c++17", "-O0", "-fno-lto", *includes, "-c",
             ROOT / "backends/windows_user/release_record.cpp", "-o", record_object])
        if record_object.read_bytes()[:2] != b"\x64\x86":
            raise AssertionError("record definition was emitted as IR/LTO instead of an AMD64 native object")
        input_record = directory / "record.bin"
        input_record.write_bytes(record)
        finalized_count = 0
        for profile in ("none", "O2"):
            original = directory / (profile + ".exe")
            run([args.compiler, "-std=c++17", "-O0" if profile == "none" else "-O2", *includes,
                 *(["-flto=thin"] if args.ipo else []), ROOT / "tests/release_record.cpp", record_object, "-o", original])
            if bytes.fromhex(run([original]).stdout.strip()) != PLACEHOLDER:
                raise AssertionError("native loaded placeholder differs from the fixed host format")
            image = original.read_bytes()
            # Inspect the section independently with LLVM's reader, not only our parser.
            inspection = run([args.readobj, "--sections", original]).stdout
            parts = [part for part in re.findall(r"Section \{\n(.*?)\n  \}", inspection, re.S)
                     if re.search(r"Name: \.pyobf\s", part)]
            if len(parts) != 1 or "IMAGE_SCN_MEM_EXECUTE" in parts[0] or "IMAGE_SCN_MEM_WRITE" in parts[0]:
                raise AssertionError("actual native record section is absent, duplicated, writable or executable")
            offset = int(re.search(r"PointerToRawData: (0x[0-9A-Fa-f]+)", parts[0])[1], 16)
            if image[offset:offset + SIZE] != PLACEHOLDER:
                raise AssertionError("LLVM section offset does not identify the exact native record")
            output, report_file = directory / (profile + ".filled.exe"), directory / (profile + ".filled.json")
            cli = [sys.executable, ROOT / "tools/finalize_release.py", original, input_record, output, "--report", report_file]
            run(cli)
            filled = output.read_bytes()
            if bytes.fromhex(run([output]).stdout.strip()) != record:
                raise AssertionError("actual loaded finalized record differs from the requested mask")
            if (filled[:offset + MASK_OFFSET] != image[:offset + MASK_OFFSET] or
                    filled[offset + MASK_OFFSET + 32:] != image[offset + MASK_OFFSET + 32:] or len(filled) != len(image)):
                raise AssertionError("actual finalized image changed outside32 mask bytes")
            # Independent header geometry must remain byte-for-byte unchanged too.
            _, optional, table, rows = sections(image)
            header_end = table + len(rows) * 40
            if image[:header_end] != filled[:header_end]: raise AssertionError("PE header geometry changed")
            report = json.loads(report_file.read_text())
            if (report["write_offset"] != offset + MASK_OFFSET or report["write_size"] != 32 or
                    report["image_after_sha256"] != hashlib.sha256(filled).hexdigest() or report["idempotent"] or
                    not report["layout_verified_unchanged"] or not report["executable_bytes_verified_unchanged"]):
                raise AssertionError("finalizer identity or data-only proof report is wrong")
            again, identity = finalize_image(filled, record)
            if again != filled or not identity["idempotent"]: raise AssertionError("identical finalization is not idempotent")
            rejected(lambda: finalize_image(filled, build_record(bytes(reversed(key)), state)))
            run([sys.executable, ROOT / "tools/finalize_release.py", output, input_record, output])
            if output.read_bytes() != filled: raise AssertionError("in-place idempotent finalization changed image bytes")
            cases = malformed_images(image)
            for name, malformed in cases:
                try:
                    finalize_image(malformed, record)
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"malformed PE image was accepted: {name}")
            # Failed validation and colliding destinations must not overwrite artifacts.
            input_record.write_bytes(b"invalid")
            run(cli, succeeds=False)
            if output.read_bytes() != filled or json.loads(report_file.read_text()) != report:
                raise AssertionError("failed record validation changed an existing output/report")
            input_record.write_bytes(record)
            run([sys.executable, ROOT / "tools/finalize_release.py", original, input_record, input_record], succeeds=False)
            run([sys.executable, ROOT / "tools/finalize_release.py", original, input_record, output, "--report", output], succeeds=False)
            if input_record.read_bytes() != record or output.read_bytes() != filled:
                raise AssertionError("colliding output paths destroyed an input or output")
            finalized_count += 1
        print(f"release record: {finalized_count} real PE/runtime profiles, IPO={args.ipo}, {len(cases)} malformed images, host format, stale/idempotent/CLI and unchanged code/layout verified")


if __name__ == "__main__":
    main()
