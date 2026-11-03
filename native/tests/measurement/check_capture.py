"""Native CNG/retained-module captures compared with independent host references."""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from code_observation import reference_digest
from code_subject import KINDS, text_subject, unwind_interval
from pe_layout import data_directory, parse_image, read_rva
from pe_relocations import relocations


def descriptor(image, subject, fixups):
    kind = KINDS[subject.kind]
    return struct.pack("<IIIIQII", kind, subject.tag, 7, image.layout.image_size, image.preferred_base,
        len(subject.ranges), len(fixups)) + b"".join(struct.pack("<II", span.rva, span.size) for span in subject.ranges) + \
        b"".join(struct.pack("<I", target) for target in fixups)


def check_native(probe, runtime_directory, directory, image_path, raw, image, subject):
    environment = dict(os.environ)
    environment["PATH"] = str(runtime_directory) + os.pathsep + environment.get("PATH", "")
    path = directory / (image_path.name + f".{subject.tag}.bin")
    path.write_bytes(descriptor(image, subject, relocations(raw, image)))
    command = [str(probe.resolve()), "self", str(path.resolve())]
    if image_path.resolve() != probe.resolve():
        command = [str(probe.resolve()), "dll", str(path.resolve()), str(image_path.resolve())]
    result = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=30)
    if result.returncode or "ownership-concurrency-verified" not in result.stdout:
        raise AssertionError(f"native capture failed: {image_path.name}/{subject.kind}\n{result.stdout}\n{result.stderr}")
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith("capture ")]
    if len(rows) != 6: raise AssertionError("native probe lost an independent capture")
    for expected_owner, row in zip(range(7, 13), rows):
        if len(row) != 8: raise AssertionError("native capture output has invalid framing")
        owner, tag, kind, frequency, started, completed = map(int, row[1:7])
        if (owner != expected_owner or tag != subject.tag or kind != KINDS[subject.kind] or
                frequency <= 0 or started < 0 or completed < started):
            raise AssertionError("native acquisition metadata is invalid or mixed across owners")
        if row[7] != reference_digest(raw, image, subject, owner).hex():
            raise AssertionError(f"actual native CNG digest differs from host canonical reference: {subject.kind}, owner{owner}")


def main():
    parser = argparse.ArgumentParser()
    for name in ("probe", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--sample", action="append", type=Path, default=[])
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="native-capture-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        for image_path in (args.probe, *args.sample):
            raw = image_path.read_bytes(); image = parse_image(raw)
            pdata_rva, pdata_size = data_directory(image, 3)
            if pdata_size < 12: raise AssertionError("native fixture lacks unwind intervals")
            begin = struct.unpack_from("<I", read_rva(raw, image, pdata_rva, 12))[0]
            subjects = (text_subject(image, 0x201), unwind_interval(raw, image, 0x202, begin))
            fixups = relocations(raw, image)
            for subject in subjects:
                if image_path != args.probe and subject.kind == "section" and not any(
                        span.rva <= target and target + 8 <= span.rva + span.size
                        for span in subject.ranges for target in fixups):
                    raise AssertionError("real DLL fixture lost its measured DIR64 relocation")
                check_native(args.probe, args.runtime_directory, directory, image_path, raw, image, subject)
            print(f"native capture {image_path.name}: .text/interval, six owner captures each, CNG and lifetime/move/concurrency pass")


if __name__ == "__main__":
    main()
