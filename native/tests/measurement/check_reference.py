"""Existing archive AEAD, independent identity and real native reference/code roundtrips."""
import argparse
import os
from pathlib import Path
import struct
import sys
import tempfile

from check_capture import ROOT
from check_functions import prepare_fixture
from code_reference import build_reference, plaintext
from code_subject import text_subject, unwind_interval
from function_subject import function_subject
from pe_layout import data_directory, parse_image, read_rva
from reference_identity import Identity, identity_bytes

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run
from reference_cases import check_cases

WORDS = (0x10203040, 0x22334455, 0x44556677, 0x12345678, 0x87654321, 0x33445566, 0x77889900, 0x99887766)


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "probe", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--faults", type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="code-reference-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        obj, fragments, dll = prepare_fixture(args.compiler, directory)
        for image_path in (args.probe, dll):
            data = image_path.read_bytes(); image = parse_image(data)
            pdata, _ = data_directory(image, 3)
            entry = struct.unpack_from("<I", read_rva(data, image, pdata, 12))[0]
            subjects = [text_subject(image, 0x501), unwind_interval(data, image, 0x502, entry)]
            if image_path == dll:
                subjects.append(function_subject(fragments.read_bytes(), data, image, 0x503, "extent_split",
                    aliases=("extent_alias",), fragments=("extent_cold",)))
            for index, subject in enumerate(subjects):
                kind = index + 1
                image_role = bytes(range(33, 49)) if image_path == dll else bytes(range(17, 33))
                identity = Identity(bytes(range(1, 17)), image_role, 7 + index,
                    subject.tag, kind, 1 + index % 2, 4096)
                metadata, package = directory / "metadata.bin", directory / "package.bin"
                metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
                encrypted = build_reference(data, subject, identity, WORDS)
                package.write_bytes(encrypted)
                run([args.probe, metadata, package, "0", "1", *([image_path] if image_path == dll else [])])
                if image_path == args.probe and index == 0:
                    check_cases(args, directory, image_path, data, subject, identity, WORDS, encrypted)
                    if args.faults:
                        plain = directory / "plaintext.bin"; plain.write_bytes(plaintext(data, subject, identity))
                        metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS)); package.write_bytes(encrypted)
                        print(run([args.faults, metadata, package, plain]).stdout.strip())
        print("native reference .text/interval/closed function roundtrips in actual EXE/DLL pass")


if __name__ == "__main__":
    main()
