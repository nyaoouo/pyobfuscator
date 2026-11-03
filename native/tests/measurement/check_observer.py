"""Real authenticated code snapshots through independent source-owned contexts."""
import argparse
import os
from pathlib import Path
import struct
import sys
import tempfile

from check_capture import ROOT
from check_reference import WORDS
from check_functions import prepare_fixture
from code_reference import build_reference
from code_subject import text_subject, unwind_interval
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image
from code_observation import reference_digest
from reference_identity import Identity, identity_bytes

sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "probe", "runtime_directory", "build_dir"): parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="owned-observer-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        _, fragments, dll = prepare_fixture(args.compiler, directory)
        data = dll.read_bytes(); image = parse_image(data)
        # Keep ordinary tests ASLR-enabled; control only the exact-address reload fixture.
        fixed = directory / "fixed-fixture.dll"
        pinned = bytearray(data)
        pe = struct.unpack_from("<I", pinned, 60)[0]
        flags = struct.unpack_from("<H", pinned, pe + 24 + 70)[0]
        if not flags & 0x40: raise AssertionError("ordinary fixture must exercise ASLR")
        struct.pack_into("<H", pinned, pe + 24 + 70, flags & ~0x40)
        fixed.write_bytes(pinned)
        symbol = next(item for item in image_symbols(data, image) if item.name == "extent_eh")
        entry = image.layout.sections[symbol.section - 1].rva + symbol.value
        subjects = (text_subject(image, 0x801), unwind_interval(data, image, 0x802, entry),
            function_subject(fragments.read_bytes(), data, image, 0x803, "extent_split",
                aliases=("extent_alias",), fragments=("extent_cold",)))
        for kind, subject in enumerate(subjects, 1):
            if reference_digest(bytes(pinned), parse_image(bytes(pinned)), subject, 7) != reference_digest(data, image, subject, 7):
                raise AssertionError("fixed-address fixture changed canonical code")
            inputs = []
            for owner in (7, 8):
                identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), owner, subject.tag, kind, 1, 4096)
                metadata, package = directory / f"{owner}.meta", directory / f"{owner}.bin"
                metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
                package.write_bytes(build_reference(data, subject, identity, WORDS)); inputs.extend((metadata, package))
            print(subject.kind, run([args.probe, *inputs, dll, fixed]).stdout.strip())


if __name__ == "__main__": main()
