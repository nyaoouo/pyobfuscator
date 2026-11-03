"""Controlled existing backend proves cache/lifecycle algorithms, not crypto authenticity."""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from archive_format import Kind, Record
from code_reference import HEADER, MAGIC
from pack_archive import seal
from reference_identity import Identity, identity_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("probe", type=Path); parser.add_argument("build_dir", type=Path)
    parser.add_argument("--runtime-directory", type=Path)
    parser.add_argument("--reader-cases", action="store_true")
    args = parser.parse_args()
    if args.runtime_directory:
        os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), 7, 11, 1, 1, 248)
    body = HEADER.pack(MAGIC, 1, HEADER.size, 1, 1, 11, 7, 1, 1, 0, 0x3000,
        0x180000000, b"\xdd" * 32, bytes(8)) + struct.pack("<II", 0x1000, 32)
    with tempfile.TemporaryDirectory(prefix="observer-faults-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        meta, package, plain = (directory / name for name in ("meta", "package", "plain"))
        meta.write_bytes(identity_bytes(identity) + struct.pack("<8I", *range(8)))
        package.write_bytes(seal([Record("observer", Kind.bytes, 8, 1, 0, body)]).data); plain.write_bytes(body)
        cases = ((None, 0), ("reader-close", 75)) if args.reader_cases else ((None, 0), ("module-close", 74), ("provider-close", 75))
        for option, wanted in cases:
            result = subprocess.run([str(args.probe), str(meta), str(package), str(plain), *([option] if option else [])],
                capture_output=True, text=True, timeout=45)
            if result.returncode != wanted:
                raise AssertionError(f"observer fault {option}: exit{result.returncode}\n{result.stdout}\n{result.stderr}")
            if not option: print(result.stdout.strip())
    print("reader callback release failure terminates before context provider cleanup" if args.reader_cases else
        "module/provider release failures terminate rather than returning success")


if __name__ == "__main__": main()
