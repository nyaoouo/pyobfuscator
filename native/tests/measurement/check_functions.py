"""Exact compiler-owned function ranges, actual native captures and producer refusals."""
import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

from check_capture import check_native
from function_subject import function_subject
from coff_layout import parse_object
from code_observation import reference_digest
from pe_layout import data_directory, parse_image, read_rva
from pe_relocations import relocations

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import run
from function_cases import check_cases
from function_icf import check_icf
from function_relocations import check_relocations
from function_data_targets import check_data_targets


def execute_fixture(dll, runtime_directory):
    with os.add_dll_directory(str(runtime_directory.resolve())):
        library = ctypes.WinDLL(str(dll.resolve()))
        handle = library._handle
        try:
            library.measurement_target.argtypes = [ctypes.c_int]; library.measurement_target.restype = ctypes.c_int
            library.extent_eh.argtypes = [ctypes.c_int]; library.extent_eh.restype = ctypes.c_uint
            if library.measurement_target(12) != 19 or library.extent_eh(-3) != ((68 * 3) ^ 17):
                raise AssertionError("actual split/EH function execution differs")
        finally:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]; kernel.FreeLibrary.restype = ctypes.c_int
            if not kernel.FreeLibrary(handle): raise OSError(ctypes.get_last_error(), "close function fixture")


def prepare_fixture(compiler, directory):
    obj, fragments, dll = (directory / name for name in ("fixture.obj", "fragments.obj", "fixture.dll"))
    run([compiler, "-O2", "-ffunction-sections", "-c", ROOT / "tests/measurement/function_fixture.cpp", "-o", obj])
    run([compiler, "-c", ROOT / "tests/measurement/function_fragments.s", "-o", fragments])
    run([compiler, "-shared", obj, fragments, "-o", dll])
    return obj, fragments, dll


def main():
    parser = argparse.ArgumentParser()
    for key in ("compiler", "probe", "runtime_directory", "build_dir"):
        parser.add_argument(key, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="function-subject-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        obj, fragments, dll = prepare_fixture(args.compiler, directory)
        data = dll.read_bytes(); image = parse_image(data)
        expected = (("extent_leaf", obj, 1), ("extent_throw", obj, 1), ("extent_eh", obj, 1),
            ("_ZL12private_leafj", obj, 1), ("extent_split", fragments, 2))
        for index, (name, source, count) in enumerate(expected):
            options = {"aliases": ("extent_alias",), "fragments": ("extent_cold",)} if count == 2 else {}
            subject = function_subject(source.read_bytes(), data, image, 0x300 + index, name, **options)
            if len(subject.ranges) != count: raise AssertionError("authored function/fragment inventory differs")
            parsed = parse_object(source.read_bytes())
            own = next(symbol for symbol in parsed.symbols if symbol.name == name and symbol.type == 0x20)
            lengths = []
            inspected = run([args.compiler.with_name("llvm-readobj.exe"), "--symbols", source]).stdout
            for section in parsed.sections:
                if parsed.owners[section.index - 1] != own.section or not section.flags & 0x20000000: continue
                match = re.search(r"    Name: " + re.escape(section.name) +
                    r"\n(?:(?!\n  }).)*?AuxSectionDef \{\s+Length: (\d+)", inspected, re.S)
                if match is None: raise AssertionError("independent LLVM reader lacks input-contribution extent")
                lengths.append(int(match[1]))
            if sorted(lengths) != sorted(span.size for span in subject.ranges):
                raise AssertionError("final ranges disagree with independently decoded compiler contributions")
            if count == 2 and sorted(lengths) != [5, 16]:
                raise AssertionError("authored split root/cold/literal extent differs")
            if name == "extent_leaf":
                pdata, size = data_directory(image, 3)
                entries = tuple(struct.iter_unpack("<III", read_rva(data, image, pdata, size)))
                if any(begin <= subject.ranges[0].rva < end for begin, end, _ in entries):
                    raise AssertionError("leaf fixture unexpectedly acquired a runtime-function interval")
                span = subject.ranges[0]
                framing = b"pyobf.native.code.observation.v1\0" + struct.pack("<IIIIIII", 1, 3, subject.tag, 7, 1, span.rva, span.size)
                if hashlib.sha256(framing + read_rva(data, image, span.rva, span.size)).digest() != reference_digest(data, image, subject, 7):
                    raise AssertionError("independent kind3 digest framing differs")
            if count == 2 and not any(span.rva <= target and target + 8 <= span.rva + span.size
                    for span in subject.ranges for target in relocations(data, image)):
                raise AssertionError("cold fragment lost its covered actual DIR64 field")
            check_native(args.probe, args.runtime_directory, directory, dll, data, image, subject)
        execute_fixture(dll, args.runtime_directory)
        check_cases(obj.read_bytes(), fragments.read_bytes(), data)
        check_icf(args.compiler, directory)
        check_relocations(args.compiler, directory)
        check_data_targets(args, directory, run, check_native)
        print("five closed function subjects incl no-pdata leaf/private/GNU-EH/associated cold+alias; thirty actual native observations pass")


if __name__ == "__main__":
    main()
