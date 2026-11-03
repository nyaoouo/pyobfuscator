"""Actual linked/mapped DLL evidence for canonical PE code reference tooling."""
import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
from code_observation import observation_digest, reference_digest
from code_subject import text_subject, unwind_interval
from code_subject_cases import check_cases
from pe_layout import parse_image
from pe_relocations import relocations
from check_release_record import run

SOURCE = r'''
#ifndef OFFSET
#define OFFSET 1
#endif
extern "C" __declspec(dllexport) __attribute__((noinline)) int subject_compute(int value) {
    volatile int saved = value;
    return saved * 3 + OFFSET;
}
extern "C" __declspec(dllexport) __attribute__((section(".text"), used))
void *const subject_relocation = reinterpret_cast<void *>(&subject_compute);
'''


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "readobj", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    free = ctypes.WinDLL("kernel32", use_last_error=True).FreeLibrary
    free.argtypes = [ctypes.c_void_p]; free.restype = ctypes.c_int
    libraries, bases, results = [], [], []
    with tempfile.TemporaryDirectory(prefix="code-subjects-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "subject.cpp"; source.write_text(SOURCE, encoding="utf-8")
        try:
            for variant, preferred in ((1, 0x180000000), (2, 0x180000000), (3, 0)):
                path = directory / f"subject-{variant}.dll"
                run([args.compiler, "-std=c++17", "-shared", "-O2", "-fno-lto", f"-DOFFSET={variant}",
                    source, f"-Wl,--image-base,0x{preferred:x}", "-o", path])
                data = path.read_bytes(); image = parse_image(data)
                library = ctypes.WinDLL(str(path.resolve())); libraries.append(library)
                base = library._handle; bases.append(base)
                compute = library.subject_compute; compute.argtypes = [ctypes.c_int]; compute.restype = ctypes.c_int
                if compute(4) != 12 + variant: raise AssertionError("actual native fixture did not change its code result")
                entry = ctypes.cast(compute, ctypes.c_void_p).value - base
                anchor = ctypes.c_void_p.in_dll(library, "subject_relocation")
                anchor_rva = ctypes.addressof(anchor) - base
                fixups = relocations(data, image)
                if anchor_rva not in fixups or anchor.value != base + entry:
                    raise AssertionError("fixture did not retain its actual loaded executable-section DIR64 pointer")
                subjects = (text_subject(image, 11), unwind_interval(data, image, 12, entry))
                if not (subjects[0].ranges[0].rva <= anchor_rva < subjects[0].ranges[0].rva + subjects[0].ranges[0].size):
                    raise AssertionError("fixture relocation was not in measured code")
                inspection = run([args.readobj, "--unwind", path]).stdout
                found = re.search(r"StartAddress: subject_compute \(0x([0-9a-fA-F]+)\)\s+EndAddress: \(0x([0-9a-fA-F]+)\)", inspection)
                if found is None: raise AssertionError("independent LLVM reader did not identify the runtime-function extent")
                begin, end = (int(value, 16) - image.preferred_base for value in found.groups())
                interval = subjects[1].ranges[0]
                if (interval.rva, interval.size) != (begin, end - begin):
                    raise AssertionError("canonical interval differs from independent final unwind metadata")
                observed = []
                for subject in subjects:
                    for owner in (7, 8):
                        reads = []
                        def reader(rva, size):
                            reads.append((rva, size))
                            return ctypes.string_at(base + rva, size)
                        actual = observation_digest(image, subject, fixups, owner, base, reader)
                        if reads != [(span.rva, span.size) for span in subject.ranges]:
                            raise AssertionError("owner did not perform its own complete read")
                        if actual != reference_digest(data, image, subject, owner):
                            raise AssertionError("actual mapped code differs from its canonical build reference")
                        observed.append(actual)
                # Independently assemble the standard digest frame for a non-relocated function interval.
                if any(begin <= target < end for target in fixups):
                    raise AssertionError("independent digest fixture unexpectedly needs a relocation normalizer")
                prefix = b"pyobf.native.code.observation.v1\0" + struct.pack("<IIIII", 1, 2, 12, 7, 1)
                independent = hashlib.sha256(prefix + struct.pack("<II", begin, end - begin) +
                    ctypes.string_at(base + begin, end - begin)).digest()
                if independent != observed[2]: raise AssertionError("digest framing does not match its independent standard encoding")
                if image.preferred_base:
                    check_cases(data, image, subjects[0], entry)
                results.append((subjects[0].ranges, tuple(observed)))
            if len(set(bases)) != len(bases) or all(base == 0x180000000 for base in bases):
                raise AssertionError("fixture did not exercise different actual load bases")
            if results[0][0] != results[1][0] or any(a == b for a, b in zip(results[0][1], results[1][1])):
                raise AssertionError("changed actual code did not change same-range owner digests")
        finally:
            for library in reversed(libraries):
                if not free(library._handle): raise OSError(ctypes.get_last_error(), "fixture DLL release failed")
    print("three actual loaded DLLs including zero preferred base, four owner/subject reads each, LLVM intervals and digest framing verified")


if __name__ == "__main__":
    main()
