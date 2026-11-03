"""Protect existing capture/archive and new reference core together, then execute both backends."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import protect, run, verify_image
from measure_reference import measure
from check_slots import check as check_slots


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--core", nargs="+", type=Path, required=True)
    parser.add_argument("--backend", nargs="+", type=Path, required=True)
    parser.add_argument("--measure-output", type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    parent = ["-flto=thin"] if args.ipo else []
    with tempfile.TemporaryDirectory(prefix="reference-cff-", dir=args.build_dir) as temporary:
        directory = Path(temporary); units = []
        for index, source in enumerate(args.core):
            output = directory / f"core-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                *includes, source, "-o", output])
            if "@llvm.global_ctors" in output.read_text(): raise AssertionError("reference core introduced dynamic initialization")
            units.append(output)
        # Source-authored Reference15 + existing Archive9 + Capture12; not a report-derived count.
        combined, native, report = protect(args, directory, "reference", units, 36)
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        actual, faults = directory / "actual.exe", directory / "faults.exe"
        run([args.compiler, "-std=c++17", "-O2", native, ROOT / "tests/measurement/reference_probe.cpp",
            *args.backend, *includes, *parent, "-lbcrypt", "-o", actual])
        atomic = [source for source in args.backend if source.name == "atomic.cpp"]
        if len(atomic) != 1: raise AssertionError("reference fault fixture needs one backend atomic implementation")
        run([args.compiler, "-std=c++17", "-O2", native, ROOT / "tests/measurement/reference_faults.cpp",
            ROOT / "tests/measurement/failure_backend.cpp", *atomic, *includes, *parent, "-o", faults])
        verify_image(checker, actual, report, directory / "actual.final.json")
        verify_image(checker, faults, report, directory / "faults.final.json")
        slot_directory = directory / "slots"; slot_directory.mkdir()
        slot_image = check_slots(args, slot_directory, [native])
        verify_image(checker, slot_image, report, directory / "slots.final.json")
        command = [sys.executable, ROOT / "tests/measurement/check_reference.py", args.compiler, actual,
            args.runtime_directory, directory, "--faults", faults]
        run(command)
        plain = directory / "plain.exe"
        run([args.compiler, "-std=c++17", "-O2", combined, ROOT / "tests/measurement/reference_probe.cpp",
            *args.backend, *includes, *parent, "-lbcrypt", "-o", plain])
        run([sys.executable, ROOT / "tests/measurement/check_reference.py", args.compiler, plain, args.runtime_directory, directory])
        refused = directory / "plain.final.json"
        run([*checker, plain, report, "--output", refused], succeeds=False)
        if refused.exists(): raise AssertionError("unprotected reference decoder borrowed CFF evidence")
        if args.measure_output: measure(args, directory, plain, actual, combined, native)
        print(f"36 marked reference/archive/capture bodies: source{args.optimization}, IPO{args.ipo}, real CNG/faults/independence/plain refusal pass")


if __name__ == "__main__":
    main()
