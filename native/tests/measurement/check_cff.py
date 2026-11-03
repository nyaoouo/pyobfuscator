"""Protect the real native capture core, then compare final live code with host references."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import protect, run, verify_image
from measure_capture import measure
from function_cff import check_functions
from function_emission import emit_functions


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--cmake", required=True, type=Path)
    parser.add_argument("--ninja", required=True, type=Path)
    parser.add_argument("--core", nargs="+", type=Path, required=True)
    parser.add_argument("--backend", nargs="+", type=Path, required=True)
    parser.add_argument("--sample", action="append", type=Path, default=[])
    parser.add_argument("--measure-output", type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="capture-cff-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        units = []
        for index, source in enumerate(args.core):
            output = directory / f"core-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                *includes, source, "-o", output])
            if "@llvm.global_ctors" in output.read_text(encoding="utf-8"):
                raise AssertionError("capture core introduced dynamic global initialization")
            units.append(output)
        # Twelve source-authored marked algorithms/ownership methods, independent of the report.
        combined, native, report = protect(args, directory, "capture", units, 12)
        default_object = emit_functions(args, directory, native, directory / "capture.protected.ll")
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        harness = [ROOT / "tests/measurement/probe.cpp", ROOT / "tests/measurement/descriptor.cpp"]
        common = [*harness, *args.backend, *includes, "-lbcrypt", *( ["-flto=thin"] if args.ipo else [])]
        binary = directory / "protected.exe"
        run([args.compiler, "-std=c++17", "-O2", native, *common, "-o", binary])
        verify_image(checker, binary, report, directory / "capture.final.json")
        check_functions(args, directory, native, binary, combined, default_object)
        command = [sys.executable, ROOT / "tests/measurement/check_capture.py", binary, args.runtime_directory, directory]
        for sample in args.sample: command.extend(["--sample", sample])
        run(command)
        run([sys.executable, ROOT / "tests/measurement/check_functions.py", args.compiler, binary,
            args.runtime_directory, directory])
        plain = directory / "plain.exe"
        run([args.compiler, "-std=c++17", "-O2", combined, *common, "-o", plain])
        run([sys.executable, ROOT / "tests/measurement/check_capture.py", plain, args.runtime_directory, directory])
        refused = directory / "plain.final.json"
        run([*checker, plain, report, "--output", refused], succeeds=False)
        if refused.exists(): raise AssertionError("unprotected capture core borrowed final CFF evidence")
        if args.measure_output:
            measure(args, directory, combined, native, includes, report)
        print(f"12 marked native capture core bodies, source{args.optimization}/parentIPO{args.ipo}, real CNG/ownership/availability and plain refusal pass")


if __name__ == "__main__":
    main()
