"""Transform actual context/SDK sources and execute their lifetime/publication contracts."""

import argparse
import os
from pathlib import Path
import tempfile

from cff_build import protect, run, verify_image


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "provider", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    for group in ("core", "sdk", "backend"):
        parser.add_argument(f"--{group}", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", str(root / "include"), "-I", str(root / "src")]
    parent_options = ["-flto=thin"] if args.ipo else []
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        units = []
        for index, source in enumerate([*args.core, *args.sdk]):
            unit = directory / f"unit-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang",
                 "-disable-O0-optnone", *includes, source, "-o", unit])
            if "@llvm.global_ctors" in unit.read_text():
                raise AssertionError(f"context/SDK introduced dynamic global initialization: {source}")
            units.append(unit)
        combined, native_object, report = protect(args, directory, "runtime", units, 47)
        backend = [path for path in args.backend if path.resolve() not in {source.resolve() for source in args.sdk}]
        checker = [os.sys.executable, root / "demo/check_linked_cff.py", args.objdump]
        for name, files, marker, provider in (
                ("lifecycle", ("lifecycle.cpp", "concurrency.cpp", "module.cpp"), "owned context lifecycle verified", True),
                ("binding", ("binding_smoke.cpp", "binding_reentrancy.cpp", "binding_concurrency.cpp"),
                 "owned context publication verified", True),
                ("snapshot", ("../sdk_snapshot.cpp",), "legacy SDK snapshot verified", False)):
            harness = [root / "tests/context" / path for path in files]
            binary = directory / f"{name}.exe"
            run([args.compiler, "-std=c++17", "-O2", native_object, *harness, *backend,
                 *includes, *parent_options, "-o", binary])
            if marker not in run([binary, *([args.provider] if provider else [])]).stdout:
                raise AssertionError(f"protected {name} did not complete its actual runtime contract")
            verify_image(checker, binary, report, directory / f"{name}.final.json")
        plain = directory / "plain.exe"
        run([args.compiler, "-std=c++17", "-O0", combined,
             *[root / "tests/context" / path for path in ("lifecycle.cpp", "concurrency.cpp", "module.cpp")],
             *backend, *includes, "-o", plain])
        run([plain, args.provider])
        rejected = directory / "rejected.json"
        run([*checker, plain, report, "--output", rejected], succeeds=False)
        if rejected.exists():
            raise AssertionError("actual unprotected context produced successful final evidence")

        _, core_object, core_report = protect(args, directory, "failures", units[:len(args.core)], 42)
        faults = directory / "failures.exe"
        run([args.compiler, "-std=c++17", "-O2", core_object, root / "tests/context/failures.cpp",
             *includes, *parent_options, "-o", faults])
        if "owned context failure boundaries verified" not in run([faults]).stdout:
            raise AssertionError("protected failure-backend suite did not complete")
        verify_image(checker, faults, core_report, directory / "failures.final.json")
        print(f"42 context + 5 SDK bodies verified: source {args.optimization}, parent IPO {args.ipo}; "
              "lifecycle/publication/snapshot/failures, actual DLL unload, plain-image rejection")


if __name__ == "__main__":
    main()
