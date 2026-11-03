"""CFF actual owned-context client/provider sources, then execute their lifetime suite."""

import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "demo")]
from cff_build import protect, run, verify_image
from check_context import check


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    parser.add_argument("--backend-source", type=Path, action="append", required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="contribution-cff-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        units = []
        for index, source in enumerate(args.sources):
            unit = directory / f"source-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
                 *includes, source, "-o", unit]); units.append(unit)
        combined, protected, report = protect(args, directory, "contribution", units, 44)
        backend = []
        for index, source in enumerate(args.backend_source):
            obj = directory / f"backend-{index}.obj"
            run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else ["-fno-lto"]),
                 *includes, "-c", source, "-o", obj]); backend.append(obj)
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        for name, source in (("protected", protected), ("plain", combined)):
            binary = directory / (name + ".exe")
            run([args.compiler, "-std=c++17", "-O2", source, *backend, *includes,
                 ROOT / "tests/contribution/context.cpp", *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", binary])
            check(binary, args.compiler.parent)
            final = directory / (name + ".json")
            if name == "protected": verify_image(checker, binary, report, final)
            else:
                run([*checker, binary, report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain contribution sources received CFF proof")
        provider_units = [unit for source, unit in zip(args.sources, units)
                          if source.resolve() == (ROOT / "src/contribution/context_derive.cpp").resolve()]
        if len(provider_units) != 1: raise AssertionError("one actual derivation source required")
        failure_plain, failure_object, failure_report = protect(args, directory, "failure", provider_units, 1)
        for name, source in (("protected", failure_object), ("plain", failure_plain)):
            binary = directory / ("failure-" + name + ".exe")
            run([args.compiler, "-std=c++17", "-O2", source, *includes,
                 ROOT / "tests/contribution/derive_failure.cpp", *(["-flto=thin"] if args.ipo else []), "-o", binary])
            output = run([binary]).stdout
            if "private serialization/digest erasure verified" not in output:
                raise AssertionError("derivation resource/failure suite did not finish")
            final = directory / ("failure-" + name + ".json")
            if name == "protected": verify_image(checker, binary, failure_report, final)
            else:
                run([*checker, binary, failure_report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain failure derivation received CFF proof")
        print(f"44 actual contribution/context SDK definitions: source{args.optimization},IPO={args.ipo}; actual CNG/lifetime suite, emitted provider OOM/hash/erasure and same-source final refusals verified")


if __name__ == "__main__":
    main()
