"""Exercise the real CMake archive DAG, opaque O2 assets and incremental rebuilds."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(command: list[str], *, succeeds: bool = True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"archive CMake command differs: {command}\n{result.stdout}\n{result.stderr}")
    return result


def probe(image: Path, expected: Path, runtime: Path, symbol="read_asset") -> None:
    with os.add_dll_directory(str(runtime)):
        module = ctypes.CDLL(str(image))
    reader = getattr(module, symbol)
    reader.argtypes, reader.restype = [ctypes.c_uint], ctypes.c_int
    data = expected.read_bytes()
    for _ in range(2):
        if any(reader(index) != value for index, value in enumerate(data)) or reader(len(data)) != -1:
            raise AssertionError("protected asset cold/warm bytes or logical size differ")


def main() -> None:
    if len(sys.argv) == 5 and sys.argv[1] in ("--probe", "--probe-demo"):
        symbol = "pyobf_demo_asset_read" if sys.argv[1] == "--probe-demo" else "read_asset"
        probe(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), symbol)
        return
    parser = argparse.ArgumentParser()
    for name in ("cmake", "ninja", "compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="asset pipeline ", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        asset, expected, build = directory / "input file.bin", directory / "expected.bin", directory / "build"
        first = b"static-asset-first-build-" + bytes(range(64)) + b"\0\xff"
        asset.write_bytes(first)
        configure = [str(args.cmake), "-S", str(root / "tests" / "archive_pipeline"), "-B", str(build),
            "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}", f"-DCMAKE_CXX_COMPILER={args.compiler}",
            f"-DPython3_EXECUTABLE={sys.executable}", f"-DNATIVE_ROOT={root}", f"-DPLUGIN={args.plugin}",
            f"-DPYOBF_NATIVE_OPT_EXECUTABLE={args.opt}", f"-DPYOBF_NATIVE_LLVM_LINK_EXECUTABLE={args.llvm_link}",
            f"-DOBJDUMP={args.objdump}", f"-DASSET_FILE={asset}", "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"]
        run(configure)

        def build_and_check(data: bytes) -> tuple[bytes, bytes]:
            run([str(args.cmake), "--build", str(build), "-j", "2"])
            image = build / "asset_fixture.dll"
            binary = image.read_bytes()
            records = json.loads((build / "archive.plan.json").read_bytes())["records"]
            if not any(bytes.fromhex(row["data_hex"]) == (data or b"\0") for row in records):
                raise AssertionError("O2 asset contents did not reach the private archive plan")
            bindings = json.loads((build / "archive.bindings.json").read_bytes())
            if (len(data) >= 16 and data in binary) or any(bytes.fromhex(row["key_hex"]) in binary
                    for row in bindings["records"]):
                raise AssertionError("asset plaintext/raw record key survived in the distributable image")
            merged = json.loads((build / "archive.requests.json").read_bytes())["functions"]
            selected = [row for row in json.loads((build / "coverage.json").read_bytes())["functions"] if row["selected"]]
            if ({row["function"] for row in selected} != {row["function"] for row in merged if row["defined"]} or
                    not any(row.get("marker") == "pyobf.native.sdk" for row in selected) or
                    any(row["status"] != "transformed" for row in selected)):
                raise AssertionError("source/helper requests did not both reach final CFF")
            removed = next(row for row in selected if row["function"] == "optimized_literal")["archive_sources"]
            if not any(row["status"] == "optimized-away" for row in removed["sources"]):
                raise AssertionError("ordinary O2 silently lost original archive requests")
            expected.write_bytes(data)
            run([sys.executable, __file__, "--probe", str(image), str(expected), str(args.compiler.parent)])
            return binary, (build / "archive.bin").read_bytes()

        initial_image, initial_pool = build_and_check(first)
        generated = (build / "assets" / "asset_sample.cpp").read_bytes()
        asset.unlink()
        run([sys.executable, __file__, "--probe", str(build / "asset_fixture.dll"), str(expected), str(args.compiler.parent)])
        missing = run([str(args.cmake), "--build", str(build)], succeeds=False)
        if "input file.bin" not in missing.stdout + missing.stderr:
            raise AssertionError("missing input failed outside the intended asset dependency boundary")
        second = b"static-asset-second-build-" + bytes(reversed(range(64))) + b"\xff\0"
        asset.write_bytes(second)
        changed_image, changed_pool = build_and_check(second)
        if (changed_image == initial_image or changed_pool == initial_pool or
                (build / "assets" / "asset_sample.cpp").read_bytes() == generated):
            raise AssertionError("asset dependency change did not rebuild generated source/package/image")
        before = hashlib.sha256(changed_image).hexdigest()
        run([str(args.cmake), "--build", str(build)])
        if hashlib.sha256((build / "asset_fixture.dll").read_bytes()).hexdigest() != before:
            raise AssertionError("unchanged asset unnecessarily regenerated the encrypted image")
        asset.write_bytes(b"")
        build_and_check(b"")
        strict = directory / "strict.json"
        recipe = json.loads((root / "demo" / "recipes" / "archive.json").read_bytes())
        recipe["functions"] = {"optimized_literal": {"components": {"constant-archive": "required"}}}
        strict.write_text(json.dumps(recipe), encoding="utf-8")
        run([*configure, f"-DRECIPE={strict}"])
        run([str(args.cmake), "--build", str(build)], succeeds=False)
        failure = next(row for row in json.loads((build / "coverage.json").read_bytes())["functions"]
                       if row["function"] == "optimized_literal")
        if (failure["status"] != "unsupported" or
                failure.get("reason") != "required archive source request is absent or incomplete" or
                not failure["archive_sources"]["requested"] or failure["archive_sources"]["applied"]):
            raise AssertionError(f"required optimized-away source was credited or failed for another cause: {failure}")
        asset.unlink()
        result = run(configure, succeeds=False)
        if "Native asset input is not a file" not in result.stdout + result.stderr:
            raise AssertionError("missing asset was not rejected by CMake asset validation")


if __name__ == "__main__":
    main()
