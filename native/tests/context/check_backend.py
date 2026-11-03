"""Reject unsupported owned-context backends while preserving legacy SDK-only builds."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("cmake", "compiler", "make_program", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("generator")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")

    def run(command, succeeds=True):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=60)
        if (result.returncode == 0) != succeeds:
            raise AssertionError(f"backend command failed: {command}\n{result.stdout}\n{result.stderr}")
        return result

    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        configuration = [args.cmake, "-S", root, "-B", directory, "-G", args.generator,
                         f"-DCMAKE_CXX_COMPILER={args.compiler}", f"-DCMAKE_MAKE_PROGRAM={args.make_program}",
                         "-DPYOBF_NATIVE_BACKEND=portable_stub", "-DPYOBF_NATIVE_BUILD_LLVM_PASS=OFF",
                         "-DPYOBF_NATIVE_BUILD_DEMO=OFF", "-DPYOBF_NATIVE_BUILD_ARCHIVE_RUNTIME=OFF"]
        result = run([*configuration, "-DPYOBF_NATIVE_BUILD_CONTEXT_RUNTIME=ON"], succeeds=False)
        if "does not provide owned bootstrap context operations" not in result.stderr:
            raise AssertionError("unsupported backend failed for an unrelated reason")
        run([*configuration, "-DPYOBF_NATIVE_BUILD_CONTEXT_RUNTIME=OFF"])
        run([args.cmake, "--build", directory, "--config", "Release", "--target", "pyobf_native_sdk_smoke"])
        multi_config = any(line.startswith("CMAKE_CONFIGURATION_TYPES:")
                           for line in (directory / "CMakeCache.txt").read_text().splitlines())
        executable_dir = directory / "tests"
        if multi_config: executable_dir /= "Release"
        run([executable_dir / "pyobf_native_sdk_smoke.exe"])


if __name__ == "__main__":
    main()
