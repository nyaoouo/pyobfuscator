"""CFF the actual source runtime and generated wrappers, then execute their data/failure suite."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(command: list[str], *, succeeds: bool = True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"archive CFF command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "linked_checker",
                 "header", "generated", "harness", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", str(root / "include"), "-I", str(root / "src"), "-I", str(args.header.parent)]
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        units = []
        for index, source in enumerate([*args.sources, args.generated]):
            output = directory / f"unit-{index}.ll"
            run([str(args.compiler), "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang",
                 "-disable-O0-optnone", *includes, str(source), "-o", str(output)])
            if source == args.generated and "@llvm.global_ctors" in output.read_text():
                raise AssertionError("per-record cache wrappers require unexpected dynamic initialization")
            units.append(output)
        combined, transformed = directory / "combined.ll", directory / "protected.ll"
        report = directory / "coverage.json"
        run([str(args.llvm_link), "-S", *map(str, units), "-o", str(combined)])
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", str(combined), "-o", str(transformed)])
        rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
        if len(rows) < 20 or any(row["status"] != "transformed" for row in rows):
            raise AssertionError("archive runtime/wrappers escaped selected CFF coverage")
        if not any("require_record" in row["function"] for row in rows):
            raise AssertionError("terminal require path was not transformed")
        for name in ("read32", "read64", "valid_type", "parse_record", "valid_plaintext",
                     "overlaps", "verify_access", "decode", "acquire_record", "require_record"):
            if not any(name in row["function"] for row in rows):
                raise AssertionError(f"archive SDK helper escaped CFF: {name}")
        wrappers = [name for name in args.generated.read_text().split()
                    if name.startswith("__pyobf_archive_") and name.endswith("(const")]
        selected = {row["function"] for row in rows}
        if not wrappers or any(name.removesuffix("(const") not in selected for name in wrappers):
            raise AssertionError("a generated per-record wrapper escaped CFF")
        binary = directory / "protected.exe"
        run([str(args.compiler), "-std=c++17", str(transformed), str(args.harness), *includes,
             "-lbcrypt", "-o", str(binary)])
        result = run([str(binary)])
        if "archive runtime verified" not in result.stdout:
            raise AssertionError("protected archive did not complete the runtime suite")
        rejected = run([str(binary), "fail"], succeeds=False)
        if "DATA-CONSUMED" in rejected.stdout:
            raise AssertionError("protected require continued into the data consumer")
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(binary), str(report)])


if __name__ == "__main__":
    main()
