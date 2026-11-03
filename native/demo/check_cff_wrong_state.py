"""Exercise one bounded wrong-state path without claiming universal invalid-state safety."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


FIXTURE = r"""
#include <cstdio>

extern "C" int guarded_value(int input) {
    int result = 0;
    if (input == 7) {
        result = 0x5a17;
    } else if (input < 0) {
        result = 23;
    } else {
        result = 3;
    }
    return result;
}

int main() {
    if (guarded_value(7) == 0x5a17) {
        std::puts("SENSITIVE_RESULT");
        return 0;
    }
    return 7;
}
"""


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if process.returncode:
        raise AssertionError(f"command failed: {command}\n{process.stderr}")
    return process


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("compiler", type=Path)
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "fixture.cpp"
        original_ir = directory / "fixture.ll"
        protected_ir = directory / "protected.ll"
        wrong_ir = directory / "wrong.ll"
        good_exe = directory / "good.exe"
        wrong_exe = directory / "wrong.exe"
        source.write_text(FIXTURE, encoding="utf-8")
        run([str(args.compiler), "-std=c++17", "-O0", "-S", "-emit-llvm",
             "-Xclang", "-disable-O0-optnone", str(source), "-o", str(original_ir)])
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=guarded_value",
             "-pyobf-cff-seed=1031", "-S", str(original_ir), "-o", str(protected_ir)])
        text = protected_ir.read_text(encoding="utf-8")
        function_start = text.index("@guarded_value(")
        function_end = text.index("\n}", function_start)
        function = text[function_start:function_end]
        initial = re.search(r"store i32 (-?\d+), ptr %pyobf\.state", function)
        if initial is None:
            raise AssertionError("CFF initial state was not found")
        wrong_state = (int(initial.group(1)) + 1 + (1 << 31)) % (1 << 32) - (1 << 31)
        mutated = function[:initial.start(1)] + str(wrong_state) + function[initial.end(1):]
        wrong_ir.write_text(text[:function_start] + mutated + text[function_end:], encoding="utf-8")
        run([str(args.compiler), "-x", "ir", str(protected_ir), "-o", str(good_exe)])
        run([str(args.compiler), "-x", "ir", str(wrong_ir), "-o", str(wrong_exe)])
        good = run([str(good_exe)])
        if good.stdout.strip() != "SENSITIVE_RESULT":
            raise AssertionError("valid state did not release the expected result")
        try:
            wrong = subprocess.run([str(wrong_exe)], capture_output=True, text=True, timeout=2)
        except subprocess.TimeoutExpired:
            return
        if "SENSITIVE_RESULT" in wrong.stdout:
            raise AssertionError("wrong state released the protected result")


if __name__ == "__main__":
    main()
