"""Opt-in O0 baseline and region-CFF size/call-cost measurement."""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import tempfile
from pathlib import Path

from check_cff_region import SOURCE, run


HARNESS = """
#include <chrono>
#include <cstdio>
extern "C" int region_case(int);
int main() {
    volatile int sink = 0;
    constexpr int iterations = 10000000;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sink = sink + region_case(i % 31 - 15);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    std::printf("%.3f\\n", std::chrono::duration<double, std::nano>(elapsed).count() / iterations);
    return sink == 0x12345678;
}
"""


def measure(objdump: Path, executable: Path) -> dict[str, float | int]:
    samples = [float(run([str(executable)]).stdout.strip()) for _ in range(5)]
    sections = run([str(objdump), "-h", str(executable)]).stdout
    text = re.search(r"(?m)^\s*\d+\s+\.text\s+([0-9a-fA-F]+)\b", sections)
    if text is None:
        raise AssertionError("linked image lacks a .text section")
    code = run([str(objdump), "-d", "--disassemble-symbols=region_case",
                str(executable)]).stdout
    instructions = len(re.findall(r"(?m)^\s*[0-9a-fA-F]+:\s", code))
    if instructions == 0:
        raise AssertionError("linked image lacks region_case")
    return {
        "median_ns_per_call": statistics.median(samples),
        "text_bytes": int(text.group(1), 16),
        "function_instructions": instructions,
        "image_bytes": executable.stat().st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("compiler", type=Path)
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("objdump", type=Path)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ["PATH"]
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        folder = Path(temporary)
        source = folder / "region.ll"
        transformed = folder / "region.cff.ll"
        harness = folder / "harness.cpp"
        source.write_text(SOURCE, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-markers=false",
             "-pyobf-cff-region=region_case:region.start:out",
             "-verify-each", "-S", str(source), "-o", str(transformed)])
        results = {}
        for label, ir in (("plain", source), ("region", transformed)):
            object_file = folder / f"{label}.obj"
            executable = folder / f"{label}.exe"
            run([str(args.compiler), "-O0", "-c", str(ir), "-o", str(object_file)])
            run([str(args.compiler), "-O2", str(harness), str(object_file),
                 "-o", str(executable)])
            results[label] = measure(args.objdump, executable)
        results["ratio"] = {
            key: round(results["region"][key] / results["plain"][key], 3)
            for key in ("median_ns_per_call", "text_bytes", "function_instructions",
                        "image_bytes")
        }
        args.output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print(args.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
