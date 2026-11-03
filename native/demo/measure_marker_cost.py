"""Isolate the O2 call-boundary cost of a Clang CFF source marker."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from measure_cff import run, text_size


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "objdump", "include_dir", "marker_source",
                 "harness_source", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        directory = Path(temporary)
        baseline = directory / "inline.dll"
        marked = directory / "noinline.dll"
        harness = directory / "measure.exe"
        common = [str(args.compiler), "-std=c++17", "-O2", "-shared",
                  "-I", str(args.include_dir), str(args.marker_source)]
        run([*common, "-o", str(baseline)])
        run([*common, "-DPYOBF_MEASURE_MARKED=1", "-o", str(marked)])
        run([str(args.compiler), "-std=c++17", "-O2", str(args.harness_source),
             "-o", str(harness)])
        env = dict(os.environ)
        env["PATH"] = str(args.compiler.parent) + os.pathsep + env.get("PATH", "")
        output = run([str(harness), str(baseline.resolve()), str(marked.resolve()),
                      "caller", "26"], env=env)
        timings = {}
        for line in output.splitlines():
            name, value = line.split("=", 1)
            timings[name] = float(value)
        if timings["baseline_hot_ns"] <= 0 or timings["protected_hot_ns"] <= 0:
            raise RuntimeError("marker timing output is invalid")
        result = {
            "scope": "O2 caller with inlined helper versus noinline/used source marker; no CFF",
            "timings": timings,
            "hot_call_ratio": timings["protected_hot_ns"] / timings["baseline_hot_ns"],
            "sizes": {
                "inline_text_bytes": text_size(args.objdump, baseline),
                "marked_text_bytes": text_size(args.objdump, marked),
            },
        }
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")


if __name__ == "__main__":
    main()
