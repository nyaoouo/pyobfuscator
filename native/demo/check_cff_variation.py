"""Check seed-specific state layouts and encoded transitions in selected functions."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


FUNCTIONS = ("pyobf_demo_compute", "pyobf_native_inner_entry")


def function_body(ir: str, name: str) -> str:
    return re.search(r"(?ms)^define [^\n]*@" + re.escape(name) + r"\(.*?^}", ir)[0]


def body_order(function: str) -> tuple[str, ...]:
    before_dispatch = function[:function.index("pyobf.dispatch:")]
    return tuple(re.findall(r"^([\w.]+):", before_dispatch, re.MULTILINE))


def dispatch_shape(function: str) -> str:
    blocks = {}
    labels = list(re.finditer(r"^([\w.]+):", function, re.MULTILINE))
    for index, label in enumerate(labels):
        end = labels[index + 1].start() if index + 1 < len(labels) else len(function)
        blocks[label.group(1)] = function[label.end():end]

    def visit(name: str) -> str:
        if name.startswith("pyobf.leaf"):
            return "L"
        branch = re.search(r"br i1 .* label %([\w.]+), label %([\w.]+)", blocks[name])
        if branch is None:
            raise AssertionError(f"missing CFF comparison branch in {name}")
        return f"({visit(branch.group(1))}{visit(branch.group(2))})"

    return visit("pyobf.compare")


def transformed(opt: Path, plugin: Path, source: Path, directory: Path,
                seed: int, functions=FUNCTIONS, extra=()) -> str:
    output = directory / f"seed-{seed}.ll"
    report = directory / f"seed-{seed}.json"
    process = subprocess.run(
        [str(opt), "-load-pass-plugin", str(plugin), "-passes=pyobf-native-cff",
         "-pyobf-cff-functions=" + ",".join(functions),
         f"-pyobf-cff-seed={seed}", f"-pyobf-cff-report={report}",
         *extra, "-S", str(source), "-o", str(output)],
        capture_output=True, text=True, timeout=15,
    )
    if process.returncode:
        raise AssertionError(f"CFF failed for seed {seed}: {process.stderr}")
    rows = {row["function"]: row for row in
            json.loads(report.read_text(encoding="utf-8"))["functions"]}
    if any(rows[name]["status"] != "transformed" for name in functions):
        raise AssertionError(f"CFF coverage incomplete for seed {seed}")
    return output.read_text(encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("input_ir", type=Path)
    parser.add_argument("--strict-payload", action="store_true")
    parser.add_argument("--post-input", nargs=2, type=Path, metavar=("RECIPE", "PRIVATE"))
    args = parser.parse_args()
    functions = ("pyobf_demo_bound_compute", "pyobf_native_inner_entry") if args.strict_payload else FUNCTIONS
    extra = ([f"-pyobf-cff-config={args.post_input[0]}",
        f"-pyobf-cff-contribution-input={args.post_input[1]}"] if args.post_input else [])
    with tempfile.TemporaryDirectory(dir=args.input_ir.parent) as temporary:
        directory = Path(temporary)
        first = transformed(args.opt, args.plugin, args.input_ir, directory, 1031, functions, extra)
        second = transformed(args.opt, args.plugin, args.input_ir, directory, 2099, functions, extra)
        layouts = [first, second]
        for seed in (3137, 4261, 5419, 6553):
            layouts.append(transformed(args.opt, args.plugin, args.input_ir,
                                       directory, seed, functions, extra))
        for name in functions:
            first_body = function_body(first, name)
            second_body = function_body(second, name)
            initial_pattern = r"store i32 (-?\d+), ptr %pyobf\.state"
            initial_first = re.search(initial_pattern, first_body)
            initial_second = re.search(initial_pattern, second_body)
            if not initial_first or not initial_second or initial_first.group(1) == initial_second.group(1):
                raise AssertionError(f"{name} did not vary its initial state across seeds")
            for body in (first_body, second_body):
                dispatcher = body[body.index("pyobf.dispatch:"):]
                pivots = re.findall(r"icmp uge i32 [^,]+, (-?\d+)", dispatcher)
                if len(pivots) < 2 or "icmp eq i32" in dispatcher:
                    raise AssertionError(f"{name} lost its comparison-tree dispatcher")
                if body.count("mul i32") < 2 or "xor i32" not in body:
                    raise AssertionError(f"{name} exposed plain relative transitions")
            if first_body == second_body:
                raise AssertionError(f"{name} generated identical IR across seeds")
            if name == functions[0]:
                bodies = [function_body(ir, name) for ir in layouts]
                if len({body_order(body) for body in bodies}) < 2:
                    raise AssertionError("CFF body layout did not vary across seeds")
                if len({dispatch_shape(body) for body in bodies}) < 2:
                    raise AssertionError("CFF comparison-tree topology did not vary")


if __name__ == "__main__":
    main()
