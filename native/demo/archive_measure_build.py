"""Explicit timed compiler phases for a paired archive fixture, without runtime timing."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
import time


@dataclass
class BuiltVariant:
    image: Path
    phases: dict[str, float]
    report: dict | None
    plan: dict | None


def command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"archive measurement command failed: {arguments}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def build_variant(args, root: Path, source: Path, directory: Path, variant: str, optimization: str) -> BuiltVariant:
    directory.mkdir()
    phases = {}

    def timed(phase, arguments):
        started = time.perf_counter()
        output = command(list(map(str, arguments)))
        phases[phase] = phases.get(phase, 0) + time.perf_counter() - started
        return output

    protected = variant != "plain"
    archived = variant == "archive"
    config = directory / "recipe.json"
    # Common scalar protection isolates the additional archive cost. After O2,
    # folded FP/global values can become integers and use this same scalar path.
    config.write_text(json.dumps({"schema_version": 1, "functions": {
        name: {"components": {"integer-literals": "optional", "constant-archive": "optional" if archived else "off"}}
        for name in ("archive_compute", "archive_pointer")}}), encoding="utf-8")
    opt = [args.opt, f"-load-pass-plugin={args.plugin}", "-verify-each"]
    selection = [f"-pyobf-cff-config={config}", "-pyobf-cff-seed=731"]
    current = source
    requests = directory / "requests.json"
    if protected:
        current = directory / "requested.ll"
        timed("source_requests", [*opt, "-passes=pyobf-native-cff-requests", *selection,
            f"-pyobf-cff-requests-output={requests}", "-S", source, "-o", current])
    if optimization == "O2":
        optimized = directory / "optimized.ll"
        timed("ordinary_O2", [args.opt, "-passes=default<O2>", "-verify-each", "-S", current, "-o", optimized])
        current = optimized
    plan = None
    if archived:
        pending, plan_path = directory / "pending.ll", directory / "plan.json"
        timed("archive_plan", [*opt, "-passes=pyobf-native-archive-plan", *selection,
            f"-pyobf-archive-plan-output={plan_path}", "-S", current, "-o", pending])
        plan = json.loads(plan_path.read_bytes())
        package, generated, bindings = [directory / name for name in ("archive.bin", "archive.cpp", "bindings.json")]
        timed("pack", [sys.executable, root / "tools" / "pack_archive.py", plan_path, package, generated, bindings])
        runtime = [root / "src" / "archive" / name for name in ("format.cpp", "acquire.cpp", "require.cpp")]
        runtime += [root / "backends" / "windows_user" / "operations" / name
                    for name in ("memory.cpp", "crypto.cpp", "atomic.cpp", "archive_support.cpp")]
        units = []
        for index, unit in enumerate([*runtime, generated]):
            output = directory / f"runtime.{index}.ll"
            timed("helper_compile", [args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone",
                "-S", "-emit-llvm", "-I", root / "include", "-I", root / "src", unit, "-o", output])
            units.append(output)
        helper_ir = directory / "helpers.ll"
        timed("helper_link", [args.llvm_link, "-S", *units, "-o", helper_ir])
        helper_requested, helper_requests = directory / "helpers.requested.ll", directory / "helpers.requests.json"
        timed("helper_requests", [*opt, "-passes=pyobf-native-cff-requests",
            f"-pyobf-cff-requests-output={helper_requests}", "-S", helper_ir, "-o", helper_requested])
        merged = directory / "merged.requests.json"
        timed("merge_requests", [sys.executable, root / "tools" / "merge_requests.py", merged, requests, helper_requests])
        requests = merged
        linked = directory / "linked.ll"
        timed("pending_link", [args.llvm_link, "-S", pending, helper_requested, "-o", linked])
        current = directory / "prepared.ll"
        timed("materialize", [*opt, "-passes=pyobf-native-archive-materialize",
            f"-pyobf-archive-bindings={bindings}", "-S", linked, "-o", current])
    report = None
    if protected:
        transformed, coverage = directory / "protected.ll", directory / "coverage.json"
        timed("CFF", [*opt, "-passes=pyobf-native-cff", *selection,
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={coverage}", "-S", current, "-o", transformed])
        report = json.loads(coverage.read_bytes())
        current = transformed
    image = directory / "sample.dll"
    timed("native_link", [args.compiler, "-O0", "-fno-lto", "-shared", current,
        *(["-lbcrypt"] if archived else []), "-o", image])
    if protected:
        timed("final_gate", [sys.executable, root / "demo" / "check_linked_cff.py", args.objdump, image,
            directory / "coverage.json"])
    if archived:
        data = image.read_bytes()
        private = json.loads((directory / "bindings.json").read_bytes())
        if any(bytes.fromhex(row["key_hex"]) in data for row in private["records"]):
            raise AssertionError("measurement image retained a raw archive key")
    return BuiltVariant(image, phases, report, plan)
