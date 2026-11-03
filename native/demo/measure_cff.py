"""Build a same-IR baseline and record image-size, startup, and hot-call costs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
    if result.returncode:
        raise RuntimeError(f"measurement command failed: {command}\n{result.stderr}")
    return result.stdout


def text_size(objdump: Path, image: Path) -> int:
    sections = run([str(objdump), "-h", str(image)])
    match = re.search(r"^\s*\d+\s+\.text\s+([0-9a-fA-F]+)\b", sections,
                      re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing .text section in {image}")
    return int(match.group(1), 16)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "objdump", "input_ir", "protected_image",
                 "harness_source", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--binding-reference", type=Path)
    parser.add_argument("--binding-harness", type=Path)
    parser.add_argument("--baseline-source", type=Path, action="append", default=[])
    parser.add_argument("--include", type=Path, action="append", default=[])
    args = parser.parse_args()
    if bool(args.binding_reference) != bool(args.binding_harness):
        parser.error("bound payload measurements need both the reference and actual entry harness")
    if args.binding_reference:
        reference = json.loads(args.binding_reference.read_text(encoding="utf-8"))
        if reference.get("provider") != "owned-context-v1":
            parser.error("isolated payload measurement requires owned-context-v1; use the explicit full-release bootstrap measurement for the post profile")
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        directory = Path(temporary)
        baseline = directory / "baseline.dll"
        harness = directory / "measure.exe"
        run([str(args.compiler), "-shared", str(args.input_ir), *map(str, args.baseline_source),
             *(f"-I{path}" for path in args.include), "-o", str(baseline)])
        extra = []
        if args.binding_harness:
            harness = args.binding_harness
            material = directory / "measurement-only-source.bin"
            material.write_bytes(b"".join(word.to_bytes(4, "little") for word in
                [reference["routing_tag"], *reference["private_words"]]))
            extra = [str(material)]
        else:
            run([str(args.compiler), "-std=c++17", "-O2", str(args.harness_source), "-o", str(harness)])
        env = dict(os.environ)
        env["PATH"] = str(args.compiler.parent) + os.pathsep + env.get("PATH", "")
        output = run([str(harness), str(baseline.resolve()),
                      str(args.protected_image.resolve()), *extra], env=env)
        timings = {}
        for line in output.splitlines():
            name, value = line.split("=", 1)
            timings[name] = float(value)
        expected = {"baseline_startup_us", "protected_startup_us",
                    "baseline_hot_ns", "protected_hot_ns", "startup_samples",
                    "hot_samples", "hot_iterations"}
        if args.binding_reference: expected.add("protected_queries")
        if set(timings) != expected or min(timings.values()) <= 0:
            raise RuntimeError(f"incomplete timing output: {output}")
        image_sizes = {
            "baseline": {"file_bytes": baseline.stat().st_size,
                         "text_bytes": text_size(args.objdump, baseline)},
            "protected": {"file_bytes": args.protected_image.stat().st_size,
                          "text_bytes": text_size(args.objdump, args.protected_image)},
        }
        result = {
            "input_ir_sha256": digest(args.input_ir),
            "protected_image_sha256": digest(args.protected_image),
            "toolchain": str(args.compiler),
            "sizes": image_sizes,
            "timings": timings,
            "ratios": {
                "file": image_sizes["protected"]["file_bytes"] /
                        image_sizes["baseline"]["file_bytes"],
                "text": image_sizes["protected"]["text_bytes"] /
                        image_sizes["baseline"]["text_bytes"],
                "startup": timings["protected_startup_us"] /
                           timings["baseline_startup_us"],
                "hot_call": timings["protected_hot_ns"] /
                            timings["baseline_hot_ns"],
            },
        }
        if args.binding_reference:
            result.update({"private_reference_sha256": digest(args.binding_reference),
                "harness_sha256": digest(harness), "baseline_sha256": digest(baseline),
                "scope": "actual strict inner entry versus caller-supplied reference IR; whole image profile, "
                    "including any ordinary optimization difference as well as CFF/archive; "
                    "real CNG derived replies, owned host lease, lifecycle and publication/reset per call; "
                    "startup includes inner DLL load/context/one entry/cleanup; hot retains DLL/context; "
                    "excludes outer authentication/decryption/file release; not isolated query instruction cost"})
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")


if __name__ == "__main__":
    main()
