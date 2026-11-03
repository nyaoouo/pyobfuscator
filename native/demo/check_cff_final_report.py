"""Validate the image-bound CFF result and its fail-closed negative case."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("final_report", "input_report", "image", "wrong_image",
                 "objdump", "checker", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--requests", type=Path)
    args = parser.parse_args()
    final = json.loads(args.final_report.read_text(encoding="utf-8"))
    original = json.loads(args.input_report.read_text(encoding="utf-8"))
    if (final["image_sha256"] != digest(args.image) or
            final["input_report_sha256"] != digest(args.input_report) or
            len(final["functions"]) != len(original["functions"])):
        raise AssertionError("final CFF report is stale or incomplete")
    selected = [row for row in final["functions"] if row["requested"]]
    expected = {row["function"] for row in original["functions"] if row["requested"]}
    if args.requests:
        expected = {row["function"] for row in json.loads(args.requests.read_bytes())["functions"] if row["defined"]}
    if ({row["function"] for row in selected} != expected or not selected or any(row["status"] != "final-binary-verified" or
                                  row["transform_status"] != "transformed" or
                                  not row["retained"] or not row["final_binary_verified"]
                                  for row in selected)):
        raise AssertionError("requested CFF symbols were not verified in the final image")
    kinds = {row["coverage_kind"] for row in selected}
    expected_kinds = {"decision-flow", "shape-only"}
    if "pyobf_demo_post_payload" in expected:
        expected_kinds.add("hybrid-eh-decision-flow")
        operation = next(row for row in selected if row["function"] == "pyobf_demo_post_payload")
        eh = operation["hybrid_eh"]
        if (operation["coverage_kind"] != "hybrid-eh-decision-flow" or eh["full_function_coverage"] or
                eh["transformed_exceptional_edges"] or not eh["ir_boundary_contract_verified"] or
                not eh["ir_flow_graph_verified"] or not eh["final_normal_dispatch_presence_verified"]):
            raise AssertionError("post operation lost its explicit partial EH ownership contract")
    if kinds != expected_kinds:
        raise AssertionError(f"CFF report collapsed meaningful and structural coverage: {kinds}")
    if any(row["decision_flow_verified"] != (row["coverage_kind"] == "decision-flow")
           for row in selected):
        raise AssertionError("shape-only CFF was counted as protected decision flow")
    if any(row["final_binary_verified"] for row in final["functions"] if not row["selected"]):
        raise AssertionError("unselected functions were marked verified")
    if any(row["selected"] and not row["requested"] and (not row.get("generated") or
            row.get("generated_owner") not in expected) for row in final["functions"]):
        raise AssertionError("implicit helper coverage lost its requested owner")

    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        absent = Path(temporary) / "should-not-exist.json"
        command = [sys.executable, str(args.checker), str(args.objdump), str(args.wrong_image),
                   str(args.input_report), "--output"]
        for output in (absent, Path(temporary) / "reused.json"):
            if output != absent: output.write_bytes(args.final_report.read_bytes())
            result = subprocess.run([*command, str(output)], capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or output.exists():
                raise AssertionError("wrong linked DLL kept or produced a verified CFF report")
        original = args.input_report.read_bytes()
        result = subprocess.run([*command, str(args.input_report)], capture_output=True,
                                text=True, timeout=20)
        if (result.returncode == 0 or args.input_report.read_bytes() != original or
                "final output aliases an input" not in result.stderr):
            raise AssertionError("linked CFF output alias damaged the input report")


if __name__ == "__main__":
    main()
