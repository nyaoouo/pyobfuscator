"""Check hybrid final-image identities, private inputs and real erased-shape failures."""

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from hybrid_final_cases import ERASURE_SOURCE, ERASURE_HARNESS


def check_final(path: Path, report: Path, image: Path) -> None:
    final = json.loads(path.read_text())
    if (final["image_sha256"] != hashlib.sha256(image.read_bytes()).hexdigest() or
            final["input_report_sha256"] != hashlib.sha256(report.read_bytes()).hexdigest() or
            final["verification_scope"] != "function-shape-and-component-presence"):
        raise AssertionError("hybrid final certificate is stale or overstates its scope")
    original = json.loads(report.read_text())["functions"]
    expected = {row["function"] for row in original if row["selected"]}
    selected = [row for row in final["functions"] if row["selected"]]
    if not selected or {row["function"] for row in selected} != expected:
        raise AssertionError("hybrid final selection is incomplete")
    for row in selected:
        eh = row["hybrid_eh"]
        if (row["status"] != "final-binary-verified" or row["transform_status"] != "transformed" or
                not row["final_binary_verified"] or row["decision_flow_verified"] or
                not row["coverage_kind"].startswith("hybrid-eh-") or eh["full_function_coverage"] or
                eh["transformed_exceptional_edges"] or not eh["ir_boundary_contract_verified"] or
                not eh["ir_flow_graph_verified"] or not eh["final_normal_dispatch_presence_verified"]):
            raise AssertionError("hybrid IR/final presence was lost or promoted to full exception equivalence")
    if any(row["final_binary_verified"] for row in final["functions"] if not row["selected"]):
        raise AssertionError("unselected hybrid support was credited")


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, report, config, final = (directory / name for name in
            ("source.ll", "protected.ll", "report.json", "recipe.json", "final.json"))
        original_image, protected_image, executable = (directory / name for name in
            ("original.dll", "protected.dll", "probe.exe"))
        fixture = Path(__file__).with_name("hybrid_eh_fixture.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        original = source.read_text()
        run([str(args.compiler), "-shared", str(source), "-o", str(original_image)])
        run([str(args.compiler), str(source), "-o", str(executable)])
        expected = run([str(executable)]).stdout

        def transform(names: tuple[str, ...], succeeds: bool = True) -> None:
            output.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            config.write_text(json.dumps({"schema_version": 1, "functions": {
                name: {"coverage": "hybrid-eh"} for name in names}}), encoding="utf-8")
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-pyobf-cff-seed=17",
                "-verify-each", "-S", str(source), "-o", str(output)], succeeds=succeeds)
            if not succeeds and (output.exists() or "private" not in result.stderr):
                raise AssertionError("private hybrid artifacts emitted output or missed their source gate")

        def reject(image: Path, input_report: Path, reason: str) -> None:
            absent = directory / "rejected.json"
            absent.unlink(missing_ok=True)
            result = run([sys.executable, str(args.linked_checker), str(args.objdump), str(image),
                str(input_report), "--output", str(absent)], succeeds=False)
            if absent.exists() or reason not in result.stderr:
                raise AssertionError(f"hybrid final failure produced a certificate or missed {reason}")

        names = ("hybrid_case", "hybrid_straight")
        transform(names)
        run([str(args.compiler), str(output), "-o", str(executable)])
        if run([str(executable)]).stdout != expected: raise AssertionError("protected final hybrid fixture changed behavior")
        run([str(args.compiler), "-shared", str(output), "-o", str(protected_image)])
        run([sys.executable, str(args.linked_checker), str(args.objdump), str(protected_image), str(report), "--output", str(final)])
        check_final(final, report, protected_image)
        for name in names:
            if f"<{name}>:" not in run([str(args.objdump), "-d", f"--disassemble-symbols={name}", str(original_image)]).stdout:
                raise AssertionError("wrong-image negative lost its same-named source symbol")
        reject(original_image, report, "lost the expected relative-tree shape")
        wrong = directory / "wrong-report.json"
        forged = json.loads(report.read_text())
        next(row for row in forged["functions"] if row["selected"])["function"] = "wrong_hybrid_owner"
        wrong.write_text(json.dumps(forged), encoding="utf-8")
        reject(protected_image, wrong, "absent from the linked DLL")

        next_id = max(map(int, re.findall(r"!(\d+)", original))) + 1
        for tag in ("pyobf.frame.helper", "pyobf.prep.bound", "pyobf.ref.table"):
            changed, count = re.subn(r"(?m)^(define [^\n]*@hybrid_case\([^\n]*) \{$",
                rf"\1 !{tag} !{next_id} {{", original, count=1)
            if count != 1: raise AssertionError("private hybrid header was not found")
            source.write_text(changed + f"\n!{next_id} = !{{}}\n", encoding="utf-8")
            run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
            transform(names, succeeds=False)

        source.write_text(ERASURE_SOURCE, encoding="utf-8")
        harness, erased = directory / "erasure.cpp", directory / "erased.ll"
        harness.write_text(ERASURE_HARNESS, encoding="utf-8")
        run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
        transform(("hybrid_erased",))
        for input_ir in (source, output):
            run([str(args.compiler), str(input_ir), str(harness), "-o", str(executable)])
            if run([str(executable)]).stdout != "ERASURE_OK\n": raise AssertionError("original/protected erasure fixture differs")
        run([str(args.compiler), "-shared", str(output), "-o", str(protected_image)])
        run([sys.executable, str(args.linked_checker), str(args.objdump), str(protected_image), str(report), "--output", str(final)])
        check_final(final, report, protected_image)
        run([str(args.opt), "-passes=default<O2>", "-S", str(output), "-o", str(erased)])
        run([str(args.compiler), str(erased), str(harness), "-o", str(executable)])
        if run([str(executable)]).stdout != "ERASURE_OK\n": raise AssertionError("post-CFF optimization changed source semantics")
        run([str(args.compiler), "-shared", str(erased), "-o", str(original_image)])
        reject(original_image, report, "lost the expected relative-tree shape")


if __name__ == "__main__":
    main()
