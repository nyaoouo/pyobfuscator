"""Keep required local frame ABIs across source O2 without masking lost-source gates."""

import argparse
import json
from pathlib import Path
import re
import tempfile

from check_cff_transition_depth import run
from frame_abi_retention_cases import HARNESS, SOURCE


def compiler_roots(text: str) -> list[str]:
    line = next(line for line in text.splitlines() if line.startswith("@llvm.compiler.used ="))
    return re.findall(r"ptr @(\w+)", line)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, stamped, optimized, output, config, requests, report, harness, binary = (
            directory / name for name in ("source.ll", "stamped.ll", "optimized.ll", "output.ll",
                "recipe.json", "requests.json", "report.json", "harness.cpp", "probe.exe"))
        source.write_text(SOURCE, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.compiler), str(source), str(harness), "-o", str(binary)])
        if run([str(binary)]).stdout != "ABI_RETENTION_OK\n": raise AssertionError("invalid source ABI fixture")
        for enabled in (False, True):
            config.write_text(json.dumps({"schema_version": 1, "functions": {"abi_owner": {
                "coverage": "whole" if enabled else "hybrid-eh",
                "components": {"constant-archive": "required" if enabled else "off"}}}}), encoding="utf-8")
            plan, pending = directory / "archive.json", directory / "pending.ll"
            plan.unlink(missing_ok=True)
            pending.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}",
                "-passes=pyobf-native-archive-plan", f"-pyobf-archive-plan-output={plan}",
                "-verify-each", "-S", str(source), "-o", str(pending)], succeeds=not enabled)
            if enabled:
                if plan.exists() or pending.exists() or "native archive source:" not in result.stderr:
                    raise AssertionError("unsupported EH archive source bypassed admission")
            elif json.loads(plan.read_text())["records"]:
                raise AssertionError("archive-disabled hybrid source was collected")
        for frame, preparation in (("optional", "off"), ("required", "off"), ("optional", "required")):
            required = frame == "required" or preparation == "required"
            config.write_text(json.dumps({"schema_version": 1, "functions": {"abi_owner": {
                "coverage": "hybrid-eh", "components": {"call-frames": frame,
                "call-preparation": preparation}}}}), encoding="utf-8")
            selection = [f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}"]
            run([str(args.opt), *selection, "-passes=pyobf-native-cff-requests",
                f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", str(source), "-o", str(stamped)])
            roots = compiler_roots(stamped.read_text())
            if roots != (["unrelated", "abi_leaf"] if required else ["unrelated"]):
                raise AssertionError(f"source retention changed unrelated/optional roots: {roots}")
            again = directory / "again.ll"
            run([str(args.opt), *selection, "-passes=pyobf-native-cff-requests",
                f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", str(stamped), "-o", str(again)])
            if compiler_roots(again.read_text()) != roots: raise AssertionError("recollection duplicated compiler roots")
            run([str(args.opt), "-passes=default<O2>", "-verify-each", "-S", str(stamped), "-o", str(optimized)])
            changed = optimized.read_text()
            i32_target = re.search(r"^define internal [^\n]*i32 @abi_leaf\(", changed, re.M) is not None
            if i32_target != required: raise AssertionError("fixture did not exercise required ABI retention")
            run([str(args.opt), *selection, "-passes=pyobf-native-cff",
                f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={report}",
                "-verify-each", "-S", str(optimized), "-o", str(output)])
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "abi_owner")
            item = next(item for item in row["components"] if item["component"] == "call-frames")
            if row["status"] != "transformed" or not item["applied"]:
                raise AssertionError("retained/optional frame was not actually generated")
            if bool(item["optimized_away"]) == required: raise AssertionError("original source loss was misreported")
            run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
            if run([str(binary)]).stdout != "ABI_RETENTION_OK\n": raise AssertionError("framed result or unwind ABI changed")


if __name__ == "__main__":
    main()
