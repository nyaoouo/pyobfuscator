"""Execute bounded opaque/junk recipes, prove role accounting and reject erased features."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from check_cff_split import SOURCE_IR as SPLIT_SOURCE, HARNESS as SPLIT_HARNESS


SOURCE_IR = SPLIT_SOURCE + r'''
declare i32 @invoke_callback(ptr, i32)
define i32 @recursive(i32 %depth) {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 0
next:
  %n = sub i32 %depth, 1
  %prior = call i32 @recursive(i32 %n)
  %result = add i32 %prior, 1
  ret i32 %result
}
define i32 @callback_case(i32 %depth) {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 42
next:
  %n = sub i32 %depth, 1
  %prior = call i32 @invoke_callback(ptr @callback_case, i32 %n)
  %result = add i32 %prior, 1
  ret i32 %result
}
'''

HELPER = r'''
#include <cstdint>
extern "C" std::uint32_t invoke_callback(std::uint32_t (*callback)(std::uint32_t),
                                          std::uint32_t depth) {
    return callback(depth);
}
'''

HARNESS = ('''extern "C" unsigned recursive(unsigned);
extern "C" unsigned callback_case(unsigned);
''' + SPLIT_HARNESS).replace(
    "if (counter != 1000) return 2;",
    "if (counter != 1000) return 2;\n"
    "    for(unsigned n=0;n<32;++n) if(recursive(n)!=n || callback_case(n)!=n+42) return 3;"
)


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result: {command}\n{result.stdout}\n{result.stderr}")
    return result


def invalid_execution(binary: Path, expected: str) -> None:
    try:
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired:
        return
    if result.returncode == 0 and result.stdout == expected:
        raise AssertionError("altered transition correction still produced valid fixture behavior")


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        output = directory / "protected.ll"
        config_file = directory / "recipe.json"
        report = directory / "coverage.json"
        helper = directory / "helper.cpp"
        harness = directory / "harness.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        helper.write_text(HELPER, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), str(helper), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        selected = ("heavy", "tail", "tiny", "recursive", "callback_case")

        def transform(features: tuple[str, ...], seed: int, *, deep: bool = False,
                      cap: int = 2, succeeds: bool = True, rounds: int = 3):
            config = {"schema_version": 1, "functions": {
                name: {"components": {feature: "required" for feature in features},
                       "budgets": {"max_opaque_sites": cap, "max_junk_sites": cap, "junk_rounds": rounds}}
                for name in selected}}
            if deep:
                config["functions"]["heavy"]["recipe"] = "deep"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            output.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                          f"-pyobf-cff-config={config_file}", f"-pyobf-cff-report={report}",
                          f"-pyobf-cff-seed={seed}", "-verify-each", "-S", str(source), "-o", str(output)],
                         succeeds=succeeds)
            if not succeeds:
                if output.exists(): raise AssertionError("invalid transition budget emitted an artifact")
                return result
            rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
            for name in selected:
                row = rows[name]
                if row["status"] != "transformed": raise AssertionError(f"missing depth recipe: {name}")
                for component in row["components"]:
                    if component["component"] in features:
                        if not 1 <= component["applied"] <= cap:
                            raise AssertionError(f"transition cap/coverage differs: {component}")
                        if sum(component["applied_roles"].values()) != component["applied"]:
                            raise AssertionError("applied transition site roles do not reconcile")
                totals = row["site_totals"]
                if totals["decoy_blocks"] or sum(totals["transition_roles"].values()) != totals["transition_sites"]:
                    raise AssertionError("opaque/junk code was misreported as fake blocks or real edges")
            tiny = rows["tiny"]
            if (tiny["coverage_kind"] != "shape-only" or tiny["site_totals"]["normalized_decisions"] or
                    tiny["site_totals"]["body_roles"] != {"real": 1, "shape": 2}):
                raise AssertionError("generated shape protection was credited as real decision coverage")
            for feature in features:
                component = next(item for item in tiny["components"] if item["component"] == feature)
                if component["applied_roles"] != {"shape": component["applied"]}:
                    raise AssertionError("shape transition protection lost its role")
            if rows["heavy"]["site_totals"]["body_roles"].get("routing", 0) == 0:
                raise AssertionError("lowered switch helpers have no routing origin")
            return rows

        for index, (features, seed) in enumerate(((('opaque-choices',), 1), (('reachable-junk',), 1),
                (('opaque-choices', 'reachable-junk'), 1), (('opaque-choices', 'reachable-junk'), 19),
                (('opaque-choices', 'reachable-junk'), 777))):
            transform(features, seed, deep=seed == 777)
            binary = directory / f"protected-{index}.exe"
            run([str(args.compiler), str(output), str(helper), str(harness), "-o", str(binary)])
            if run([str(binary)]).stdout != expected:
                raise AssertionError("opaque/junk execution differs on memory/loop/recursive/callback cases")
            image = directory / f"protected-{index}.dll"
            run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(image)])
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])

        transform(("opaque-choices", "reachable-junk"), 1)
        ir = output.read_text(encoding="utf-8")
        body = re.search(r"define i32 @heavy\(.*?\n\}", ir, re.S)
        if body is None: raise AssertionError("heavy function is missing")
        def perturb_state(match: re.Match[str]) -> str:
            observed = match[1].replace("pyobf.junk.state", "pyobf.test.state")
            return f"{observed} = {match[2]}\n  {match[1]} = xor i32 {observed}, 1"

        changed, count = re.subn(
            r"(%pyobf\.junk\.state(?:\.?\d+)?) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
            perturb_state, body.group())
        if count == 0: raise AssertionError("reachable work does not consume live state")
        altered = directory / "altered.ll"
        altered.write_text(ir[:body.start()] + changed + ir[body.end():], encoding="utf-8")
        binary = directory / "altered.exe"
        run([str(args.compiler), str(altered), str(helper), str(harness), "-o", str(binary)])
        invalid_execution(binary, expected)

        # A valid CFG-only image must fail if paired with a report claiming these features.
        claimed = directory / "claimed.json"
        claimed.write_text(report.read_text(), encoding="utf-8")
        transform((), 1)
        absent = directory / "absent.dll"
        run([str(args.compiler), "-shared", str(output), str(helper), "-o", str(absent)])
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(absent), str(claimed)],
                     succeeds=False)
        if "lost opaque transition products" not in result.stderr:
            raise AssertionError(f"feature-removal gate failed for another reason: {result.stderr}")
        transform(("reachable-junk",), 1)
        claimed.write_text(report.read_text(), encoding="utf-8")
        result = run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(absent), str(claimed)],
                     succeeds=False)
        if "lost reachable junk coefficients" not in result.stderr:
            raise AssertionError(f"junk feature-removal gate failed for another reason: {result.stderr}")
        transform(("opaque-choices", "reachable-junk"), 1, cap=1)
        result = transform(("reachable-junk",), 1, rounds=9, succeeds=False)
        if "junk_rounds" not in result.stderr: raise AssertionError("junk round cap is unenforced")


if __name__ == "__main__":
    main()
