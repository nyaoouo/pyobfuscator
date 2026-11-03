"""Verify original call profiles through actual framed CFF, O2 and linked execution."""

import argparse
from collections import Counter
import json
import re
import sys
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from frame_profile_cases import SOURCE, INTERNAL_TARGET, HARNESS


def call_profiles(text: str, name: str) -> list[str]:
    definitions = dict(re.findall(r"^!(\d+) = (.*)$", text, re.M))
    match = re.search(rf"^define [^\n]*@{re.escape(name)}\([^\n]*\).*?\{{(.*?)^\}}", text, re.M | re.S)
    if not match: raise AssertionError(f"missing profiled owner {name}")
    calls = re.finditer(r"^\s*(?:%[^=\n]+=\s*)?(?:(?:tail|musttail|notail)\s+)?(?:call|invoke)\s[^\n]*(?:\n\s+to label[^\n]*)?", match[1], re.M)
    return [definitions[tag].removeprefix("distinct ") for call in calls for tag in re.findall(r"!prof !(\d+)", call[0])]


def check_profiles(original: str, protected: str, rows: list[dict]) -> None:
    for owner in ("hybrid_phi", "normal_profile"):
        outer, inner = [], []
        for profile in call_profiles(original, owner):
            if '!"branch_weights"' in profile:
                outer.append(profile)
                if len(re.findall(r"\bi(?:32|64) -?\d+", profile)) == 1: inner.append(profile)
            else: inner.append(profile)
        helpers = [row["function"] for row in rows if row.get("generated_owner") == owner]
        if not helpers: raise AssertionError(f"missing framed profile owner {owner}")
        actual_inner = [profile for helper in helpers for profile in call_profiles(protected, helper)]
        if Counter(call_profiles(protected, owner)) != Counter(outer) or Counter(actual_inner) != Counter(inner):
            raise AssertionError(f"source profile changed owner or value: {owner}, {outer}, {inner}, {actual_inner}")
    if "!pyobf.frame." in protected: raise AssertionError("private frame artifacts leaked")


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, optimized, stamped, output, config, requests, report = (directory / name for name in
            ("source.ll", "optimized.ll", "stamped.ll", "output.ll", "recipe.json", "requests.json", "report.json"))
        harness = directory / "harness.cpp"
        harness.write_text(HARNESS, encoding="utf-8")
        if "extra=normal_profile" not in HARNESS: raise AssertionError("normal profile harness was not constructed")
        baseline, binary = directory / "baseline.exe", directory / "protected.exe"
        source.write_text(SOURCE, encoding="utf-8")
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        for external in (False, True):
            text = SOURCE if external else re.sub(r"\b(call|invoke) i32 @throw_or_return", r"\1 i32 @profile_target", SOURCE) + INTERNAL_TARGET
            source.write_text(text, encoding="utf-8")
            for o2 in (False, True):
                if o2: run([str(args.opt), "-passes=default<O2>", "-S", str(source), "-o", str(optimized)])
                else: optimized.write_text(text, encoding="utf-8")
                for composed in (False, True):
                    component = "external-calls" if external else "call-frames"
                    components = {component: "required"}
                    if composed:
                        components.update({"call-preparation": "required", "import-routes" if external else "reference-routes": "required"})
                    config.write_text(json.dumps({"schema_version": 1, "functions": {
                        "hybrid_phi": {"coverage": "hybrid-eh", "components": components},
                        "normal_profile": {"components": components}}}), encoding="utf-8")
                    run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
                        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
                        "-S", str(optimized), "-o", str(stamped)])
                    run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                        f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-input={requests}",
                        f"-pyobf-cff-report={report}", "-verify-each", "-S", str(stamped), "-o", str(output)])
                    rows = json.loads(report.read_text())["functions"]
                    if not o2 and any(len(call_profiles(stamped.read_text(), owner)) != 2
                                      for owner in ("hybrid_phi", "normal_profile")):
                        raise AssertionError("input call-profile inventory was not observed")
                    check_profiles(stamped.read_text(), output.read_text(), rows)
                    run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
                    if run([str(binary)]).stdout != expected: raise AssertionError("profiled frame behavior changed")
                    image, provider = directory / "protected.dll", directory / "provider.cpp"
                    provider.write_text('extern "C" { int cleanup_count=0; int throw_or_return(int x) {if(x<0)throw x;return x*3+1;} }', encoding="utf-8")
                    run([str(args.compiler), "-shared", str(output), str(provider), "-o", str(image)])
                    run([sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])


if __name__ == "__main__":
    main()
