"""Exercise explicit normal-flow CFF without changing C++ landingpad/unwind semantics."""

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import invalid_execution, run
from hybrid_eh_cases import FUNCLET, SOURCE as PHI_SOURCE, HARNESS as PHI_HARNESS
from hybrid_eh_cases import SWITCH_SOURCE, SWITCH_HARNESS


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, report, config = (directory / name for name in ("source.ll", "output.ll", "report.json", "recipe.json"))
        fixture = Path(__file__).with_name("hybrid_eh_fixture.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        original = source.read_text()
        if "invoke " not in original or "landingpad " not in original or "__gxx_personality_seh0" not in original:
            raise AssertionError("real C++ fixture lost its expected EH model")
        baseline, binary = directory / "baseline.exe", directory / "protected.exe"
        run([str(args.compiler), str(source), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        if "-2:998:17\n" not in expected or "4:18:21\n" not in expected:
            raise AssertionError("baseline did not exercise actual rethrow/cleanup effects")

        def transform(functions, *, seed=1, succeeds=True, strict=False, requests=None, region=None):
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            config.write_text(json.dumps({"schema_version": 1, "functions": functions}), encoding="utf-8")
            command = [str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                       f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", f"-pyobf-cff-seed={seed}",
                       "-verify-each", "-S", str(source), "-o", str(output)]
            if strict: command.append("-pyobf-cff-require-decision-flow")
            if requests: command.append(f"-pyobf-cff-requests-input={requests}")
            if region: command.append(f"-pyobf-cff-region={region}")
            result = run(command, succeeds=succeeds)
            if not succeeds and output.exists(): raise AssertionError("rejected hybrid request emitted output")
            return result

        selected = {name: {"coverage": "hybrid-eh"} for name in ("hybrid_case", "hybrid_straight")}
        for seed in (1, 17, 41):
            transform(selected, seed=seed)
            rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
            for name in selected:
                row = rows[name]
                if row["status"] != "transformed" or not row["coverage_kind"].startswith("hybrid-eh-"):
                    raise AssertionError(f"missing explicit hybrid scope: {row}")
                eh = row["hybrid_eh"]
                if (eh["full_function_coverage"] or eh["transformed_exceptional_edges"] or
                        not eh["ir_boundary_contract_verified"] or not eh["ir_flow_graph_verified"]):
                    raise AssertionError("preserved EH was credited as fully transformed")
                if not eh["preserved_exceptional_edges"] or not eh["landing_pads"]:
                    raise AssertionError("actual EH boundary inventory is missing")
            if rows["hybrid_straight"]["site_totals"]["real_decisions"]:
                raise AssertionError("invoke exceptional fork was counted as an original normal decision")
            run([str(args.compiler), str(output), "-o", str(binary)])
            if run([str(binary)]).stdout != expected: raise AssertionError("normal/catch/cleanup/rethrow/recursive result changed")
            image, final = directory / "protected.dll", directory / "final.json"
            run([str(args.compiler), "-shared", str(output), "-o", str(image)])
            run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report), "--output", str(final)])
            for row in json.loads(final.read_text())["functions"]:
                if row["selected"] and (not row["hybrid_eh"]["final_normal_dispatch_presence_verified"] or row["decision_flow_verified"]):
                    raise AssertionError("final hybrid presence was missing or promoted to ordinary full decision coverage")

        transform({"hybrid_case": {}}, succeeds=False)
        if "supports branches" not in report.read_text(): raise AssertionError("ordinary whole scope silently admitted EH")
        transform({"hybrid_straight": {"coverage": "hybrid-eh"}}, succeeds=False, strict=True)
        if "no original decision" not in report.read_text(): raise AssertionError("strict selection accepted EH fork as normal decision")
        for coverage in ("auto", 1):
            result = transform({"hybrid_case": {"coverage": coverage}}, succeeds=False)
            if "coverage must be whole or hybrid-eh" not in result.stderr: raise AssertionError("invalid scope accepted")
        transform({"hybrid_case": {"coverage": "hybrid-eh", "components": {"integer-literals": "optional"}}})
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_case")
        if next(item["applied"] for item in row["components"] if item["component"] == "integer-literals") < 1:
            raise AssertionError("former scalar refusal did not earn actual hybrid data coverage")
        run([str(args.compiler), str(output), "-o", str(binary)])
        if run([str(binary)]).stdout != expected: raise AssertionError("hybrid scalar follow-through changed reference semantics")
        transform({"hybrid_case": {"coverage": "hybrid-eh", "components": {"indexed-locals": "required"}}})
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_case")
        if next(item["applied"] for item in row["components"] if item["component"] == "indexed-locals") < 1:
            raise AssertionError("former local refusal did not earn actual hybrid object coverage")
        run([str(args.compiler), str(output), "-o", str(binary)])
        if run([str(binary)]).stdout != expected: raise AssertionError("hybrid locals changed C++ cleanup/rethrow behavior")
        result = transform({"hybrid_case": {"coverage": "hybrid-eh", "components": {"internal-calls": "optional"}}}, succeeds=False)
        if "does not support component 'internal-calls'" not in result.stderr:
            raise AssertionError("unverified hybrid component was enabled")
        source.write_text(original.replace("__gxx_personality_seh0", "unverified_personality"), encoding="utf-8")
        transform(selected, succeeds=False)
        if "landingpad personality" not in report.read_text(): raise AssertionError("unknown EH personality was admitted")
        source.write_text(original.replace("x86_64-w64-windows-gnu", "x86_64-unknown-linux-gnu"), encoding="utf-8")
        transform(selected, succeeds=False)
        if "target model is not verified" not in report.read_text(): raise AssertionError("unknown target was admitted")

        source.write_text(PHI_SOURCE, encoding="utf-8")
        harness = directory / "phi.cpp"
        harness.write_text(PHI_HARNESS, encoding="utf-8")
        run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected_phi = run([str(baseline)]).stdout
        for seed in (1, 17, 41):
            transform({"hybrid_phi": {"coverage": "hybrid-eh"}}, seed=seed)
            run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
            if run([str(binary)]).stdout != expected_phi:
                raise AssertionError("invoke-result or shared-pad PHI changed")
        # Clearing this seed's first armed correction breaks the fixture; other wrong values may share a leaf.
        protected = output.read_text()
        changed, count = re.subn(r"store i32 (-?\d+), ptr %pyobf\.eh\.correction",
                                lambda match: match[0].replace(match[1], "0", 1),
                                protected, count=1)
        if count != 1: raise AssertionError("armed unwind correction was not found")
        output.write_text(changed, encoding="utf-8")
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
        invalid_execution(binary, expected_phi)

        # Collection precedes ordinary O2; the same recipe consumes the retained provenance.
        requests, stamped, optimized = (directory / name for name in ("requests.json", "stamped.ll", "optimized.ll"))
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
             "-S", str(source), "-o", str(stamped)])
        run([str(args.opt), "-passes=default<O2>", "-S", str(stamped), "-o", str(optimized)])
        source.write_text(optimized.read_text(), encoding="utf-8")
        transform({"hybrid_phi": {"coverage": "hybrid-eh"}}, requests=requests)
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_phi")
        cfg = next(component for component in row["components"] if component["component"] == "cfg")
        if not cfg["requested"]: raise AssertionError("pre-optimization hybrid requests were lost")
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
        if run([str(binary)]).stdout != expected_phi: raise AssertionError("source O2 hybrid behavior changed")

        source.write_text(PHI_SOURCE, encoding="utf-8")
        transform({"hybrid_phi": {"coverage": "hybrid-eh", "budgets": {"max_body_blocks": 3}}}, succeeds=False)
        if "max_body_blocks" not in report.read_text(): raise AssertionError("hybrid body budget was ignored")
        result = transform({"hybrid_phi": {"coverage": "hybrid-eh"}}, succeeds=False, region="hybrid_phi:entry:join")
        if "conflicts with explicit regions" not in result.stderr: raise AssertionError("hybrid/region conflict accepted")
        bundled = PHI_SOURCE.replace("invoke i32 @throw_or_return(i32 %x)",
                                     'invoke i32 @throw_or_return(i32 %x) [ "deopt"(i32 7) ]')
        for text, reason in ((bundled, "operand bundles"), (FUNCLET, "unsized cross-block")):
            source.write_text(text, encoding="utf-8")
            run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
            transform({"hybrid_phi": {"coverage": "hybrid-eh"}}, succeeds=False)
            if reason not in report.read_text():
                failures = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"] if row["selected"]]
                raise AssertionError(f"EH rejection reason missed {reason}: {failures}")

        source.write_text(SWITCH_SOURCE, encoding="utf-8")
        harness.write_text(SWITCH_HARNESS, encoding="utf-8")
        if SWITCH_SOURCE.count("switch i32") != 2: raise AssertionError("hybrid switch fixture lost its actual switches")
        run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected_switch = run([str(baseline)]).stdout
        if len(expected_switch.splitlines()) != 63: raise AssertionError("hybrid switch/default/throw matrix was incomplete")
        for seed in (1, 17, 41):
            for prepared in (False, True):
                components = {name: "required" for name in
                    ("external-calls", "call-preparation", "import-routes")} if prepared else {}
                transform({"hybrid_switch": {"coverage": "hybrid-eh", "components": components}}, seed=seed)
                row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_switch")
                if (row["status"] != "transformed" or row["site_totals"]["real_decisions"] != 2 or
                        row["hybrid_eh"]["preserved_exceptional_edges"] != 2 or
                        not row["hybrid_eh"]["ir_flow_graph_verified"] or "switch i32" in output.read_text()):
                    raise AssertionError("hybrid switch lowering or final-flow proof was skipped")
                for name in components:
                    item = next(item for item in row["components"] if item["component"] == name)
                    if not item["applied"] or item["unsupported"]: raise AssertionError(f"hybrid switch lost {name}")
                run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
                if run([str(binary)]).stdout != expected_switch:
                    raise AssertionError(f"hybrid switch/invoke-result/shared-pad behavior changed: {seed}, {prepared}")
                if seed == 17:
                    image = directory / "switch.dll"
                    run([str(args.compiler), "-shared", str(output), str(harness), "-o", str(image)])
                    run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])


if __name__ == "__main__":
    main()
