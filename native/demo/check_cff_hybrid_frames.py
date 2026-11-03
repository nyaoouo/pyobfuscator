"""Compose typed internal/external frames and preparation with actual C++ EH scopes."""

import argparse
import json
import os
import tempfile
from pathlib import Path

from check_cff_transition_depth import run
from hybrid_eh_cases import SOURCE as PHI_SOURCE, HARNESS as PHI_HARNESS


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, config, report = (directory / name for name in ("source.ll", "output.ll", "recipe.json", "report.json"))
        baseline, binary = directory / "baseline.exe", directory / "protected.exe"
        fixture = Path(__file__).with_name("hybrid_eh_fixture.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        run([str(args.compiler), str(source), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        for seed in (1, 17):
            for modes in (("call-frames",), ("external-calls",), ("call-frames", "external-calls"), ()):
                for prepared, routed in ((False, False), (True, False), (False, True), (True, True)):
                    if not modes and (not routed or prepared): continue
                    components = {name: "required" for name in modes}
                    if prepared: components["call-preparation"] = "required"
                    if routed: components.update({"reference-routes": "required", "import-routes": "required"})
                    selected = {"hybrid_case": {"coverage": "hybrid-eh", "components": components}}
                    config.write_text(json.dumps({"schema_version": 1, "functions": selected}), encoding="utf-8")
                    run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                        f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", f"-pyobf-cff-seed={seed}",
                        "-verify-each", "-S", str(source), "-o", str(output)])
                    row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_case")
                    for name in components:
                        item = next(item for item in row["components"] if item["component"] == name)
                        if not item["applied"] or item["unsupported"]:
                            raise AssertionError(f"hybrid component was lost: {seed}, {modes}, {prepared}, {item}")
                    if modes and "pyobf.frame.complete" not in output.read_text():
                        raise AssertionError("normal-only frame completion is missing")
                    run([str(args.compiler), str(output), "-o", str(binary)])
                    if run([str(binary)]).stdout != expected:
                        raise AssertionError(f"framed catch/cleanup/rethrow/recursion changed: {seed}, {modes}, {prepared}")
                    if seed == 17:
                        image = directory / "protected.dll"
                        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
                        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])

        # Actual frontend aggregate ABI includes caller-owned sret storage and a packed small result.
        fixture = Path(__file__).with_name("hybrid_frame_abi.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        if "sret(" not in source.read_text(): raise AssertionError("aggregate fixture lost actual sret ABI")
        abi_original = source.read_text()
        run([str(args.compiler), str(source), "-o", str(baseline)])
        expected_abi = run([str(baseline)]).stdout
        for prepared in (False, True):
            components = {"call-frames": "required", "external-calls": "required"}
            if prepared: components["call-preparation"] = "required"
            components.update({"reference-routes": "required", "import-routes": "required"})
            config.write_text(json.dumps({"schema_version": 1, "functions": {
                "hybrid_abi": {"coverage": "hybrid-eh", "components": components}}}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)])
            run([str(args.compiler), str(output), "-o", str(binary)])
            if run([str(binary)]).stdout != expected_abi: raise AssertionError("framed aggregate ABI or cleanup changed")

        source.write_text(PHI_SOURCE, encoding="utf-8")
        harness = directory / "harness.cpp"
        harness.write_text(PHI_HARNESS, encoding="utf-8")
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        for prepared in (False, True):
            components = {"external-calls": "required"}
            if prepared: components["call-preparation"] = "required"
            config.write_text(json.dumps({"schema_version": 1, "functions": {
                "hybrid_phi": {"coverage": "hybrid-eh", "components": components}}}), encoding="utf-8")
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)])
            run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
            if run([str(binary)]).stdout != expected: raise AssertionError("framed invoke-result/shared-pad PHI changed")

        source.write_text(abi_original, encoding="utf-8")
        components = {name: "required" for name in ("call-frames", "external-calls", "call-preparation",
                                                     "reference-routes", "import-routes")}
        config.write_text(json.dumps({"schema_version": 1, "functions": {
            "hybrid_abi": {"coverage": "hybrid-eh", "components": components}}}), encoding="utf-8")
        requests, stamped, optimized, private = (directory / name for name in
            ("requests.json", "stamped.ll", "optimized.ll", "private.json"))
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-output={requests}",
             "-S", str(source), "-o", str(stamped)])
        run([str(args.opt), "-passes=default<O2>", "-S", str(stamped), "-o", str(optimized)])
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
             f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-input={requests}",
             f"-pyobf-cff-private-map={private}", f"-pyobf-cff-report={report}", "-verify-each",
             "-S", str(optimized), "-o", str(output)])
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "hybrid_abi")
        for name in components:
            item = next(item for item in row["components"] if item["component"] == name)
            if not item["requested"] or not item["applied"]:
                raise AssertionError(f"hybrid pre-O2 request handoff lost {name}")
        run([str(args.compiler), str(output), "-o", str(binary)])
        if run([str(binary)]).stdout != expected_abi: raise AssertionError("optimized framed aggregate behavior changed")


if __name__ == "__main__":
    main()
