"""Exercise composed recipes, strict site coverage, provenance and dependency preflight."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = r'''
@.marker = private constant [17 x i8] c"pyobf.native.cff\00"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr } { ptr @choose, ptr @.marker, ptr null, i32 1, ptr null }],
  section "llvm.metadata"
define i32 @helper(i32 %x) {
private_helper_block:
  %y = add i32 %x, 37
  ret i32 %y
}
define i32 @choose(i32 %x) {
private_original_entry:
  %zero = icmp eq i32 %x, 0
  br i1 %zero, label %private_yes, label %private_no
private_yes:
  %y = call i32 @helper(i32 %x)
  ret i32 %y
private_no:
  %z = add i32 %x, 61
  ret i32 %z
}
define i32 @other(i32 %x) {
private_other_block:
  %y = add i32 %x, 5
  ret i32 %y
}
define i32 @empty(i32 %x) {
entry:
  ret i32 %x
}
define i256 @unsupported_width(i256 %x) {
entry:
  %y = add i256 %x, 123456789012345
  ret i256 %y
}
'''

HARNESS = r'''
extern "C" int choose(int);
extern "C" int other(int);
int main() {
    for (int x = -100; x <= 100; ++x) {
        if (choose(x) != (x == 0 ? 37 : x + 61) || other(x) != x + 5) return 1;
    }
    return 0;
}
'''


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result: {command}\n{result.stdout}\n{result.stderr}")
    return result


def rows(report: Path) -> dict[str, dict]:
    return {row["function"]: row for row in json.loads(report.read_text(encoding="utf-8"))["functions"]}


def components(row: dict) -> dict[str, dict]:
    return {item["component"]: item for item in row["components"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        source.write_text(SOURCE_IR, encoding="utf-8")
        config_file = directory / "recipe.json"
        report = directory / "coverage.json"
        output = directory / "protected.ll"
        private = directory / "private.json"
        command = [str(args.opt), f"-load-pass-plugin={args.plugin}",
                   "-passes=pyobf-native-cff", f"-pyobf-cff-config={config_file}",
                   f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source),
                   "-o", str(output)]

        def transform(config: dict, *, succeeds: bool = True, extra: list[str] | None = None):
            config_file.write_text(json.dumps(config), encoding="utf-8")
            report.unlink(missing_ok=True)
            output.unlink(missing_ok=True)
            result = run(command + (extra or []), succeeds=succeeds)
            if not succeeds and output.exists():
                raise AssertionError("rejected recipe emitted a transformed artifact")
            return result

        config = {
            "schema_version": 1,
            "domain": "inner",
            "defaults": {"recipe": "deep"},
            "markers": {"pyobf.native.cff": {"recipe": "baseline"}},
            "functions": {
                "choose": {"components": {"integer-literals": "required",
                                           "internal-calls": "required"}},
                "other": {"recipe": "baseline"},
            },
            "build_domains": [{"id": "inner", "requires": ["assets"]}, {"id": "assets"}],
            "runtime_services": [
                {"id": "root", "ready_at": "L0", "first_use": "L0"},
                {"id": "support", "ready_at": "L1", "first_use": "L1", "requires": ["root"]},
                {"id": "handoff", "ready_at": "L2", "first_use": "L2", "requires": ["support"],
                 "protects_first_release": True},
                {"id": "app", "ready_at": "L4", "first_use": "L4", "requires": ["handoff"],
                 "application_domain": True},
            ],
        }
        transform(config, extra=[f"-pyobf-cff-private-map={private}"])
        selected = rows(report)
        chosen = selected["choose"]
        effective = chosen["effective_recipe"]
        if effective["name"] != "baseline" or selected["helper"]["selected"]:
            raise AssertionError("override precedence or explicit selection changed")
        applied = components(chosen)
        if (applied["integer-literals"]["applied"] < 2 or
                applied["internal-calls"]["applied"] != 1 or
                applied["decoy-transitions"]["status"] != "disabled" or
                chosen["site_totals"]["real_decisions"] != 1 or
                chosen["site_totals"]["decoy_blocks"] != 0):
            raise AssertionError(f"composed component evidence is incorrect: {chosen}")
        if (selected["other"]["coverage_kind"] != "shape-only" or
                selected["other"]["site_totals"]["shape_padding"] < 1):
            raise AssertionError("shape padding was credited as original decisions")
        public_text = report.read_text(encoding="utf-8")
        if "private_original_entry" in public_text or "123456789012345" in public_text:
            raise AssertionError("public coverage leaked private provenance or literal contents")
        if "private_original_entry" not in private.read_text(encoding="utf-8"):
            raise AssertionError("opt-in source map omitted original block provenance")
        private_rows = json.loads(private.read_text(encoding="utf-8"))["functions"]
        chosen_map = next(row for row in private_rows if row["function"] == "choose")
        if not chosen_map["sites"] or any(not site["transformed_ir"] for site in chosen_map["sites"]):
            raise AssertionError("private map lost a transformed IR consumption site")
        summary = json.loads(public_text)
        contract = summary["dependency_contract"]
        if (contract["build_domain_order"] != ["assets", "inner"] or
                contract["runtime_readiness_proven"] is not False):
            raise AssertionError("declaration checks were confused with runtime evidence")
        seeds = {item["component"]: item["seed"] for item in effective["components"]}
        if len(set(seeds.values())) != len(seeds):
            raise AssertionError("component seeds have no independent domains")
        first_ir = output.read_text(encoding="utf-8")
        transform(config)
        if output.read_text(encoding="utf-8") != first_ir:
            raise AssertionError("fixed recipe/seed did not reproduce the transformed IR")
        transform(config, extra=["-pyobf-cff-seed=929"])
        if output.read_text(encoding="utf-8") == first_ir:
            raise AssertionError("build seed did not diversify component output")
        transform(config)

        harness = directory / "harness.cpp"
        harness.write_text(HARNESS, encoding="utf-8")
        for name, ir in (("baseline", source), ("protected", output)):
            binary = directory / f"{name}.exe"
            run([str(args.compiler), str(ir), str(harness), "-o", str(binary)])
            run([str(binary)])
        image = directory / "protected.dll"
        final = directory / "final.json"
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image),
             str(report), "--output", str(final)])
        verified = rows(final)["choose"]["components"]
        if not all(row["final_presence_verified"] for row in verified if row["applied"]):
            raise AssertionError("linked checker omitted actual component presence")
        erased_literal = directory / "erased_literal.ll"
        protected_text = output.read_text(encoding="utf-8")
        if "-2048144789" not in protected_text:
            raise AssertionError("literal feature fixture lacks its runtime mixing multiplier")
        erased_literal.write_text(protected_text.replace("-2048144789", "-2048144787"),
                                  encoding="utf-8")
        erased_image = directory / "erased_literal.dll"
        run([str(args.compiler), "-shared", str(erased_literal), "-o", str(erased_image)])
        rejected = run([os.sys.executable, str(args.linked_checker), str(args.objdump),
                        str(erased_image), str(report)], succeeds=False)
        if "lost state-dependent literals" not in rejected.stderr:
            raise AssertionError("linked component gate failed for an unrelated reason")

        for name, feature, message in (("empty", "integer-literals", "zero eligible"),
                                       ("unsupported_width", "integer-literals", "i1 through i128"),
                                       ("empty", "internal-calls", "zero eligible")):
            bad = {"schema_version": 1, "functions": {
                name: {"components": {feature: "required"}}}}
            transform(bad, succeeds=False, extra=["-pyobf-cff-markers=false"])
            row = rows(report)[name]
            if row["status"] != "unsupported" or message not in row["reason"]:
                raise AssertionError(f"required empty/unsupported component was hidden: {row}")
            if not components(row)[feature]["sites"] and name != "empty":
                raise AssertionError("unsupported operand has no exact site record")

        invalid_configs = [
            ({"schema_version": 2}, "schema_version"),
            ({"schema_version": 1, "unknown_option": True}, "unknown field"),
            ({"schema_version": 1, "defaults": {"recipe": "parity"}}, "not yet implemented"),
            ({"schema_version": 1, "defaults": {"components": {"unknown": "required"}}},
             "unknown or unimplemented"),
            ({"schema_version": 1, "defaults": {"components": {"cfg": "off"}}}, "cannot be disabled"),
            ({"schema_version": 1, "markers": {"absent": {"recipe": "baseline"}}}, "matched no"),
        ]
        for bad, message in invalid_configs:
            result = transform(bad, succeeds=False)
            if message not in result.stderr:
                raise AssertionError(f"missing configuration diagnostic: {result.stderr}")

        for key, value, message in (
            ("build_domains", [{"id": "inner", "requires": ["child"]},
                               {"id": "child", "requires": ["inner"]}], "cycle"),
            ("build_domains", [{"id": "inner", "requires": ["missing"]}], "unknown dependency"),
            ("runtime_services", [{"id": "bad", "ready_at": "L4", "first_use": "L1"}],
             "before readiness"),
            ("runtime_services", [{"id": "early", "ready_at": "L1", "first_use": "L2",
                                   "requires": ["late"]},
                                  {"id": "late", "ready_at": "L3", "first_use": "L4"}],
             "unavailable at initialization"),
            ("runtime_services", [{"id": "app", "ready_at": "L2", "first_use": "L2",
                                   "application_domain": True, "protects_first_release": True}],
             "depends on application release"),
            ("runtime_services", [{"id": "a", "ready_at": "L1", "first_use": "L2", "requires": ["b"]},
                                  {"id": "b", "ready_at": "L1", "first_use": "L2", "requires": ["a"]}],
             "cycle"),
        ):
            bad = copy.deepcopy(config)
            bad[key] = value
            result = transform(bad, succeeds=False)
            if message not in result.stderr:
                raise AssertionError(f"invalid dependency contract was not rejected: {result.stderr}")

        manifest = directory / "requests.json"
        stamped = directory / "stamped.ll"
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff-requests",
             "-pyobf-cff-functions=choose", f"-pyobf-cff-requests-output={manifest}",
             "-S", str(source), "-o", str(stamped)])
        changed = directory / "changed.ll"
        changed.write_text(stamped.read_text(encoding="utf-8").replace(
            "%z = add i32 %x, 61", "%z = add i32 %x, %x"), encoding="utf-8")
        config_file.write_text(json.dumps({"schema_version": 1, "functions": {
            "choose": {"components": {"integer-literals": "required"}}}}), encoding="utf-8")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
             f"-pyobf-cff-config={config_file}", f"-pyobf-cff-requests-input={manifest}",
             f"-pyobf-cff-report={report}", "-disable-output", str(changed)], succeeds=False)
        lost = components(rows(report)["choose"])["integer-literals"]
        if lost["optimized_away"] != 1 or not any(
                site["status"] == "optimized-away" for site in lost["sites"]):
            raise AssertionError("removed required literal was not reported at site granularity")


if __name__ == "__main__":
    main()
