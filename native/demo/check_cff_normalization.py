"""Differentially prove dedup/common-exit behavior and required-site alias preservation."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


SOURCE_IR = r'''
@effects = global i32 0
define i32 @helper(i32 %x) {
entry:
  %result = add i32 %x, 23
  ret i32 %result
}
define i32 @duplicate_math(i32 %x) {
entry:
  %pick = icmp ult i32 %x, 8
  br i1 %pick, label %left, label %right
left:
  %a = add i32 %x, 7
  br label %out
right:
  %b = add i32 %x, 7
  br label %out
out:
  %result = phi i32 [%a, %left], [%b, %right]
  ret i32 %result
}
define i32 @literal_returns(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  ret i32 123456789
right:
  ret i32 123456789
}
define i32 @mixed_returns(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %result = call i32 @helper(i32 %x)
  ret i32 %result
right:
  ret i32 99
}
define i32 @combined_case(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a0 = add i32 %x, 7
  %a1 = mul i32 %a0, 3
  %a2 = xor i32 %a1, 8
  %a3 = add i32 %a2, 9
  ret i32 %a3
right:
  %b0 = add i32 %x, 7
  %b1 = mul i32 %b0, 3
  %b2 = xor i32 %b1, 8
  %b3 = add i32 %b2, 9
  ret i32 %b3
}
define void @void_case(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  store volatile i32 %x, ptr @effects
  ret void
right:
  store volatile i32 %x, ptr @effects
  ret void
}
define double @float_case(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  ret double -0.0
right:
  ret double 0.0
}
define {i32, i32} @aggregate_case(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a0 = insertvalue {i32, i32} poison, i32 %x, 0
  %a1 = insertvalue {i32, i32} %a0, i32 7, 1
  ret {i32, i32} %a1
right:
  %b0 = insertvalue {i32, i32} poison, i32 %x, 0
  %b1 = insertvalue {i32, i32} %b0, i32 9, 1
  ret {i32, i32} %b1
}
define i64 @aggregate_read(i32 %x) {
entry:
  %pair = call {i32, i32} @aggregate_case(i32 %x)
  %low = extractvalue {i32, i32} %pair, 0
  %high = extractvalue {i32, i32} %pair, 1
  %low64 = zext i32 %low to i64
  %high64 = zext i32 %high to i64
  %shift = shl i64 %high64, 32
  %result = or i64 %low64, %shift
  ret i64 %result
}
define i32 @duplicate_loop(i32 %x) {
entry:
  br label %header
header:
  %i = phi i32 [0, %entry], [%next, %join]
  %value = phi i32 [%x, %entry], [%combined, %join]
  %bit = and i32 %i, 1
  %pick = icmp eq i32 %bit, 0
  br i1 %pick, label %left, label %right
left:
  %a = add i32 %value, 7
  br label %join
right:
  %b = add i32 %value, 7
  br label %join
join:
  %combined = phi i32 [%a, %left], [%b, %right]
  %next = add i32 %i, 1
  %again = icmp ult i32 %next, 5
  br i1 %again, label %header, label %out
out:
  ret i32 %combined
}
define i32 @phi_mismatch(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a = add i32 %x, 7
  br label %out
right:
  %b = add i32 %x, 7
  br label %out
out:
  %result = phi i32 [%a, %left], [999, %right]
  ret i32 %result
}
define i32 @volatile_dup(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a = load volatile i32, ptr @effects
  br label %out
right:
  %b = load volatile i32, ptr @effects
  br label %out
out:
  %result = phi i32 [%a, %left], [%b, %right]
  ret i32 %result
}
define i32 @undef_dup(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a = add i32 %x, undef
  ret i32 %a
right:
  %b = add i32 %x, undef
  ret i32 %b
}
define i32 @flag_mismatch(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a = add nuw i32 %x, 7
  ret i32 %a
right:
  %b = add i32 %x, 7
  ret i32 %b
}
define i32 @tail_return(i32 %x) {
entry:
  %pick = icmp eq i32 %x, 0
  br i1 %pick, label %left, label %right
left:
  %a = musttail call i32 @helper(i32 %x)
  ret i32 %a
right:
  ret i32 99
}
define i32 @budget_case(i32 %x) {
entry:
  switch i32 %x, label %a [i32 0, label %b i32 1, label %c]
a:
  ret i32 1
b:
  ret i32 2
c:
  ret i32 3
}
'''

HARNESS = r'''
#include <cstdint>
#include <cstring>
extern "C" std::uint32_t duplicate_math(std::uint32_t);
extern "C" std::uint32_t literal_returns(std::uint32_t);
extern "C" std::uint32_t mixed_returns(std::uint32_t);
extern "C" std::uint32_t combined_case(std::uint32_t);
extern "C" std::uint32_t duplicate_loop(std::uint32_t);
extern "C" std::uint64_t aggregate_read(std::uint32_t);
extern "C" double float_case(std::uint32_t);
extern "C" void void_case(std::uint32_t);
extern "C" std::uint32_t effects;
int main() {
    for (std::uint32_t i = 0; i < 1000; ++i) {
        const std::uint32_t x = i * 0x1234567u;
        if (duplicate_math(x) != x + 7 || literal_returns(x) != 123456789u ||
            mixed_returns(x) != (x == 0 ? x + 23 : 99) || duplicate_loop(x) != x + 35)
            return 1;
        if (combined_case(x) != (((x + 7) * 3) ^ 8u) + 9) return 5;
        void_case(x);
        if (effects != x) return 2;
        const auto floating = float_case(x);
        std::uint64_t bits = 0;
        std::memcpy(&bits, &floating, sizeof(bits));
        if (bits != (x == 0 ? 0x8000000000000000ull : 0ull)) return 3;
        if (aggregate_read(x) != (x | (std::uint64_t(x == 0 ? 7 : 9) << 32))) return 4;
    }
    return 0;
}
'''


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result: {command}\n{result.stdout}\n{result.stderr}")
    return result


def component(row: dict, name: str) -> dict:
    return next(item for item in row["components"] if item["component"] == name)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        output = directory / "protected.ll"
        report = directory / "coverage.json"
        config_file = directory / "recipe.json"
        private = directory / "private.json"
        source.write_text(SOURCE_IR, encoding="utf-8")
        config = {"schema_version": 1, "functions": {
            "duplicate_math": {"components": {"deduplicate-blocks": "required", "integer-literals": "required"},
                               "budgets": {"max_body_blocks": 3}},
            "duplicate_loop": {"components": {"deduplicate-blocks": "required", "integer-literals": "required"}},
            "literal_returns": {"components": {"common-exit": "required", "deduplicate-blocks": "required",
                                                  "integer-literals": "required"}},
            "mixed_returns": {"components": {"common-exit": "required", "integer-literals": "required",
                                                "internal-calls": "required"}},
            "combined_case": {"components": {"common-exit": "required", "deduplicate-blocks": "required",
                                                "split-blocks": "required", "integer-literals": "required"},
                              "budgets": {"max_block_instructions": 2}},
            "void_case": {"components": {"common-exit": "required"}},
            "float_case": {"components": {"common-exit": "required"}},
            "aggregate_case": {"components": {"common-exit": "required"}},
        }}

        def transform(settings: dict, *, succeeds: bool = True, input_ir: Path = source):
            config_file.write_text(json.dumps(settings), encoding="utf-8")
            output.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}",
                          "-passes=pyobf-native-cff", f"-pyobf-cff-config={config_file}",
                          f"-pyobf-cff-report={report}", f"-pyobf-cff-private-map={private}",
                          "-verify-each", "-S", str(input_ir), "-o", str(output)], succeeds=succeeds)
            if not succeeds and output.exists():
                raise AssertionError("rejected normalization emitted a protected artifact")
            return result

        transform(config)
        rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
        math = component(rows["duplicate_math"], "integer-literals")
        if (math["coalesced"] != 1 or math["applied"] != 2 or
                rows["duplicate_math"]["site_totals"]["deduplicated_blocks"] != 1):
            raise AssertionError(f"merged sites were lost or double-counted: {math}")
        if (rows["duplicate_math"]["coverage_kind"] != "normalized-straight-line" or
                rows["duplicate_math"]["site_totals"]["normalized_decisions"] != 0 or
                rows["duplicate_loop"]["site_totals"]["normalized_decisions"] != 1):
            raise AssertionError("a collapsed decision was credited as retained control flow")
        literals = component(rows["literal_returns"], "integer-literals")
        if (literals["relocated"] != 2 or literals["coalesced"] != 1 or
                literals["applied"] != 2 or
                rows["literal_returns"]["site_totals"]["normalized_returns"] != 2):
            raise AssertionError(f"return/store/merged-store alias chain is incorrect: {literals}")
        maps = {row["function"]: row["sites"] for row in json.loads(private.read_text())["functions"]}
        mapped = {site["id"]: site for site in maps["literal_returns"]}
        aliases = [site for site in literals["sites"] if site["status"] == "relocated"]
        if any(not mapped[site["id"]]["transformed_ir"] for site in aliases):
            raise AssertionError("private return-site aliases lost their final consumption locations")
        combined = rows["combined_case"]["site_totals"]
        if combined["real_splits"] < 1 or combined["deduplicated_blocks"] != 1 or combined["normalized_returns"] != 2:
            raise AssertionError("the combined recipe did not actually apply all three normalizers")
        for name, row in rows.items():
            if row["selected"] and row["status"] != "transformed":
                raise AssertionError(f"selected normalized function did not complete: {name}")
        ir = output.read_text(encoding="utf-8")
        for name in ("literal_returns", "mixed_returns", "combined_case", "void_case", "float_case", "aggregate_case"):
            body = re.search(rf"define [^\n]*@{name}\(.*?\n\}}", ir, re.S)
            if body is None or len(re.findall(r"(?m)^\s+ret\b", body.group())) != 1:
                raise AssertionError(f"common exit is absent: {name}")
        harness = directory / "harness.cpp"
        harness.write_text(HARNESS, encoding="utf-8")
        for label, path in (("baseline", source), ("protected", output)):
            binary = directory / f"{label}.exe"
            run([str(args.compiler), str(path), str(harness), "-o", str(binary)])
            run([str(binary)])
        image = directory / "protected.dll"
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])

        # The alias must reach a real state-bound decoder, rather than only marking coverage.
        block = mapped[aliases[0]["id"]]["transformed_ir"][0]["block"]
        function = re.search(r"define i32 @literal_returns\(.*?\n\}", ir, re.S)
        if function is None:
            raise AssertionError("missing literal_returns body")
        local = function.group()
        match = re.search(rf"(?m)^{re.escape(block)}:[^\n]*\n(?:(?!^[^\s;][^\n]*:).)*",
                          local, re.S | re.M)
        if match is None:
            raise AssertionError("relocated decoder block is absent")
        changed, count = re.subn(
            r"(%pyobf\.literal\.state(?:\.?\d+)? = )load i32, ptr %pyobf\.state(?:, align \d+)?",
            r"\1add i32 0, 0", match.group(), count=1)
        if count != 1:
            raise AssertionError("relocated literal has no state-dependent decoder")
        altered_local = local[:match.start()] + changed + local[match.end():]
        altered = directory / "tampered.ll"
        altered.write_text(ir[:function.start()] + altered_local + ir[function.end():], encoding="utf-8")
        binary = directory / "tampered.exe"
        run([str(args.compiler), str(altered), str(harness), "-o", str(binary)])
        run([str(binary)], succeeds=False)

        bound = directory / "already_bound.ll"
        bound.write_text(ir, encoding="utf-8")
        transform(config, succeeds=False, input_ir=bound)
        if "already state-bound" not in report.read_text():
            raise AssertionError("normalization/CFF was reapplied after final state binding")

        for name, feature, message in (
            ("phi_mismatch", "deduplicate-blocks", "PHI values differ"),
            ("volatile_dup", "deduplicate-blocks", "volatile"),
            ("undef_dup", "deduplicate-blocks", "undef/poison"),
            ("flag_mismatch", "deduplicate-blocks", "zero eligible"),
            ("tail_return", "common-exit", "musttail"),
        ):
            bad = {"schema_version": 1, "functions": {name: {"components": {feature: "required"}}}}
            transform(bad, succeeds=False)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            if row["status"] != "unsupported" or message not in row["reason"]:
                raise AssertionError(f"unsafe normalization was not rejected precisely: {row}")
        bad = {"schema_version": 1, "functions": {"budget_case": {
            "components": {"deduplicate-blocks": "required"},
            "budgets": {"max_dedup_comparisons": 1}}}}
        transform(bad, succeeds=False)
        if "budget exhausted" not in report.read_text():
            raise AssertionError("bounded dedup planning silently skipped unknown eligibility")
        bad = {"schema_version": 1, "functions": {"literal_returns": {
            "components": {"common-exit": "required"}, "budgets": {"max_body_blocks": 3}}}}
        transform(bad, succeeds=False)
        if "normalized scope exceeds max_body_blocks" not in report.read_text():
            raise AssertionError("normalization growth exceeded the final body budget")
        bad = {"schema_version": 1, "functions": {"duplicate_math": {
            "components": {"deduplicate-blocks": "required"}}}}
        config_file.write_text(json.dumps(bad), encoding="utf-8")
        result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                      f"-pyobf-cff-config={config_file}", "-pyobf-cff-region=duplicate_math:left:out",
                      "-disable-output", str(source)], succeeds=False)
        if "does not support regions" not in result.stderr:
            raise AssertionError("normalization silently widened a region to a whole function")
        result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                      f"-pyobf-cff-config={config_file}", "-pyobf-cff-require-decision-flow=true",
                      f"-pyobf-cff-report={report}", "-disable-output", str(source)], succeeds=False)
        if "normalization removed all protected decision flow" not in report.read_text():
            raise AssertionError("strict decision-flow selection accepted a collapsed decision")


if __name__ == "__main__":
    main()
