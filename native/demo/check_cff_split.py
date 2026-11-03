"""Prove legal budget splitting, SSA/memory behavior, tail adjacency and final transitions."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from split_request_cases import check_retained_split_requests


SOURCE_IR = '''
@observed = global i32 0
@counter = global i32 0
define i32 @heavy(i32 %x) {
entry:
  %a = add i32 %x, 3
  store volatile i32 %a, ptr @observed
  %b = mul i32 %a, 7
  %old = atomicrmw add ptr @counter, i32 1 seq_cst
  %c = add i32 %b, %old
  %seen = load volatile i32, ptr @observed
  %v0 = xor i32 %c, %seen
  @WORK@
  %pick = and i32 %x, 3
  switch i32 %pick, label %done [i32 0, label %loop]
loop:
  %i = phi i32 [0, %entry], [%next, %loop]
  %value = phi i32 [%v19, %entry], [%accum, %loop]
  %accum = add i32 %value, %i
  %next = add i32 %i, 1
  %again = icmp ult i32 %next, 5
  br i1 %again, label %loop, label %loop_done
loop_done:
  ret i32 %accum
done:
  ret i32 %v19
}
define i32 @tail_target(i32 %x) {
entry:
  %y = add i32 %x, 17
  ret i32 %y
}
define i32 @tail(i32 %x) {
entry:
  %result = musttail call i32 @tail_target(i32 %x)
  ret i32 %result
}
define i32 @tiny(i32 %x) {
entry:
  ret i32 %x
}
'''.replace("@WORK@", "\n  ".join(
    f"%v{index} = {'add' if index % 2 else 'xor'} i32 %v{index - 1}, {index * 23 + 5}"
    for index in range(1, 20)
))

HARNESS = r'''
#include <cstdint>
#include <cstdio>
extern "C" std::uint32_t heavy(std::uint32_t);
extern "C" std::uint32_t tail(std::uint32_t);
extern "C" std::uint32_t tiny(std::uint32_t);
extern "C" std::uint32_t observed;
extern "C" std::uint32_t counter;
int main() {
    std::uint64_t checksum = 0;
    for (std::uint32_t i = 0; i < 1000; ++i) {
        const std::uint32_t x = i * 0x1234567u;
        checksum = checksum * 131 + heavy(x);
        if (observed != x + 3 || tail(x) != x + 17 || tiny(x) != x) return 1;
    }
    if (counter != 1000) return 2;
    std::printf("%llu\n", static_cast<unsigned long long>(checksum));
    return 0;
}
'''


def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result for {command}\n{result.stdout}\n{result.stderr}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        protected = directory / "protected.ll"
        config_file = directory / "recipe.json"
        report = directory / "coverage.json"
        private = directory / "private.json"
        harness = directory / "harness.cpp"
        source.write_text(SOURCE_IR, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        config = {
            "schema_version": 1,
            "functions": {
                "heavy": {"components": {"split-blocks": "required", "integer-literals": "optional"},
                          "budgets": {"max_block_instructions": 4, "max_body_blocks": 100}},
                "tail": {"components": {"split-blocks": "optional"},
                         "budgets": {"max_block_instructions": 1}},
                "tiny": {"budgets": {"min_blocks": 7, "max_body_blocks": 7}},
            },
        }

        def transform(current: dict, *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
            config_file.write_text(json.dumps(current), encoding="utf-8")
            protected.unlink(missing_ok=True)
            result = run([str(args.opt), f"-load-pass-plugin={args.plugin}",
                          "-passes=pyobf-native-cff", f"-pyobf-cff-config={config_file}",
                          f"-pyobf-cff-report={report}", f"-pyobf-cff-private-map={private}",
                          "-verify-each", "-S", str(source), "-o", str(protected)], succeeds=succeeds)
            if not succeeds and protected.exists():
                raise AssertionError("failed block budget emitted a protected artifact")
            return result

        transform(config)
        rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
        sites = {row["component"]: row for row in rows["heavy"]["components"]}["split-blocks"]
        if (sites["applied"] < 5 or sites["unsupported"] or
                sites["eligible"] != sites["applied"] or
                rows["heavy"]["site_totals"]["real_splits"] != sites["applied"] or
                rows["heavy"]["site_totals"]["decoy_blocks"] != 0):
            raise AssertionError(f"real split coverage is incorrect: {sites}")
        if rows["tiny"]["site_totals"]["shape_padding"] != 6:
            raise AssertionError("configured minimum was not counted as shape padding")
        ir = protected.read_text(encoding="utf-8")
        tail = re.search(r"define i32 @tail\(.*?\n\}", ir, re.S)
        if tail is None or not re.search(
                r"musttail call i32 @tail_target\([^\n]*\n\s+ret i32", tail.group()):
            raise AssertionError("musttail call/return adjacency was lost")
        mapped = next(row for row in json.loads(private.read_text())["functions"]
                      if row["function"] == "heavy")
        ids = {row["id"] for row in sites["sites"]}
        if not all(site["transformed_ir"] for site in mapped["sites"] if site["id"] in ids):
            raise AssertionError("split work lost its transformed location map")
        outputs = []
        for name, ir_file in (("baseline", source), ("protected", protected)):
            binary = directory / f"{name}.exe"
            run([str(args.compiler), str(ir_file), str(harness), "-o", str(binary)])
            outputs.append(run([str(binary)]).stdout)
        if outputs[0] != outputs[1] or not outputs[0].strip():
            raise AssertionError("split/SSA/switch/memory behavior differs from original execution")
        image = directory / "protected.dll"
        run([str(args.compiler), "-shared", str(protected), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])

        limited = {"schema_version": 1, "functions": {"heavy": {
            "components": {"split-blocks": "required"},
            "budgets": {"max_block_instructions": 1, "max_body_blocks": 5}}}}
        transform(limited, succeeds=False)
        failed = next(row for row in json.loads(report.read_text())["functions"]
                      if row["function"] == "heavy")
        if failed["status"] != "unsupported" or "max_body_blocks" not in failed["reason"]:
            raise AssertionError("required split budget exhaustion was silently skipped")
        transform({"schema_version": 1, "functions": {"tiny": {
            "components": {"split-blocks": "required"}}}}, succeeds=False)
        zero = next(row for row in json.loads(report.read_text())["functions"]
                    if row["function"] == "tiny")
        if "zero eligible" not in zero["reason"]:
            raise AssertionError("zero-work splitting was credited as applied protection")
        bad = {"schema_version": 1, "functions": {"tiny": {
            "budgets": {"min_blocks": 9, "max_body_blocks": 8}}}}
        result = transform(bad, succeeds=False)
        if "min_blocks" not in result.stderr:
            raise AssertionError("incoherent min/max block budget was not rejected")
        check_retained_split_requests(args, directory, SOURCE_IR, harness, outputs[0], run)


if __name__ == "__main__":
    main()
