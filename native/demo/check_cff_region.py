"""Exercise explicit single-entry/single-exit region CFF and its rejection boundary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE = """
define i32 @region_case(i32 %x) noinline {
pre:
  %slot = alloca i32
  %before = mul i32 %x, 3
  br label %region.start
region.start:
  %positive = icmp sgt i32 %x, 0
  br i1 %positive, label %region.yes, label %region.no
region.yes:
  %yes = add i32 %before, 7
  store i32 %yes, ptr %slot
  br label %out
region.no:
  %no = sub i32 %before, 5
  store i32 %no, ptr %slot
  br label %out
out:
  %result = load i32, ptr %slot
  %scaled = mul i32 %result, 2
  ret i32 %scaled
}

@entry_value = global i32 0

define i32 @entry_case(i32 %x) noinline {
region.start:
  %positive = icmp sgt i32 %x, 0
  br i1 %positive, label %region.yes, label %region.no
region.yes:
  store i32 7, ptr @entry_value
  br label %out
region.no:
  store i32 -5, ptr @entry_value
  br label %out
out:
  %result = load i32, ptr @entry_value
  %sum = add i32 %result, %x
  ret i32 %sum
}
"""

HARNESS = """
extern "C" int region_case(int);
extern "C" int entry_case(int);
int main() {
    for (int value = -100; value <= 100; ++value) {
        const int expected = 2 * (value * 3 + (value > 0 ? 7 : -5));
        if (region_case(value) != expected) return 1;
        if (entry_case(value) != value + (value > 0 ? 7 : -5)) return 2;
    }
    return 0;
}
"""


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(f"command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result


def reject(opt: Path, plugin: Path, folder: Path, name: str,
           source: str, spec: str, reason: str) -> None:
    ir = folder / f"{name}.ll"
    report = folder / f"{name}.json"
    ir.write_text(source, encoding="utf-8")
    run([str(opt), "-passes=verify", "-disable-output", str(ir)])
    result = subprocess.run(
        [str(opt), "-load-pass-plugin", str(plugin), "-passes=pyobf-native-cff",
         "-pyobf-cff-markers=false", f"-pyobf-cff-region={spec}",
         f"-pyobf-cff-report={report}", "-disable-output", str(ir)],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode == 0 or not report.exists():
        raise AssertionError(f"invalid region succeeded or lacked report: {name}\n{result.stderr}")
    rows = json.loads(report.read_text(encoding="utf-8"))["functions"]
    row = next(row for row in rows if row["function"] == "region_case")
    if row["status"] != "unsupported" or reason not in row["reason"]:
        raise AssertionError(f"wrong region failure for {name}: {row}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("compiler", type=Path)
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("objdump", type=Path)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        folder = Path(temporary)
        ir = folder / "region.ll"
        output = folder / "region.cff.ll"
        report = folder / "region.json"
        harness = folder / "harness.cpp"
        ir.write_text(SOURCE, encoding="utf-8")
        harness.write_text(HARNESS, encoding="utf-8")
        run([str(args.opt), "-passes=verify", "-disable-output", str(ir)])
        requests = folder / "regions.requests.json"
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff-requests", "-pyobf-cff-markers=false",
             "-pyobf-cff-region=region_case:region.start:out",
             "-pyobf-cff-region=entry_case:region.start:out",
             f"-pyobf-cff-requests-output={requests}", "-disable-output", str(ir)])
        requested = {row["function"]: row["defined"] for row in
                     json.loads(requests.read_text(encoding="utf-8"))["functions"]}
        if requested != {"region_case": True, "entry_case": True}:
            raise AssertionError(f"region request collection failed: {requested}")
        run([str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-markers=false",
             "-pyobf-cff-region=region_case:region.start:out",
             "-pyobf-cff-region=entry_case:region.start:out",
             f"-pyobf-cff-requests-input={requests}",
             f"-pyobf-cff-report={report}", "-verify-each", "-S", str(ir),
             "-o", str(output)])
        rows = {row["function"]: row for row in
                json.loads(report.read_text(encoding="utf-8"))["functions"]}
        for name in ("region_case", "entry_case"):
            row = rows[name]
            if (row["status"] != "transformed" or
                    row["strategy"] != "relative-tree-region" or
                    row["coverage_kind"] != "region-decision-flow"):
                raise AssertionError(f"region report is incomplete: {row}")
        transformed = output.read_text(encoding="utf-8")
        if ("pyobf.region.dispatch:" not in transformed or
                "pyobf.region.setup:" not in transformed or
                "pyobf.region.exit:" not in transformed):
            raise AssertionError("region dispatcher is absent")
        pre = transformed.split("pre:", 1)[1].split("region.start:", 1)[0]
        out = transformed.split("out:", 1)[1].split("\n}", 1)[0]
        if "%before = mul i32 %x, 3" not in pre or "%scaled = mul i32 %result, 2" not in out:
            raise AssertionError("outside region blocks were rewritten")
        for label, source in (("plain", ir), ("region", output)):
            executable = folder / f"{label}.exe"
            run([str(args.compiler), str(harness), str(source), "-o", str(executable)])
            run([str(executable)])
            if label == "region":
                disassembly = run([str(args.objdump), "-d",
                                   "--disassemble-symbols=region_case",
                                   str(executable)]).stdout.lower()
                if (len(re.findall(r"\bjae\b", disassembly)) < 2 or
                        len(re.findall(r"\bimull\s+\$0x7feb352d\b", disassembly)) < 2):
                    raise AssertionError("linked region lost relative-tree transitions")
                final_report = folder / "region.final.json"
                run([sys.executable, str(Path(__file__).with_name("check_linked_cff.py")),
                     str(args.objdump), str(executable), str(report),
                     "--output", str(final_report)])
                final_rows = {row["function"]: row for row in
                              json.loads(final_report.read_text(encoding="utf-8"))
                              ["functions"] if row["selected"]}
                if not all(final_rows[name]["decision_flow_verified"] for name in
                           ("region_case", "entry_case")):
                    raise AssertionError("linked region was not verified as decision flow")

        reject(args.opt, args.plugin, folder, "missing", SOURCE,
               "region_case:absent:out", "distinct existing named")
        with_phi = SOURCE.replace("  %result = load i32, ptr %slot",
                                  "  %incoming = phi i32 [ 1, %region.yes ], [ 2, %region.no ]\n"
                                  "  %result = load i32, ptr %slot")
        reject(args.opt, args.plugin, folder, "exit_phi", with_phi,
               "region_case:region.start:out", "exit PHI")
        # Use a separate value defined in the region entry while preserving valid IR.
        cross_block = SOURCE.replace("  %positive = icmp sgt i32 %x, 0",
                                     "  %shared = add i32 %x, 1\n"
                                     "  %positive = icmp sgt i32 %x, 0")
        cross_block = cross_block.replace("%before, 7", "%shared, 7")
        reject(args.opt, args.plugin, folder, "cross_block", cross_block,
               "region_case:region.start:out", "cross-block use")
        multi_entry = SOURCE.replace("  br label %region.start\nregion.start:",
                                     "  %bypass = icmp eq i32 %x, 99\n"
                                     "  br i1 %bypass, label %region.yes, label %region.start\n"
                                     "region.start:")
        reject(args.opt, args.plugin, folder, "multi_entry", multi_entry,
               "region_case:region.start:out", "external entry")
        indirect_entry = SOURCE.replace("  br label %region.start\nregion.start:",
                                        "  indirectbr ptr blockaddress(@region_case, %region.start), "
                                        "[label %region.start]\nregion.start:")
        reject(args.opt, args.plugin, folder, "indirect_entry", indirect_entry,
               "region_case:region.start:out", "unsupported external predecessor")
        early_return = SOURCE.replace("  store i32 %no, ptr %slot\n  br label %out",
                                      "  ret i32 %no")
        reject(args.opt, args.plugin, folder, "early_return", early_return,
               "region_case:region.start:out", "branch terminators only")


if __name__ == "__main__":
    main()
