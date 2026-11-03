"""Verify failed selections cannot silently produce an unprotected build."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


UNSUPPORTED_IR = """
declare void @may_throw()
declare i32 @__gxx_personality_v0(...)

define i32 @unsupported(i32 %value) personality ptr @__gxx_personality_v0 {
entry:
  %condition = icmp eq i32 %value, 0
  br i1 %condition, label %call, label %other
call:
  invoke void @may_throw() to label %done unwind label %handler
other:
  ret i32 1
done:
  ret i32 0
handler:
  %landing = landingpad {ptr, i32} cleanup
  ret i32 -1
}
"""

DEAD_BLOCKS_IR = """
define i32 @dead_blocks(i32 %value) {
entry:
  ret i32 %value
dead_one:
  ret i32 1
dead_two:
  ret i32 2
}
"""

COROUTINE_IR = """
declare token @llvm.coro.id(i32, ptr, ptr, ptr)
define void @coroutine_probe() {
entry:
  %id = call token @llvm.coro.id(i32 0, ptr null, ptr null, ptr null)
  ret void
}
"""

SDK_BIND = "_ZN12pyobfuscator6native22bind_bootstrap_contextERKNS0_21BootstrapContextLeaseE"


def run_case(opt: Path, plugin: Path, source: Path, selection: str,
             strategy: str, report: Path, expected_status: str | None,
             expected_reason: str | None = None) -> None:
    command = [str(opt), "-load-pass-plugin", str(plugin),
               "-passes=pyobf-native-cff", f"-pyobf-cff-functions={selection}",
               "-pyobf-cff-markers=false",
               f"-pyobf-cff-strategy={strategy}", f"-pyobf-cff-report={report}",
               "-disable-output", str(source)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if process.returncode == 0:
        raise AssertionError(f"invalid CFF selection succeeded: {selection}/{strategy}")
    if expected_status is None:
        if report.exists() or "unknown native CFF strategy" not in process.stderr:
            raise AssertionError("unknown strategy did not fail before the report")
        return
    if not report.exists():
        raise AssertionError(f"failed CFF selection did not write a report: {process.stderr}")
    rows = json.loads(report.read_text(encoding="utf-8"))["functions"]
    if not any(row["function"] == selection and row["status"] == expected_status and
               (expected_reason is None or expected_reason in row.get("reason", ""))
               for row in rows):
        raise AssertionError(f"CFF report did not record {selection}: {rows}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("input_ir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.input_ir.parent) as temporary:
        directory = Path(temporary)
        unsupported = directory / "unsupported.ll"
        unsupported.write_text(UNSUPPORTED_IR, encoding="utf-8")
        dead_blocks = directory / "dead_blocks.ll"
        dead_blocks.write_text(DEAD_BLOCKS_IR, encoding="utf-8")
        coroutine = directory / "coroutine.ll"
        coroutine.write_text(COROUTINE_IR, encoding="utf-8")
        single_report = directory / "single.json"
        single = subprocess.run(
            [str(args.opt), "-load-pass-plugin", str(args.plugin),
             "-passes=pyobf-native-cff", "-pyobf-cff-functions=pyobf_demo_compute",
             "-pyobf-cff-markers=false",
             f"-pyobf-cff-report={single_report}", "-disable-output", str(args.input_ir)],
            capture_output=True, text=True, timeout=15,
        )
        if single.returncode != 0:
            raise AssertionError(f"single-function CFF failed: {single.stderr}")
        single_rows = {row["function"]: row for row in
                       json.loads(single_report.read_text(encoding="utf-8"))["functions"]}
        if (single_rows["pyobf_demo_compute"]["status"] != "transformed" or
                single_rows["pyobf_native_inner_entry"]["status"] != "unselected"):
            raise AssertionError("single-function CFF report did not distinguish coverage")
        run_case(args.opt, args.plugin, args.input_ir, "absent_function",
                 "relative-tree", directory / "missing.json", "missing")
        run_case(args.opt, args.plugin, args.input_ir, SDK_BIND,
                 "relative-tree", directory / "sdk_missing.json", "unsupported",
                 "declaration")
        run_case(args.opt, args.plugin, unsupported, "unsupported",
                 "relative-tree", directory / "unsupported.json", "unsupported", "branches")
        run_case(args.opt, args.plugin, dead_blocks, "dead_blocks",
                 "relative-tree", directory / "dead.json", "unsupported", "unreachable body")
        run_case(args.opt, args.plugin, coroutine, "coroutine_probe",
                 "relative-tree", directory / "coroutine.json", "unsupported", "coroutine")
        run_case(args.opt, args.plugin, args.input_ir, "pyobf_demo_compute",
                 "unknown", directory / "unknown.json", None)


if __name__ == "__main__":
    main()
