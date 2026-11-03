"""Verify pre-optimization requests distinguish removed definitions from unknown names."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


REQUESTED_IR = r"""
@.marker = private constant [17 x i8] c"pyobf.native.cff\00"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr } { ptr @protected, ptr @.marker, ptr null, i32 1, ptr null }],
  section "llvm.metadata"
define i32 @protected() {
entry:
  ret i32 7
}
"""

REMOVED_IR = "define i32 @unrelated() {\nentry:\n  ret i32 0\n}\n"


def run(command: list[str], *, succeeds: bool) -> None:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected CFF result: {command}\n{result.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "configured_manifest", "configured_report", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    configured = json.loads(args.configured_manifest.read_text(encoding="utf-8"))
    report = json.loads(args.configured_report.read_text(encoding="utf-8"))
    requested = {row["function"] for row in configured["functions"] if row["defined"]}
    retained = {row["function"] for row in report["functions"]
                if row["requested"] and row["retained"] and row["status"] == "transformed"}
    if not requested or retained != requested:
        raise AssertionError("configured source and SDK requests were not retained")

    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        original = directory / "requested.ll"
        removed = directory / "removed.ll"
        manifest = directory / "requests.json"
        removed_report = directory / "removed.json"
        unknown_report = directory / "unknown.json"
        original.write_text(REQUESTED_IR, encoding="utf-8")
        removed.write_text(REMOVED_IR, encoding="utf-8")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}",
             "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-requests-output={manifest}", "-disable-output",
             str(original)], succeeds=True)
        gathered = json.loads(manifest.read_text(encoding="utf-8"))["functions"]
        identities = [{key: value for key, value in row.items() if key != "sites"}
                      for row in gathered]
        if (identities != [{"defined": True, "function": "protected",
                            "marker": "pyobf.native.cff"}] or
                not gathered[0].get("sites")):
            raise AssertionError(f"request collection lost the source marker: {gathered}")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}",
             "-passes=pyobf-native-cff", "-pyobf-cff-markers=false",
             f"-pyobf-cff-requests-input={manifest}", f"-pyobf-cff-report={removed_report}",
             "-disable-output", str(removed)], succeeds=False)
        rows = json.loads(removed_report.read_text(encoding="utf-8"))["functions"]
        lost = next(row for row in rows if row["function"] == "protected")
        if (lost["status"] != "optimized-away" or lost["retained"] or
                not lost["requested"] or lost.get("marker") != "pyobf.native.cff"):
            raise AssertionError(f"removed protected function was misreported: {lost}")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}",
             "-passes=pyobf-native-cff", "-pyobf-cff-markers=false",
             "-pyobf-cff-functions=protected", f"-pyobf-cff-report={unknown_report}",
             "-disable-output", str(removed)], succeeds=False)
        unknown = json.loads(unknown_report.read_text(encoding="utf-8"))["functions"]
        if next(row for row in unknown if row["function"] == "protected")["status"] != "missing":
            raise AssertionError("unknown exact selection was not distinct from removed code")


if __name__ == "__main__":
    main()
