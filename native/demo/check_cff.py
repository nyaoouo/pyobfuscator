"""Reject an identity pass or an equality-chain dispatcher in the demo IR."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ir", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("strategy")
    parser.add_argument("selected")
    parser.add_argument("markers")
    parser.add_argument("--requests", type=Path)
    args = parser.parse_args()
    source = args.ir.read_text(encoding="utf-8")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    rows = {row["function"]: row for row in report["functions"]}
    if report["strategy"] != args.strategy:
        raise SystemExit("native CFF report has the wrong strategy")
    for name in filter(None, args.selected.split(",")):
        if rows[name]["status"] != "transformed" or not rows[name]["selected"]:
            raise SystemExit(f"native CFF did not cover {name}")
        if args.strategy != "relative-tree":
            continue
        function = re.search(r"(?ms)^define [^\n]*@" + re.escape(name) + r"\(.*?^}", source)[0]
        dispatcher = function[function.index("pyobf.dispatch:") :]
        if ("pyobf.leaf" not in dispatcher or dispatcher.count("icmp uge i32") < 2 or
                "icmp eq i32" in dispatcher or "add i32" not in function):
            raise SystemExit(f"native CFF did not produce a comparison tree for {name}")
    if args.markers == "true":
        if args.requests:
            requests = json.loads(args.requests.read_bytes())["functions"]
            expected = {row["function"]: row["marker"] for row in requests if row["defined"] and row.get("marker")}
            actual = {row["function"]: row["marker"] for row in report["functions"] if row.get("marker")}
            if actual != expected or any(rows[name]["status"] != "transformed" for name in expected):
                raise SystemExit("native CFF marker coverage differs from source/helper requests")
        else:
            expected = {"pyobf.native.cff": 2, "pyobf.native.sdk": 47}
            for marker, count in expected.items():
                actual = [row for row in report["functions"] if row.get("marker") == marker]
                if len(actual) != count or any(row["status"] != "transformed" for row in actual):
                    raise SystemExit(f"native CFF marker coverage is incomplete for {marker}")
    if not any(row["status"] == "declaration" for row in report["functions"]):
        raise SystemExit("native CFF report omitted module declarations")


if __name__ == "__main__":
    main()
