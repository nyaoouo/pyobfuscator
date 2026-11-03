"""Merge source and late-helper requests without weakening duplicate-definition checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def read(path: Path) -> dict[str, dict]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("request manifest exceeds the byte budget")
    document = json.loads(raw)
    if (not isinstance(document, dict) or set(document) != {"module", "functions"} or
            not isinstance(document["module"], str) or not isinstance(document["functions"], list)):
        raise ValueError("invalid request manifest root")
    result = {}
    for row in document["functions"]:
        if (not isinstance(row, dict) or not {"function", "defined", "sites"} <= set(row) or
                set(row) - {"function", "defined", "sites", "marker"} or
                not isinstance(row["function"], str) or not row["function"] or
                type(row["defined"]) is not bool or not isinstance(row["sites"], list) or
                not isinstance(row.get("marker", ""), str) or row["function"] in result):
            raise ValueError("invalid or duplicate requested function")
        ids = set()
        for site in row["sites"]:
            if (not isinstance(site, dict) or set(site) != {"id", "component"} or
                    any(not isinstance(site[name], str) or not site[name] for name in ("id", "component")) or
                    site["id"] in ids):
                raise ValueError("invalid or duplicate requested site")
            ids.add(site["id"])
        if not row["defined"] and row["sites"]:
            raise ValueError("an undefined function cannot contain requested sites")
        result[row["function"]] = row
    if not result:
        raise ValueError("request manifest has no functions")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    if args.output.resolve() in {path.resolve() for path in args.inputs}:
        parser.error("merged requests cannot overwrite an input")
    try:
        combined = {}
        for path in args.inputs:
            for name, row in read(path).items():
                previous = combined.get(name)
                if previous is not None:
                    if previous["defined"] and row["defined"]:
                        raise ValueError("two request producers define the same function")
                    if previous.get("marker") and row.get("marker") and previous["marker"] != row["marker"]:
                        raise ValueError("request producers disagree on a source marker")
                    chosen = row if row["defined"] else previous
                    marker = row.get("marker") or previous.get("marker")
                    combined[name] = dict(chosen, **({"marker": marker} if marker else {}))
                else:
                    combined[name] = row
        document = {"module": "native-source-and-runtime", "functions": [combined[name] for name in sorted(combined)]}
        args.output.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
