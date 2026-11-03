"""Reject malformed build inputs without overwriting private source requests or assets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    tools = Path(__file__).resolve().parents[1] / "tools"
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)

        def invoke(tool: str, paths: list, *, succeeds=True):
            result = subprocess.run([sys.executable, str(tools / tool), *map(str, paths)],
                                    capture_output=True, text=True, timeout=30)
            if (result.returncode == 0) != succeeds:
                raise AssertionError(f"{tool} exit differs: {result.stderr}")

        asset, header, source = [directory / name for name in ("input.bin", "asset_sample.hpp", "asset_sample.cpp")]
        asset.write_bytes(bytes(range(256)))
        invoke("embed_asset.py", ["sample", asset, header, source])
        outputs = header.read_bytes(), source.read_bytes()
        invoke("embed_asset.py", ["sample", asset, header, source])
        if outputs != (header.read_bytes(), source.read_bytes()) or "return 256;" not in source.read_text():
            raise AssertionError("asset generation changed bytes for the same input or lost logical size")
        for identity in ("", "Bad", "a-b", "x" * 65, "../x"):
            invoke("embed_asset.py", [identity, asset, header, source], succeeds=False)
        invoke("embed_asset.py", ["sample", asset, asset, source], succeeds=False)
        invoke("embed_asset.py", ["sample", asset, directory / "wrong.hpp", source], succeeds=False)
        if asset.read_bytes() != bytes(range(256)) or outputs != (header.read_bytes(), source.read_bytes()):
            raise AssertionError("invalid asset input changed existing artifacts")
        asset.write_bytes(b"")
        invoke("embed_asset.py", ["sample", asset, header, source])
        if "return 0;" not in source.read_text() or "0x00" not in source.read_text():
            raise AssertionError("empty asset lost its explicit logical length or portable storage sentinel")
        with asset.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        invoke("embed_asset.py", ["sample", asset, header, source], succeeds=False)
        asset.unlink()
        invoke("embed_asset.py", ["sample", asset, header, source], succeeds=False)

        left, right, output = [directory / name for name in ("left.json", "right.json", "merged.json")]
        row = {"function": "f", "defined": True, "marker": "pyobf.native.cff",
               "sites": [{"id": "site-f", "component": "constant-archive"}]}
        first = {"module": "source", "functions": [row]}
        second = {"module": "runtime", "functions": [dict(row, defined=False, sites=[]),
                  dict(row, function="g", marker="pyobf.native.sdk", sites=[])]}
        left.write_text(json.dumps(first), encoding="utf-8")
        right.write_text(json.dumps(second), encoding="utf-8")
        invoke("merge_requests.py", [output, left, right])
        merged = output.read_bytes()
        rows = json.loads(merged)["functions"]
        if [item["function"] for item in rows] != ["f", "g"] or rows[0] != row:
            raise AssertionError("late helper requests lost source definition/site provenance")
        invoke("merge_requests.py", [output, right, left])
        if output.read_bytes() != merged:
            raise AssertionError("merge order changed the canonical request manifest")
        bad = [dict(first, unknown=1), dict(first, functions=[])]
        for change in ({"defined": 1}, {"sites": row["sites"] * 2}, {"defined": False}, {"function": ""}):
            bad.append(dict(first, functions=[dict(row, **change)]))
        bad.append(dict(first, functions=[row, row]))
        for document in bad:
            right.write_text(json.dumps(document), encoding="utf-8")
            invoke("merge_requests.py", [output, left, right], succeeds=False)
        for other in (row, dict(row, defined=False, sites=[], marker="different")):
            right.write_text(json.dumps(dict(second, functions=[other])), encoding="utf-8")
            invoke("merge_requests.py", [output, left, right], succeeds=False)
        invoke("merge_requests.py", [left, left], succeeds=False)
        if json.loads(left.read_bytes()) != first or output.read_bytes() != merged:
            raise AssertionError("invalid request merge changed a source or prior output")


if __name__ == "__main__":
    main()
