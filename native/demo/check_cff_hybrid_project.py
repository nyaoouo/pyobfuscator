"""Run a real mixed-scope CMake project through callback EH, SDK, assets and archive."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

def run(command: list[str], *, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"hybrid project command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result


def configuration(composed: bool, archive: bool, strict_literals: bool = False) -> dict:
    hybrid = {"constant-archive": "off"}
    whole = {"integer-literals": "required" if strict_literals else "optional"}
    if composed:
        hybrid.update({name: "required" for name in ("call-frames", "external-calls", "call-preparation",
                                                     "reference-routes", "import-routes")})
        whole.update({name: "required" for name in ("call-frames", "call-preparation", "reference-routes")})
    return {"schema_version": 1, "markers": {
        "pyobf.native.cff": {"recipe": "baseline", "components": {"constant-archive": "optional" if archive else "off"}},
        "pyobf.native.sdk": {"recipe": "baseline"}}, "functions": {
            "hybrid_callback": {"coverage": "hybrid-eh", "components": hybrid},
            "whole_callback_result": {"components": whole},
            "__pyobf_native_asset_sample_data": {"components": {"constant-archive": "required" if archive else "off"}}}}


def check_reports(build: Path, composed: bool, archive: bool, asset: bytes) -> None:
    report = build / "coverage.json"
    rows = json.loads(report.read_text())["functions"]
    selected = {row["function"]: row for row in rows if row["selected"]}
    owner, whole = selected["hybrid_callback"], selected["whole_callback_result"]
    if (not owner["coverage_kind"].startswith("hybrid-eh-") or whole["coverage_kind"].startswith("hybrid") or
            any(row["status"] != "transformed" for row in selected.values())):
        raise AssertionError("mixed whole/hybrid selection was lost")
    if not any(row.get("marker") == "pyobf.native.sdk" and "inspect_current_process" in name for name, row in selected.items()):
        raise AssertionError("actual SDK inspection was not included in CFF")
    if not owner["hybrid_eh"]["ir_flow_graph_verified"]: raise AssertionError("callback EH final-flow proof was skipped")
    if composed:
        for name in ("call-frames", "external-calls", "call-preparation", "reference-routes", "import-routes"):
            item = next(item for item in owner["components"] if item["component"] == name)
            if not item["applied"] or item["unsupported"]: raise AssertionError(f"callback owner lost {name}")
    literal = next(item for item in whole["components"] if item["component"] == "integer-literals")
    if not literal["applied"]: raise AssertionError("whole-scope data protection was not exercised")
    final = json.loads((build / "final.json").read_text())
    image = build / "hybrid_subject.dll"
    if (final["image_sha256"] != hashlib.sha256(image.read_bytes()).hexdigest() or
            final["input_report_sha256"] != hashlib.sha256(report.read_bytes()).hexdigest()):
        raise AssertionError("mixed project final report is stale")
    final_owner = next(row for row in final["functions"] if row["function"] == "hybrid_callback")
    if final_owner["decision_flow_verified"] or not final_owner["hybrid_eh"]["final_normal_dispatch_presence_verified"]:
        raise AssertionError("callback EH scope was promoted or final dispatch disappeared")
    if archive:
        plan = json.loads((build / "archive.plan.json").read_text())["records"]
        if not any(bytes.fromhex(record["data_hex"]) == asset for record in plan):
            raise AssertionError("real source asset did not reach the archive")
        if asset in image.read_bytes(): raise AssertionError("archived callback asset remains plaintext")
        source = selected["__pyobf_native_asset_sample_data"]["archive_sources"]
        if not source["requested"] or not source["applied"]: raise AssertionError("archive source handoff was lost")


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("cmake", "ninja", "compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="hybrid project ", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        asset = b"\x05hybrid-callback-archive-" + bytes(range(64)) + b"\0\xff"
        asset_path = directory / "callback asset.bin"
        asset_path.write_bytes(asset)
        expected = None
        for name, protected, composed, archive, seed in (
            ("plain", False, False, False, 17), ("strict-data", True, False, False, 17),
            ("cfg", True, False, False, 17), ("composed", True, True, False, 1), ("archive", True, True, True, 41)):
            build, recipe = directory / name, directory / f"{name}.json"
            strict = name == "strict-data"
            recipe.write_text(json.dumps(configuration(composed, archive, strict)), encoding="utf-8")
            run([str(args.cmake), "-S", str(root / "tests/hybrid_project"), "-B", str(build), "-G", "Ninja",
                f"-DCMAKE_MAKE_PROGRAM={args.ninja}", f"-DCMAKE_CXX_COMPILER={args.compiler}",
                f"-DPython3_EXECUTABLE={sys.executable}", f"-DNATIVE_ROOT={root}", f"-DPLUGIN={args.plugin}",
                f"-DPYOBF_NATIVE_OPT_EXECUTABLE={args.opt}", f"-DPYOBF_NATIVE_LLVM_LINK_EXECUTABLE={args.llvm_link}",
                f"-DOBJDUMP={args.objdump}", f"-DASSET_FILE={asset_path}", f"-DRECIPE={recipe}",
                f"-DPROTECT={'ON' if protected else 'OFF'}", f"-DARCHIVE_ENABLED={'ON' if archive else 'OFF'}",
                f"-DSEED={seed}", "-DSOURCE_OPT=default<O2>", "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"])
            run([str(args.cmake), "--build", str(build), "-j", "2"], succeeds=not strict)
            if strict:
                row = next(row for row in json.loads((build / "coverage.json").read_text())["functions"]
                           if row["function"] == "whole_callback_result")
                item = next(item for item in row["components"] if item["component"] == "integer-literals")
                if (row["status"] != "unsupported" or not item["optimized_away"] or
                        "requested site did not survive ordinary optimization" not in row["reason"] or
                        (build / "hybrid_subject.dll").exists() or (build / "final.json").exists()):
                    raise AssertionError("strict original-data loss was accepted or failed outside its intended gate")
                continue
            result = run([str(build / "hybrid_probe.exe")]).stdout
            if "HYBRID_CALLBACK_THREADS_OK" not in result or len(result.splitlines()) != 16:
                raise AssertionError("actual callback/reentrant/thread matrix did not finish")
            if expected is None: expected = result
            elif result != expected: raise AssertionError(f"callback result/destructor/SDK effects changed: {name}")
            if protected: check_reports(build, composed, archive, asset)


if __name__ == "__main__":
    main()
