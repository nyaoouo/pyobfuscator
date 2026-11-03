"""Run empty and optimized-away source inventories through the actual CMake archive helper."""

from __future__ import annotations

import json
from pathlib import Path
import sys


def check_cmake(args, directory: Path, source: Path, config: Path, run, probe_script: Path,
                empty: str, folded_source: str, settings: dict) -> None:
    root = Path(__file__).resolve().parents[1]
    build = directory / "cmake empty build"
    configure = [str(args.cmake), "-S", str(root / "tests" / "archive_pipeline"), "-B", str(build),
        "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}", f"-DCMAKE_CXX_COMPILER={args.compiler}",
        f"-DPython3_EXECUTABLE={sys.executable}", f"-DNATIVE_ROOT={root}", f"-DPLUGIN={args.plugin}",
        f"-DPYOBF_NATIVE_OPT_EXECUTABLE={args.opt}", f"-DPYOBF_NATIVE_LLVM_LINK_EXECUTABLE={args.llvm_link}",
        f"-DOBJDUMP={args.objdump}", f"-DSOURCE_IR={source}", f"-DRECIPE={config}",
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"]
    empty_settings = dict(settings, functions={name: value for name, value in settings["functions"].items() if name != "folded"})
    source.write_text(empty, encoding="utf-8")
    config.write_text(json.dumps(empty_settings), encoding="utf-8")
    run(configure)
    run([str(args.cmake), "--build", str(build), "-j", "2"])
    if json.loads((build / "archive.plan.json").read_bytes())["records"] or (build / "archive.bin").read_bytes():
        raise AssertionError("originally empty CMake input generated phantom archive records")
    run([sys.executable, str(probe_script), "--probe", str(build / "asset_fixture.dll"), str(args.compiler.parent)])
    source.write_text(folded_source, encoding="utf-8")
    config.write_text(json.dumps(settings), encoding="utf-8")
    run([str(args.cmake), "--build", str(build), "-j", "2"])
    if (build / "archive.bin").read_bytes() or json.loads((build / "archive.plan.json").read_bytes())["records"]:
        raise AssertionError("empty CMake pipeline emitted an archive pool or phantom record")
    prepared = (build / "archive.prepared.ll").read_text()
    final = (build / "protected.ll").read_text()
    if "!pyobf.archive.empty" not in prepared or "!pyobf.archive." in final or "@__pyobf_archive_" in final:
        raise AssertionError("empty CMake handoff was lost, or private/gate material survived final CFF")
    report = json.loads((build / "coverage.json").read_bytes())["functions"]
    for row in report:
        if row["selected"]:
            archive = next(item for item in row["components"] if item["component"] == "constant-archive")
            if row["status"] != "transformed" or archive["applied"] or archive["eligible"]:
                raise AssertionError("empty CMake source credited archive work or lost selected support")
    folded = next(row for row in report if row["function"] == "folded")["archive_sources"]
    if (not folded["requested"] or folded["applied"] or folded["acquisitions"] or
            any(row["status"] != "optimized-away" for row in folded["sources"])):
        raise AssertionError("empty CMake handoff discarded the original optimized-away source requests")
    run([sys.executable, str(probe_script), "--probe", str(build / "asset_fixture.dll"), str(args.compiler.parent)])
    settings = json.loads(config.read_bytes())
    settings["functions"]["folded"]["components"]["constant-archive"] = "required"
    config.write_text(json.dumps(settings), encoding="utf-8")
    run([str(args.cmake), "--build", str(build)], succeeds=False)
    failure = next(row for row in json.loads((build / "coverage.json").read_bytes())["functions"]
                   if row["function"] == "folded")
    if failure.get("reason") != "required archive source request is absent or incomplete":
        raise AssertionError(f"required empty CMake inventory failed outside its intended boundary: {failure}")
    for value in settings["functions"].values(): value["components"]["constant-archive"] = "off"
    config.write_text(json.dumps(settings), encoding="utf-8")
    run([str(args.cmake), "--build", str(build), "-j", "2"])
    if json.loads((build / "archive.plan.json").read_bytes())["records"]:
        raise AssertionError("disabled archive scopes still produced protected records")
    report = json.loads((build / "coverage.json").read_bytes())["functions"]
    for row in report:
        if row["function"] in settings["functions"]:
            archive = next(item for item in row["components"] if item["component"] == "constant-archive")
            if archive["status"] != "disabled" or archive["applied"]:
                raise AssertionError("disabled empty source scopes were credited as archive protection")
    run([sys.executable, str(probe_script), "--probe", str(build / "asset_fixture.dll"), str(args.compiler.parent)])
