"""Run the production decoy CMake module without a real-payload target/dependency."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

from check_decoy_package import run
from decoy_test_support import inspect_package
from atomic_artifact import remove_artifact

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def fixture_directory(parent):
    directory = Path(tempfile.mkdtemp(prefix="decoy-build-", dir=parent))
    try:
        yield directory
    except BaseException as error:
        details = traceback.format_exc()
        result = getattr(error, "result", None)
        if result is not None:
            details += "\nComplete stdout:\n" + result.stdout + "\nComplete stderr:\n" + result.stderr
        (directory / "failure.log").write_text(details, encoding="utf-8")
        print(f"Retained failed decoy fixture: {directory}", file=sys.stderr)
        raise
    else:
        if directory.resolve().parent != parent.resolve() or not directory.name.startswith("decoy-build-"):
            raise AssertionError("decoy fixture cleanup escaped its owned parent")
        try:
            shutil.rmtree(directory)
        except OSError:
            print(f"Retained decoy fixture after cleanup failure: {directory}", file=sys.stderr)
            raise


def main():
    parser = argparse.ArgumentParser()
    for name in ("cmake", "ninja", "compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with fixture_directory(args.build_dir) as directory:
        host = directory / "entry.exe"
        run([args.compiler, "-std=c++17", "-O2", ROOT / "demo/decoy/smoke.cpp", "-o", host])
        for profile, ipo in (("none", False), ("O2", False), ("O2", True)):
            source = directory / (profile + ("-ipo" if ipo else "")); source.mkdir()
            build = source / "build"
            for name in ("payload.cpp", "compute.cpp", "handoff.hpp"):
                shutil.copyfile(ROOT / "demo/decoy" / name, source / name)
            recipe = source / "recipe.json"
            recipe.write_bytes((ROOT / "demo/recipes/decoy.json").read_bytes())
            values = {"PYOBF_NATIVE_CFF_SEED": "12345678", "Python3_EXECUTABLE": Path(sys.executable).as_posix(),
                "PYOBF_NATIVE_OPT_EXECUTABLE": args.opt.as_posix(), "PYOBF_NATIVE_LLVM_LINK_EXECUTABLE": args.llvm_link.as_posix(),
                "PYOBF_NATIVE_OBJDUMP_EXECUTABLE": args.objdump.as_posix()}
            text = 'cmake_minimum_required(VERSION 3.21)\nproject(decoy_fixture LANGUAGES CXX)\n'
            text += ''.join(f'set({key} "{value}")\n' for key, value in values.items())
            text += ('set(PYOBF_NATIVE_DEMO_DECOY ON CACHE BOOL "")\n'
                'set(PYOBF_NATIVE_DEMO_DECOY_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/payload.cpp;${CMAKE_CURRENT_SOURCE_DIR}/compute.cpp" CACHE STRING "")\n'
                'set(PYOBF_NATIVE_DECOY_CFF_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/recipe.json" CACHE FILEPATH "")\n'
                f'set(PYOBF_NATIVE_DECOY_CFF_SOURCE_OPT "{profile}" CACHE STRING "")\n'
                'add_library(pyobf_native_cff MODULE IMPORTED)\n'
                f'set_target_properties(pyobf_native_cff PROPERTIES IMPORTED_LOCATION "{args.plugin.as_posix()}")\n'
                f'include("{ROOT.as_posix()}/demo/cmake/DecoyConfigure.cmake")\n'
                f'include("{ROOT.as_posix()}/demo/cmake/DecoyPipeline.cmake")\n')
            (source / "CMakeLists.txt").write_text(text)
            configure = [args.cmake, "-S", source, "-B", build, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}",
                f"-DCMAKE_CXX_COMPILER={args.compiler}", f"-DCMAKE_INTERPROCEDURAL_OPTIMIZATION={'ON' if ipo else 'OFF'}"]
            run(configure)
            def compile_package():
                return run([args.cmake, "--build", build, "--target", "pyobf_native_demo_decoy_package", "-j", "2"])
            compile_package()
            image = build / "libpyobf_native_demo_decoy.dll"
            inspect_package(build, image); run([host, image])
            selected = [row["function"] for row in json.loads((build / "decoy.final.json").read_text())["functions"] if row["selected"]]
            assert set(selected) == {"pyobf_native_inner_entry", "pyobf_demo_decoy_compute"} and len(selected) == 2
            paths = [image, *(build / name for name in ("decoy.0.ll", "decoy.1.ll", "decoy.obj", "decoy.coverage.json",
                "decoy.final.json", "decoy.private.json", "decoy-material.private.json", "decoy_events_generated.hpp", "decoy_blob.hpp", "decoy.package.json"))]
            def snapshot():
                return {path.name: (hashlib.sha256(path.read_bytes()).digest(), path.stat().st_mtime_ns) for path in paths}
            initial = snapshot()
            assert "ninja: no work to do." in compile_package().stdout and snapshot() == initial
            compute = source / "compute.cpp"
            compute.write_text(compute.read_text().replace("return 101;", "return 104;"))
            compile_package(); inspect_package(build, image); run([host, image, 104])
            changed_source = snapshot()
            for name in ("decoy-material.private.json", "decoy_events_generated.hpp"):
                assert changed_source[name] == initial[name], "child-source changes rewrote an upstream root/header"
            assert changed_source[image.name][0] != initial[image.name][0]
            assert changed_source["decoy.private.json"][0] != initial["decoy.private.json"][0]
            handoff = source / "handoff.hpp"; handoff.write_text(handoff.read_text() + "\n// Header dependency fixture.\n")
            compile_package(); inspect_package(build, image); run([host, image, 104])
            changed_header = snapshot()
            for name in ("decoy-material.private.json", "decoy_events_generated.hpp"):
                assert changed_header[name] == initial[name], "child-header changes rewrote an upstream root/header"
            assert changed_header["decoy.0.ll"][1] > changed_source["decoy.0.ll"][1]
            assert changed_header["decoy.1.ll"] == changed_source["decoy.1.ll"]
            document = json.loads(recipe.read_text())
            document["functions"] = {"pyobf_native_inner_entry": {"budgets": {"max_body_blocks": 4096}}}
            recipe.write_text(json.dumps(document))
            compile_package(); inspect_package(build, image)
            changed_recipe = snapshot()
            for name in ("decoy-material.private.json", "decoy_events_generated.hpp"):
                assert changed_recipe[name] == initial[name], "child-recipe changes rewrote an upstream root/header"
            assert changed_recipe["decoy.private.json"][0] != changed_header["decoy.private.json"][0]
            remove_artifact(build / "decoy_blob.hpp")
            compile_package(); inspect_package(build, image)
            repacked = snapshot()
            assert repacked["decoy_blob.hpp"][0] != changed_recipe["decoy_blob.hpp"][0]
            assert all(repacked[name] == changed_recipe[name] for name in
                (image.name, "decoy.obj", "decoy.final.json", "decoy.private.json", "decoy_events_generated.hpp"))
            assert "ninja: no work to do." in compile_package().stdout and snapshot() == repacked
            for source_argument in ("", str(source / "missing.cpp"), str(compute) + ";" + str(compute)):
                run([*configure, f"-DPYOBF_NATIVE_DEMO_DECOY_SOURCES={source_argument}"], succeeds=False)
            assert snapshot() == repacked
            run([*configure, "-DPYOBF_NATIVE_DEMO_DECOY=OFF"])
            compile_disabled = run([args.cmake, "--build", build, "--target", "pyobf_native_demo_decoy_package"], succeeds=False)
            assert "unknown target" in compile_disabled.stderr + compile_disabled.stdout
            assert snapshot() == repacked
            print(f"decoy isolated source {profile}/parent IPO {ipo}: native entry, AEAD, source/header/recipe/missing-output rebuilds, no-change and invalid-source/OFF guards passed")


if __name__ == "__main__":
    main()
