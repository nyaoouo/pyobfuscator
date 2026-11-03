"""Isolated actual-bootstrap build, image and complete-release measurements."""

import argparse
import json
import os
from pathlib import Path
import tempfile

from bootstrap_measure_build import backend_objects, image, prepare, timed
from measure_cff import digest
import measured_artifacts


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "configuration", "build_dir", "record", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--decoy-configuration", type=Path)
    parser.add_argument("--backend-source", type=Path, action="append", required=True)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--seed", type=int, required=True)
    measured_artifacts.arguments(parser)
    args = parser.parse_args()
    measured_artifacts.bind(args, parser, ["pyobf_native_demo_outer", *(["pyobf_native_demo_outer_decoy",
        "pyobf_native_demo_outer_decoy_triggered"] if args.decoy_configuration else [])])
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="bootstrap-measure-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        objects, marker, backend_costs = backend_objects(args, directory, root)
        harness = directory / "measure.exe"
        _, harness_seconds = timed([args.compiler, "-std=c++17", "-O2", root / "demo/measure_bootstrap.cpp", "-o", harness])
        scenarios = [("real", "pyobf_native_demo_outer", 0, False)]
        if args.decoy_configuration:
            scenarios += [("failed-real-decoy", "pyobf_native_demo_outer_decoy", 1, True),
                          ("denied-decoy", "pyobf_native_demo_outer_decoy_triggered", 0, True)]
        profiles = {}
        for optimization in ("none", "O2"):
            rows = {}
            for label, name, corrupt, decoy in scenarios:
                source, transformed, coverage, prefix, record = prepare(args, directory, root, name, optimization, decoy=decoy)
                paths = {role: Path(str(prefix) + "-" + role + ".dll") for role in ("protected", "plain")}
                for role, path in paths.items():
                    record[role] = image(args, root, transformed if role == "protected" else source, path,
                                         objects, marker, coverage, name=name, protected=role == "protected",
                                         protected_emission=(paths["protected"].with_suffix(".obj"),
                                            Path(str(paths["protected"].with_suffix(".obj")) + ".ownership.json")))
                result, wall_seconds = timed([harness, paths["plain"], paths["protected"], corrupt, int(decoy)])
                record["timings"] = {key: float(value) for key, value in (line.split("=", 1) for line in result.stdout.splitlines())}
                record["measurement_wall_seconds"] = wall_seconds
                rows[label] = record
            profiles[optimization] = rows
        result = {"schema_version": 1, "plugin_sha256": digest(args.plugin), "harness_sha256": digest(root / "demo/measure_bootstrap.cpp"),
            "driver_sha256": digest(Path(__file__)), "builder_sha256": digest(root / "demo/bootstrap_measure_build.py"),
            "runtime_headers": {str(path.relative_to(root)): digest(path) for directory_name in ("include", "src")
                                for path in sorted((root / directory_name).rglob("*.hpp"))},
            "compiler": timed([args.compiler, "--version"])[0].stdout, "seed": args.seed,
            "real_child_sha256": digest(args.build_dir / "libpyobf_native_demo_inner.dll"),
            "record_sha256": digest(args.record), "real_plan_sha256": digest(args.build_dir / "release-plan.private.json"),
            "backend_costs": backend_costs, "harness_compile_seconds": harness_seconds,
            "scope": "Windows CLANG64 actual CNG/disk-backed loader/SDK; same-source/private-input pairs; warm alternating medians; no bound",
            "build_scope": "existing production combined IR; request/O2/CFF/codegen/link/data-only completion/final gate separately; excludes frontend/payload/plugin/toolchain build",
            "startup_scope": "warm outer load/symbol/one complete release/outer unload; includes inner file I/O/CNG/context/entry/teardown, not cold process startup",
            "repeated_scope": "outer retained; each call still performs complete context/key/inner load/entry/teardown; includes result validation, not body-only hot cost",
            "profiles": profiles}
        if args.decoy_configuration:
            result.update({"decoy_child_sha256": digest(args.build_dir / "libpyobf_native_demo_decoy.dll"),
                           "decoy_plan_sha256": digest(args.build_dir / "decoy.private.json")})
        result["release_binding"] = "pre-release-complete-observation-v1" if args.measured_inputs else "fold-only-v1"
        if args.post_inputs:
            result["post_subjects_sha256"] = digest(args.post_subjects) if args.post_subjects else None
            result["release_binding"] = "pre-and-post-complete-observation-v1" if args.post_pre_release else "post-complete-observation-v1"
            result["post_inputs"] = {name: digest(getattr(args, "post_" + name)) for name in
                ("material", "private", "child", "child_report", "release_plan")}
        if args.measured_inputs:
            result["measured_material_sha256"] = digest(args.measured_material)
            result["measured_references"] = {name: {"plan_sha256": plan.digest.hex(), "storage_object_sha256": digest(obj)}
                for name, (plan, obj) in args.measured_inputs[1].items()}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({optimization: {label: {"text_bytes": {role: row[role]["text_bytes"] for role in ("plain", "protected")},
            "timings": row["timings"]} for label, row in rows.items()} for optimization, rows in profiles.items()}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
