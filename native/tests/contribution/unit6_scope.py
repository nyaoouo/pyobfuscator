"""Run a source-detached measured body with ordinary and forced-success observers."""

import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement")]

import check_observer_cff
import grouped_scope_cff
from cff_build import run


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if "--measure-output" not in sys.argv:
        raise AssertionError("Unit6 Scope needs the existing paired actual-image cost driver")
    cost = Path(sys.argv[sys.argv.index("--measure-output") + 1])
    original = check_observer_cff.check_key_oracle_bypass
    detached_images = []

    def bypass(args, directory, actual, report, includes, parent):
        forced = original(args, directory, actual, report, includes, parent)
        source = directory / "grouped-detached.ll"
        if not source.exists():
            raise AssertionError("grouped measured Scope did not produce its valid-IR source detachment")
        native = directory / "grouped-detached.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", native])
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        driver = [sys.executable, ROOT / "tests/measurement/check_measured_key.py", args.compiler]
        options = [args.runtime_directory, directory, "--contribution", "--scope"]
        def link(label, observer, body):
            image = directory / f"grouped-{label}.exe"
            run([args.compiler, "-std=c++17", "-O2", observer,
                ROOT / "tests/measurement/measured_key_probe.cpp",
                ROOT / "tests/measurement/measured_contribution_cases.cpp",
                ROOT / "tests/measurement/scope_cases.cpp", body,
                "-DPYOBF_TEST_MEASURED_CONTRIBUTION=1", "-DPYOBF_TEST_MEASURED_SCOPE=1",
                *args.backend, *includes, *parent, "-lbcrypt", "-o", image])
            return image
        forced_control = link("forced-control", forced, directory / "grouped-scope.protected.obj")
        control = run([*driver, forced_control, *options], succeeds=False)
        if ("measured scope strict parent admission" not in control.stderr or
                "measured key: missing observation" not in control.stderr):
            raise AssertionError(f"forced-success control did not execute the intact scoped body: {control.stdout} {control.stderr}")
        for label, observer in (("ordinary", directory / "observer.obj"), ("forced-success", forced)):
            image = link(f"detached-{label}", observer, native)
            if label == "ordinary":
                for name, path in (("actual.exe", actual), ("detached.exe", image),
                        ("body-report.json", directory / "grouped-scope.coverage.json"),
                        ("detached.ll", source)):
                    shutil.copy2(path, args.build_dir / f"unit6-{args.optimization}-{name}")
            final = directory / f"grouped-detached-{label}.final.json"
            refused = run([*checker, image, directory / "grouped-scope.coverage.json",
                "--output", final], succeeds=False)
            if final.exists() or "lost measured query return flow" not in refused.stderr:
                raise AssertionError(f"{label} detached body borrowed grouped final evidence: {refused.stderr}")
            failed = run([*driver, image, *options], succeeds=False)
            if ("measured scope strict parent admission" in failed.stderr or
                    "actual scoped body result" not in failed.stderr and
                    "exit status: 3221225477" not in failed.stderr):
                raise AssertionError(f"{label} detached body failed outside protected effect: {failed.stderr}")
            detached_images.append({"observer": label, "image_sha256": digest(image),
                "linked_report_refused": True, "actual_body_refused": True})
        print("source-detached measured body rejects real execution and final-image proof with ordinary/forced-success observers")
        return forced

    check_observer_cff.check_key_oracle_bypass = bypass
    grouped_scope_cff.main()
    measured = json.loads(cost.read_text())
    if len(measured.get("subjects", [])) != 3 or measured.get("batches") != 7 or not detached_images:
        raise AssertionError("Unit6 Scope cost lacks three actual subjects or detached image evidence")
    measured["unit6_scope"] = {"input": "measured-scope-v1 schema2, one referenced source per site, same-source plain/protected pair",
        "detached_images": detached_images,
        "limit": "Function-invocation Scope hot cost and source-detached body only; not complete bootstrap startup, mixed sources, or D6 Unit6 closure"}
    cost.write_text(json.dumps(measured, indent=2) + "\n")


if __name__ == "__main__":
    main()
