"""Protect complete observer/reference/capture/context sources and execute real/fault consumers."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/context"))
from cff_build import protect, run, verify_image
from measure_observer import measure, digest, text_size


def check_key_oracle_bypass(args, directory, actual, report, includes, parent):
    source = (directory / "observer.protected.ll").read_text()
    matches = list(re.finditer(r"(?m)^define [^\n]*@[^\n(]*Snapshot5check[^\n(]*\([^\n]*\)[^\n]*\{", source))
    if len(matches) != 1: raise AssertionError("measured bypass lost exact Snapshot::check definition")
    header = matches[0].group()
    output = re.search(r"\bsret\(([^)]+)\)", header)
    slot = re.search(r" (%[-\w.$]+)(?=,|\))", header[output.end():]) if output else None
    if slot is None: raise AssertionError(f"measured bypass needs actual Windows sret lowering: {header}")
    end = source.index("\n}", matches[0].end()) + 2
    body = header + f"\n  store {output[1]} zeroinitializer, ptr {slot[1]}, align 8\n  ret void\n}}"
    mutated = directory / "oracle-bypass.ll"; mutated.write_text(source[:matches[0].start()] + body + source[end:])
    run([args.opt, "-passes=verify", "-disable-output", mutated])
    native = directory / "oracle-bypass.obj"; binary = directory / "oracle-bypass.exe"
    run([args.compiler, "-O0", "-fno-lto", "-c", mutated, "-o", native])
    run([args.compiler, "-std=c++17", "-O2", native, ROOT / "tests/measurement/measured_key_probe.cpp",
        *([ROOT / "tests/measurement/measured_contribution_cases.cpp", "-DPYOBF_TEST_MEASURED_CONTRIBUTION=1"] if args.measured_contribution else []),
        *args.backend, *includes, *parent, "-lbcrypt", "-o", binary])
    checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
    refused = directory / "oracle-bypass.final.json"
    run([*checker, binary, report, "--output", refused], succeeds=False)
    if refused.exists(): raise AssertionError("patched success oracle borrowed final protection evidence")
    command = [sys.executable, ROOT / "tests/measurement/check_measured_key.py", args.compiler,
        *(["--contribution"] if args.measured_contribution else [])]
    run([*command, actual, args.runtime_directory, directory, "--bypass"], succeeds=False)
    run([*command, binary, args.runtime_directory, directory, "--bypass"])
    print("forced Snapshot::check success still cannot recover keys for928 changed input bits in each live subject; ordinary bypass and patched final image refuse")
    return native


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--measure-output", type=Path)
    parser.add_argument("--measured-key", action="store_true")
    parser.add_argument("--measured-contribution", action="store_true")
    parser.add_argument("--measured-scope", action="store_true")
    for name in ("core", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    args.measured_contribution = args.measured_contribution or args.measured_scope
    args.measured_key = args.measured_key or args.measured_contribution
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    parent = ["-flto=thin"] if args.ipo else []
    test_flags = ["-DPYOBF_TEST_MEASURED_CONTRIBUTION=1"] if args.measured_contribution else []
    test_cases = [ROOT / "tests/measurement/measured_contribution_cases.cpp"] if args.measured_contribution else []
    driver_options = ["--contribution"] if args.measured_contribution else []
    if args.measured_scope:
        driver_options += ["--scope"]
        test_flags += ["-DPYOBF_TEST_MEASURED_SCOPE=1"]
        test_cases += [ROOT / "tests/measurement/scope_cases.cpp"]
    with tempfile.TemporaryDirectory(prefix="observer-cff-", dir=args.build_dir) as temporary:
        directory = Path(temporary); units = []
        for index, source in enumerate(args.core):
            output = directory / f"core-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                *includes, source, "-o", output])
            if "@llvm.global_ctors" in output.read_text(): raise AssertionError("observer introduced dynamic initialization")
            units.append(output)
        # Independent source inventory: Observer32 + Reference15 + Archive9 + Capture12 + Context42; scoped mode adds nine.
        count = 124 if args.measured_scope else 115 if args.measured_contribution else 113 if args.measured_key else 110
        combined, native, report = protect(args, directory, "observer", units, count)
        body = None
        if args.measured_scope:
            from scope_cff import prepare
            body = prepare(args, directory, includes)
        probe = "measured_key_probe.cpp" if args.measured_key else "observer_probe.cpp"
        driver = "check_measured_key.py" if args.measured_key else "check_observer.py"
        actual, faults = directory / "actual.exe", directory / "faults.exe"
        run([args.compiler, "-std=c++17", "-O2", native, ROOT / "tests/measurement" / probe,
            *test_cases, *([body["protected"]] if body else []), *test_flags, *args.backend, *includes, *parent, "-lbcrypt", "-o", actual])
        atomic = [source for source in args.backend if source.name == "atomic.cpp"]
        if len(atomic) != 1: raise AssertionError("observer faults need exact backend atomics")
        fault_sources = ("measured_key_faults.cpp", "observer_fixture.cpp", "failure_backend.cpp") if args.measured_key else (
            "observer_faults.cpp", "observer_fixture.cpp", "observer_policy.cpp", "observer_races.cpp", "observer_failures.cpp", "failure_backend.cpp")
        if args.measured_contribution: fault_sources += ("measured_contribution_faults.cpp",)
        if args.measured_scope: fault_sources += ("scope_faults.cpp",)
        run([args.compiler, "-std=c++17", "-O2", native, *[ROOT / "tests/measurement" / name for name in fault_sources],
            *test_flags, *atomic, *includes, *parent, "-o", faults])
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        verify_image(checker, actual, report, directory / "actual.final.json")
        verify_image(checker, faults, report, directory / "faults.final.json")
        if body: verify_image(checker, actual, body["report"], directory / "scope-body.final.json")
        run([sys.executable, ROOT / "tests/measurement" / driver, args.compiler, actual,
            args.runtime_directory, directory, *driver_options, *(["--scope-negative", "protected"] if body else [])])
        run([sys.executable, ROOT / "tests/measurement/check_observer_faults.py", faults, directory,
            "--runtime-directory", args.runtime_directory])
        plain = directory / "plain.exe"
        run([args.compiler, "-std=c++17", "-O2", combined, ROOT / "tests/measurement" / probe,
            *test_cases, *([body["plain"], ROOT / "src/contribution/scope_marker.cpp"] if body else []),
            *test_flags, *args.backend, *includes, *parent, "-lbcrypt", "-o", plain])
        run([sys.executable, ROOT / "tests/measurement" / driver, args.compiler, plain,
            args.runtime_directory, directory, *driver_options, *(["--scope-negative", "plain"] if body else [])])
        rejected = directory / "plain.final.json"
        run([*checker, plain, report, "--output", rejected], succeeds=False)
        if rejected.exists(): raise AssertionError("plain observer borrowed protected evidence")
        if body:
            rejected_body = directory / "plain-scope-body.final.json"
            run([*checker, plain, body["report"], "--output", rejected_body], succeeds=False)
            if rejected_body.exists(): raise AssertionError("plain scope body borrowed measured query evidence")
        if args.measured_key:
            mutant = check_key_oracle_bypass(args, directory, actual, report, includes, parent)
            if body:
                binary = directory / "scope-oracle-bypass.exe"
                run([args.compiler, "-std=c++17", "-O2", mutant, ROOT / "tests/measurement" / probe,
                    *test_cases, body["protected"], *test_flags, *args.backend, *includes, *parent, "-lbcrypt", "-o", binary])
                refused = directory / "scope-oracle-bypass.final.json"
                run([*checker, binary, report, "--output", refused], succeeds=False)
                if refused.exists(): raise AssertionError("scope oracle mutant borrowed complete final evidence")
                command = [sys.executable, ROOT / "tests/measurement" / driver, args.compiler]
                options = [args.runtime_directory, directory, "--contribution", "--scope", "--scope-digest-bypass"]
                run([*command, actual, *options], succeeds=False)
                run([*command, binary, *options])
                print("actual scoped AEAD rejects changed observed digest despite forged snapshot success; ordinary bypass and complete final proof refuse")
        if args.measure_output:
            if args.measured_key:
                run([sys.executable, ROOT / "tests/measurement" / driver, args.compiler, actual,
                    args.runtime_directory, directory, *driver_options, "--compare", plain, "--measure-output", args.measure_output])
                costs = json.loads(args.measure_output.read_text())
                costs.update({"optimization": args.optimization, "parent_ipo": args.ipo,
                    "source_ir_sha256": digest(combined), "protected_object_sha256": digest(native),
                    "final_report_sha256": digest(directory / "actual.final.json"),
                    "plain_text_bytes": text_size(args.objdump, plain), "protected_text_bytes": text_size(args.objdump, actual)})
                if body:
                    costs["scope_body"] = {"source_ir_sha256": digest(body["source_ir"]),
                        "native_object_sha256": digest(body["protected"]), "report_sha256": digest(body["report"]),
                        "final_report_sha256": digest(directory / "scope-body.final.json")}
                args.measure_output.write_text(json.dumps(costs, indent=2) + "\n")
            else: measure(args, directory, combined, native, report)
        print(f"{count} actual measured/observer/reference/archive/capture/context bodies: source{args.optimization}/IPO{args.ipo}, real+fault+plain refusal pass")


if __name__ == "__main__": main()
