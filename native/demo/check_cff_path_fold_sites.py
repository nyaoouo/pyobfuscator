"""Execute registered whole/hybrid fold sites and reject ABI/dataflow/final-image mutations."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
import path_fold_reference as fold
from path_fold_site_cases import CALL, DECL, PAD_HARNESS, body, guard_mutations, rejected_markers


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=60)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"fold-site command result differs: {command}\n{result.stdout}\n{result.stderr[:5000]}")
    return result


def expected_output(text):
    rows = text.splitlines()
    if len(rows) != 36: raise AssertionError("whole/hybrid/loop executions were skipped")
    for index, line in enumerate(rows):
        name, number, *words = line.split()
        number = int(number)
        if index < 32:
            if name != "whole" or number != index: raise AssertionError("whole transcript identity changed")
            state = fold.initialize(0x13579bdf)
            state = fold.advance(state, 0x101 if number & 1 else 0x102, 0x912bca71 if number & 1 else 0x01234567)
            state = fold.advance(state, 0x103, 0xa17e54c3)
        elif index < 35:
            if name != "hybrid" or number != index - 32: raise AssertionError("hybrid transcript identity changed")
            state = fold.initialize(0x2468ace0)
            state = fold.advance(state, 0x201 if number == 0 else 0x202, 0x8a7351bd if number == 0 else 0xc51a973d)
            if number != 2: state = fold.advance(state, 0x203, 0x715c3f91)
        else:
            if name != "loop" or number != 3: raise AssertionError("loop transcript identity changed")
            state = fold.initialize(0x3179bdf5)
            for _ in range(3): state = fold.advance(state, 0x301, 0x6173b9d1)
        if tuple(map(int, words)) != state: raise AssertionError("actual source execution differs from independent build reference")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--ipo", action="store_true")
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, requested, requests = (directory / name for name in ("source.ll", "requested.ll", "requests.json"))
        includes = ["-I", ROOT / "src", "-I", ROOT / "include"]
        run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
             *includes, ROOT / "tests/path_fold_sites.cpp", "-o", source])
        config = directory / "config.json"
        settings = {"schema_version": 1, "defaults": {"components": {"path-fold": "required"}},
                    "functions": {"fold_hybrid": {"coverage": "hybrid-eh"}}}
        config.write_text(json.dumps(settings))
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}"]
        configured = [*plugin, f"-pyobf-cff-config={config}"]
        run([*configured, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
             "-verify-each", "-S", source, "-o", requested])
        if "nomerge" not in requested.read_text() or "noduplicate" not in requested.read_text():
            raise AssertionError("pre-O2 marker merge/clone retention was not applied")
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        def executable(ir, name, *, ipo=False, reference=False, harness="path_fold_sites_harness.cpp"):
            obj, binary = directory / (name + ".obj"), directory / (name + ".exe")
            run([args.compiler, "-O0", "-fno-lto", "-c", ir, "-o", obj])
            native_support = [ROOT / "tests" / harness, *([ROOT / "src/path_fold/marker.cpp"] if reference else [])]
            run([args.compiler, "-std=c++17", "-O2", obj, *native_support, *includes,
                 *(["-flto=thin"] if ipo else []), "-o", binary])
            return binary
        plain = executable(source, "plain", reference=True)
        expected_output(run([plain]).stdout)
        for profile in ("none", "O2"):
            pre = requested
            if profile == "O2":
                pre = directory / "optimized.ll"
                run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", pre])
            transformed, report, final = (directory / (profile + suffix) for suffix in (".ll", ".json", ".final.json"))
            run([*configured, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
                 f"-pyobf-cff-report={report}", "-verify-each", "-S", pre, "-o", transformed])
            rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
            if len(rows) != 3: raise AssertionError("source function scope changed")
            for row in rows:
                component = next(item for item in row["components"] if item["component"] == "path-fold")
                sites = 2 if row["function"] == "fold_loop" else 4
                if (row["status"] != "transformed" or not row["requested"] or component["requested"] != sites or
                        component["applied"] != sites or component["unsupported"] or component["applied_roles"] != {"real": sites} or
                        component["applied_types"] != {"initialize32x8": 1, "advance32x8": sites - 1} or
                        not row["path_fold"]["ir_binding_contract_verified"]):
                    raise AssertionError("source-site/state binding accounting changed")
            run([*plugin, "-passes=pyobf-native-path-fold-verify", "-verify-each", "-disable-output", transformed])
            binary = executable(transformed, profile, ipo=args.ipo)
            expected_output(run([binary]).stdout)
            run([*checker, binary, report, "--output", final])
            linked = json.loads(final.read_text())
            for row in linked["functions"]:
                if row["selected"]:
                    component = next(item for item in row["components"] if item["component"] == "path-fold")
                    if not component["final_presence_verified"] or component["individual_sites_verified"]:
                        raise AssertionError("linked presence was lost or promoted to per-site proof")
            absent = directory / "plain-rejected.json"
            run([*checker, plain, report, "--output", absent], succeeds=False)
            if absent.exists(): raise AssertionError("plain image received a final success artifact")
            altered_report = directory / (profile + ".false-proof.json")
            altered = json.loads(report.read_text())
            for row in altered["functions"]:
                if row["selected"]: row["path_fold"]["ir_binding_contract_verified"] = False
            altered_report.write_text(json.dumps(altered))
            rejected_final = directory / (profile + ".false-proof.final.json")
            run([*checker, binary, altered_report, "--output", rejected_final], succeeds=False)
            if rejected_final.exists(): raise AssertionError("false IR proof received a final presence artifact")
            if profile == "none":
                mutants = list(guard_mutations(transformed.read_text()))
                if len(mutants) != 9: raise AssertionError("guard mutation inventory changed")
                for name, text in mutants:
                    mutant = directory / (name + ".ll")
                    mutant.write_text(text)
                    run([args.opt, "-passes=verify", "-disable-output", mutant])
                    rejected = run([*plugin, "-passes=pyobf-native-path-fold-verify", "-disable-output", mutant], succeeds=False)
                    if "path-fold" not in rejected.stderr: raise AssertionError("guard mutation failed at an unrelated boundary")
                    if name == "wrong-current-word":
                        wrong = executable(mutant, name)
                        if run([wrong], succeeds=False).returncode not in (10, 14):
                            raise AssertionError("state perturbation did not fail at the actual whole/loop fold result")
        # Valid IR at the boundary must fail before a successful output is produced.
        negative_config = directory / "negative-config.json"
        negative_config.write_text(json.dumps({"schema_version": 1, "defaults": {"components": {"path-fold": "required"}}}))
        for name, text, reason in rejected_markers():
            raw, bad_report, output = (directory / (name + suffix) for suffix in (".source.ll", ".coverage.json", ".output.ll"))
            raw.write_text(text)
            run([args.opt, "-passes=verify", "-disable-output", raw])
            case_config = negative_config
            if name == "eh-pad":
                case_config = directory / "eh-pad-config.json"
                case_config.write_text(json.dumps({"schema_version": 1, "defaults": {
                    "coverage": "hybrid-eh", "components": {"path-fold": "required"}}}))
            failed = run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={case_config}",
                "-pyobf-cff-markers=false", "-pyobf-cff-functions=probe", f"-pyobf-cff-report={bad_report}",
                "-verify-each", "-S", raw, "-o", output], succeeds=False)
            records = json.loads(bad_report.read_text())["functions"]
            owner = next(row for row in records if row["function"] == "probe")
            if reason not in owner.get("reason", "") or owner["status"] != "unsupported" or output.exists():
                raise AssertionError(f"wrong marker refusal: {name}: {owner.get('reason')} / {failed.stderr[:500]}")
        # EH normalization moves pad instructions into an ordinary continuation. An
        # originally unsupported optional site must not become a frozen binding obligation.
        pad_source = directory / "eh-pad.source.ll"
        pad_config, pad_ir, pad_report = (directory / ("optional-pad" + suffix)
            for suffix in (".config.json", ".ll", ".json"))
        pad_config.write_text(json.dumps({"schema_version": 1, "defaults": {
            "coverage": "hybrid-eh", "components": {"path-fold": "optional"}}}))
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={pad_config}",
             "-pyobf-cff-markers=false", "-pyobf-cff-functions=probe", f"-pyobf-cff-report={pad_report}",
             "-verify-each", "-S", pad_source, "-o", pad_ir])
        owner = next(row for row in json.loads(pad_report.read_text())["functions"] if row["function"] == "probe")
        component = next(item for item in owner["components"] if item["component"] == "path-fold")
        if owner["status"] != "transformed" or component["applied"] or component["unsupported"] != 1:
            raise AssertionError("optional pad gained a binding obligation after normalization")
        run([*plugin, "-passes=pyobf-native-path-fold-verify", "-verify-each", "-disable-output", pad_ir])
        pad_harness = directory / "pad-harness.cpp"
        pad_harness.write_text(PAD_HARNESS)
        pad_binary = executable(pad_ir, "optional-pad", reference=True, harness=pad_harness)
        output = run([pad_binary]).stdout.splitlines()
        if len(output) != 2: raise AssertionError("optional pad normal/unwind execution was skipped")
        for mode, line in enumerate(output):
            number, *words = map(int, line.split())
            if number != mode or tuple(words) != (fold.initialize(123) if mode else (0,) * 8):
                raise AssertionError("ordinary optional pad or original exception semantics changed")
        run([*checker, pad_binary, pad_report])
        region_source, region_output = directory / "region.ll", directory / "region-output.ll"
        region_source.write_text(DECL + "define void @probe(ptr %storage, i32 %word) {\n"
            "pre:\n  br label %start\nstart:\n  " + CALL + "\n  br label %out\nout:\n  ret void\n}\n")
        run([args.opt, "-passes=verify", "-disable-output", region_source])
        refused = run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={negative_config}",
            "-pyobf-cff-markers=false", "-pyobf-cff-region=probe:start:out", "-S", region_source,
            "-o", region_output], succeeds=False)
        if "component 'path-fold' does not support regions" not in refused.stderr or region_output.exists():
            raise AssertionError("path-fold explicit region scope was silently accepted")
        # Disabling or partially admitting the component must preserve ordinary source semantics.
        for mode in ("off", "optional", "partial"):
            ordinary, mode_config, mode_ir, mode_report = (directory / (mode + suffix)
                for suffix in (".source.ll", ".config.json", ".ordinary.ll", ".ordinary.json"))
            call = CALL.replace("i32 123", "i32 %word")
            declaration = DECL
            if mode == "partial":
                declaration += "declare void @pyobf_native_path_fold_step_v1(ptr, i32, i32) nounwind\n"
                call = CALL + "\n  call void @pyobf_native_path_fold_step_v1(ptr nonnull align 4 dereferenceable(32) %storage, i32 769, i32 %word) nounwind"
            ordinary.write_text(body(call, declaration))
            mode_config.write_text(json.dumps({"schema_version": 1, "defaults": {
                "components": {"path-fold": "off" if mode == "off" else "optional"}}}))
            run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={mode_config}", "-pyobf-cff-markers=false",
                 "-pyobf-cff-functions=probe", f"-pyobf-cff-report={mode_report}", "-verify-each", "-S", ordinary, "-o", mode_ir])
            owner = next(row for row in json.loads(mode_report.read_text())["functions"] if row["function"] == "probe")
            component = next(item for item in owner["components"] if item["component"] == "path-fold")
            if (component["applied"] != (1 if mode == "partial" else 0) or
                    component["unsupported"] != (0 if mode == "off" else 1) or
                    (mode == "off" and component["status"] != "disabled")):
                raise AssertionError("off/optional coverage falsely credited an unsupported marker")
            binary = executable(mode_ir, mode, reference=True, harness="path_fold_plain_harness.cpp")
            output = run([binary]).stdout.splitlines()
            if len(output) != 7: raise AssertionError("ordinary marker execution was skipped")
            for line in output:
                seed, *words = map(int, line.split())
                state = fold.initialize(seed) if mode != "partial" else fold.advance(fold.initialize(123), 769, seed)
                if tuple(words) != state: raise AssertionError("off/optional changed ordinary marker semantics")
            if mode == "partial": run([*checker, binary, mode_report])
            if mode == "off":
                missing_provider = directory / "missing-provider.exe"
                failed = run([args.compiler, "-std=c++17", directory / "off.obj",
                    ROOT / "tests/path_fold_plain_harness.cpp", *includes, "-o", missing_provider], succeeds=False)
                if "pyobf_native_path_fold_init_v1" not in failed.stderr or missing_provider.exists():
                    raise AssertionError("missing ordinary provider did not fail at marker linkage")
        # A lost original request and an excessive site budget cannot pass a required recipe.
        missing = directory / "lost-site.ll"
        original = requested.read_text()
        function = re.search(r"define [^\n]*@fold_whole\(.*?\n\}", original, re.S)
        if function is None: raise AssertionError("whole source owner is missing")
        first = next(line for line in function.group().splitlines(keepends=True) if "call void @pyobf_native_path_fold_init_v1" in line)
        missing.write_text(original.replace(first, "", 1))
        run([args.opt, "-passes=verify", "-disable-output", missing])
        lost_report = directory / "lost-site.json"
        run([*configured, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
             f"-pyobf-cff-report={lost_report}", "-disable-output", missing], succeeds=False)
        lost = next(row for row in json.loads(lost_report.read_text())["functions"] if row["function"] == "fold_whole")
        if "did not survive" not in lost.get("reason", ""): raise AssertionError("required request loss was hidden")
        limited = copy.deepcopy(settings)
        limited["defaults"]["budgets"] = {"max_path_fold_sites": 3}
        budget_config = directory / "budget.json"
        budget_config.write_text(json.dumps(limited))
        budget_report = directory / "budget-report.json"
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-config={budget_config}",
             f"-pyobf-cff-report={budget_report}", "-disable-output", source], succeeds=False)
        for row in json.loads(budget_report.read_text())["functions"]:
            if not row["selected"]: continue
            if row["function"] == "fold_loop":
                if row["status"] != "transformed": raise AssertionError("per-function budget rejected the smaller loop")
            elif "exceed max_path_fold_sites" not in row.get("reason", ""):
                raise AssertionError("site budget was not enforced")
        print(f"registered path-fold sites: whole/hybrid/loop36 executions, source none/O2, IPO={args.ipo}, 9 IR mutations, {len(rejected_markers())} marker refusals, optional-pad normal/unwind, region refusal, off/optional/partial, request loss and budget verified")


if __name__ == "__main__":
    main()
