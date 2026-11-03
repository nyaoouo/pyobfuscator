"""Exercise owned and measured providers at different sites of one CFF function."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"), str(ROOT / "tools"), str(ROOT / "demo")]
from cff_build import run, verify_image
from cff_contribution_groups import check_contribution_groups
from site_scope_cff import actual_subject


def private_input():
    return {"schema_version": 3, "provider": "site-mixed-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {"mixed_site_body": 7},
        "sources": [{"id": "owned-context", "word_label": 13, "group": "context",
            "provider": "owned-context-v1", "provider_version": 1},
            {"id": "measured-code", "word_label": 29, "group": "code",
                "provider": "measured-scope-v1", "provider_version": 1}],
        "bindings": {"mixed_site_body": {"sites": {
            "701": {"sources": ["owned-context"], "mixing_domain": "owned-site",
                "groups": [{"id": "context", "minimum": 1}]},
            "702": {"sources": ["measured-code"], "mixing_domain": "measured-site",
                "groups": [{"id": "code", "minimum": 1}]}}}}}


def check_report(document, expected):
    rows = [row for row in document["functions"] if row.get("selected") and not row.get("generated")]
    if len(rows) != 1 or rows[0].get("function") != "mixed_site_body" or rows[0].get("status") != "transformed":
        raise AssertionError("mixed function is absent from actual CFF output")
    proof = rows[0]["runtime_contribution"]
    check_contribution_groups(proof, 2, "mixed_site_body")
    if (proof.get("scheme_version") != 3 or proof.get("query_count") != 2 or
            proof.get("generated_owner_independence_verified") is not False or
            proof.get("helper_counts") != {"owned-context-v1": 1, "measured-scope-v1": 1} or
            proof.get("private_input_sha256") != hashlib.sha256(json.dumps(expected).encode()).hexdigest()):
        raise AssertionError("mixed source report overstates or loses its two helpers")
    catalog = {source["id"]: source for source in expected["sources"]}
    for site in proof["sites"]:
        rule = expected["bindings"]["mixed_site_body"]["sites"].get(str(site["label"]))
        if rule is None: raise AssertionError("unexpected mixed site in report")
        source = catalog[rule["sources"][0]]
        if (site.get("provider") != source["provider"] or site.get("provider_version") != 1 or
                site.get("mixing_domain") != rule["mixing_domain"] or site.get("sources") != [{
                "id": source["id"], "word_label": source["word_label"], "encoding": 1,
                "group": source["group"], "class": "referenced-evidence" if source["provider"] == "measured-scope-v1" else "authenticated-material",
                "sharing": "owner-independent" if source["provider"] == "measured-scope-v1" else "context-material",
                "use": "required-binding", "provider": source["provider"], "provider_version": 1}]):
            raise AssertionError("mixed site report differs from independently supplied private policy")
    return rows[0]


def negative_compiler(args, directory, source, requests, configuration, protected):
    command = [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={configuration}", f"-pyobf-cff-requests-input={requests}"]
    for label, change, reason in (
            ("unknown-provider", lambda d: d["sources"][1].update(provider="missing-scope"), "unsupported provider/version"),
            ("provider-version", lambda d: d["sources"][1].update(provider_version=2), "unsupported provider/version"),
            ("same-site-mix", lambda d: d["bindings"]["mixed_site_body"]["sites"]["701"]["sources"].append("measured-code"),
                "site mixes provider references"),
            ("missing-rule", lambda d: d["bindings"]["mixed_site_body"]["sites"].pop("702"),
                "mixed owner needs both source providers"),
            ("unused-rule", lambda d: d["bindings"]["mixed_site_body"]["sites"].update({"703":
                copy.deepcopy(d["bindings"]["mixed_site_body"]["sites"]["702"])}), "markers must exactly match explicit site rules"),
            ("default-rule", lambda d: d["bindings"]["mixed_site_body"].update(default=copy.deepcopy(
                d["bindings"]["mixed_site_body"]["sites"]["701"])), "mixed owner needs explicit site rules")):
        data = copy.deepcopy(private_input()); change(data)
        candidate = directory / f"{label}.json"; candidate.write_text(json.dumps(data))
        output, report = directory / f"{label}.ll", directory / f"{label}.coverage.json"
        failed = run([*command, f"-pyobf-cff-contribution-input={candidate}",
            f"-pyobf-cff-report={report}", "-S", source, "-o", output], succeeds=False)
        if reason not in failed.stderr or output.exists() or report.exists():
            raise AssertionError(f"invalid mixed policy escaped compiler gate: {label}: {failed.stderr}")
    missing = private_input()
    sites = missing["bindings"]["mixed_site_body"]["sites"]
    sites["703"] = sites.pop("701")
    missing_input = directory / "missing-site-rule.json"; missing_input.write_text(json.dumps(missing))
    missing_output, missing_report = directory / "missing-site-rule.ll", directory / "missing-site-rule.coverage.json"
    failed = run([*command, f"-pyobf-cff-contribution-input={missing_input}",
        f"-pyobf-cff-report={missing_report}", "-S", source, "-o", missing_output], succeeds=False)
    row = next((row for row in json.loads(missing_report.read_text())["functions"]
        if row.get("function") == "mixed_site_body"), {}) if missing_report.exists() else {}
    if ("selection was not fully transformed" not in failed.stderr or missing_output.exists() or
            "mixed contribution marker has no explicit site rule" not in row.get("reason", "")):
        raise AssertionError(f"missing per-site rule escaped compiler gate: {failed.stderr}; {row}")
    original = source.read_text()
    wrong_marker = re.sub(r"call void @pyobf_native_contribution_site_v1\(",
        "call void @pyobf_native_measured_contribution_site_v1(", original, count=1)
    if wrong_marker == original: raise AssertionError("owned marker call was not retained")
    mismatch = directory / "wrong-marker.ll"; mismatch.write_text(wrong_marker)
    run([args.opt, "-passes=verify", "-disable-output", mismatch])
    wrong_report = directory / "wrong-marker.coverage.json"
    refused = run([*command, f"-pyobf-cff-contribution-input={directory / 'mixed-site.private.json'}",
        f"-pyobf-cff-report={wrong_report}",
        "-S", mismatch, "-o", directory / "wrong-marker.protected.ll"], succeeds=False)
    row = next((row for row in json.loads(wrong_report.read_text())["functions"]
        if row.get("function") == "mixed_site_body"), {}) if wrong_report.exists() else {}
    if ("selection was not fully transformed" not in refused.stderr or
            "marker differs from its configured provider" not in row.get("reason", "")):
        raise AssertionError(f"wrong per-site marker provider escaped compiler gate: {refused.stderr}")
    original_config = json.loads(configuration.read_text())
    original_config["functions"]["mixed_site_body"]["contribution"]["selection"] = "original-edges"
    automatic = directory / "automatic.json"; automatic.write_text(json.dumps(original_config))
    failure = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={automatic}", f"-pyobf-cff-requests-input={requests}",
        f"-pyobf-cff-contribution-input={directory / 'mixed-site.private.json'}",
        "-S", source, "-o", directory / "automatic.ll"], succeeds=False)
    if "mixed site providers require explicit contribution points" not in failure.stderr:
        raise AssertionError("mixed original-edge source selection escaped its unsupported gate")
    actual = protected.read_text()
    owned = next((match for match in re.finditer(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_contribution_word_v1\([^\n]+", actual)
        if "i32 701, i32 13," in match.group()), None)
    measured = next((match for match in re.finditer(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_measured_contribution_word_v1\([^\n]+", actual)
        if "i32 702, i32 29," in match.group()), None)
    if owned is None or measured is None: raise AssertionError("mixed protected body lost its two provider queries")
    mutants = {
        "wrong-owned-helper": actual[:owned.start()] + owned.group().replace(
            "@pyobf_native_contribution_word_v1", "@pyobf_native_measured_contribution_word_v1") + actual[owned.end():],
        "wrong-measured-helper": actual[:measured.start()] + measured.group().replace(
            "@pyobf_native_measured_contribution_word_v1", "@pyobf_native_contribution_word_v1") + actual[measured.end():],
        "wrong-owned-label": actual[:owned.start()] + owned.group().replace("i32 13,", "i32 29,") + actual[owned.end():],
        "detached-owned-result": actual[:owned.end()] + re.sub(re.escape(owned[1]) + r"(?![-\w.$])", "0", actual[owned.end():]),
        "detached-measured-result": actual[:measured.end()] + re.sub(re.escape(measured[1]) + r"(?![-\w.$])", "0", actual[measured.end():]),
    }
    for label, changed in mutants.items():
        if changed == actual: raise AssertionError(f"mutation did not change actual mixed IR: {label}")
        mutant = directory / f"{label}.ll"; mutant.write_text(changed)
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
            "-passes=pyobf-native-contribution-verify", "-disable-output", mutant], succeeds=False)
        if "contribution" not in refused.stderr:
            raise AssertionError(f"mixed IR mutation escaped proof: {label}: {refused.stderr}")
    return directory / "detached-owned-result.ll", directory / "detached-measured-result.ll"


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    for name in ("core", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="mixed-site-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        raw, requested, requests, optimized, protected, report, configuration, private = [
            directory / ("mixed-site." + suffix) for suffix in
            ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "config.json", "private.json")]
        configuration.write_text(json.dumps({"schema_version": 1, "functions": {"mixed_site_body": {
            "components": {"runtime-contribution": "required", "external-calls": "required"},
            "contribution": {"selection": "explicit-points"}}}}))
        policy = private_input(); private.write_text(json.dumps(policy))
        run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
            *includes, ROOT / "tests/contribution/mixed_site_body.cpp", "-o", raw])
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
            "-verify-each", "-S", raw, "-o", requested])
        source = requested
        if args.optimization == "O2":
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized]); source = optimized
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
            "-verify-each", "-S", source, "-o", protected])
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", protected])
        document = json.loads(report.read_text())
        check_report(document, policy)
        detached = negative_compiler(args, directory, source, requests, configuration, protected)
        for label, mutation in (("site-provider", lambda p: next(s for s in p["sites"] if s["label"] == 701).update(provider="measured-scope-v1")),
                ("source-provider", lambda p: next(s for s in p["sites"] if s["label"] == 702)["sources"][0].update(provider="owned-context-v1")),
                ("helper-count", lambda p: p["helper_counts"].update({"owned-context-v1": 2}))):
            false = copy.deepcopy(document)
            proof = next(row["runtime_contribution"] for row in false["functions"] if row.get("function") == "mixed_site_body")
            mutation(proof)
            try: check_report(false, policy)
            except (AssertionError, SystemExit): pass
            else: raise AssertionError(f"independent private policy admitted forged mixed {label}")
        protected_obj, plain_obj = directory / "protected.obj", directory / "plain.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", protected_obj])
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", plain_obj])
        core = list(dict.fromkeys([*args.core, *args.backend]))
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        inputs = actual_subject(args, directory)
        for kind, changed in zip(("owned", "measured"), detached):
            body, binary = directory / f"detached-{kind}.obj", directory / f"detached-{kind}.exe"
            run([args.compiler, "-O0", "-fno-lto", "-c", changed, "-o", body])
            run([args.compiler, "-std=c++17", "-O2", body,
                ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
                "-lbcrypt", "-o", binary])
            final = directory / f"detached-{kind}.final.json"
            refused = run([*checker, binary, report, "--output", final], succeeds=False)
            if final.exists() or f"lost {kind} query return flow" not in refused.stderr:
                raise AssertionError(f"detached {kind} return escaped final proof: {refused.stderr}")
        for variant, body, markers in (("protected", protected_obj, []),
                ("plain", plain_obj, [ROOT / "src/contribution/marker.cpp",
                    ROOT / "src/contribution/scope_marker.cpp"])):
            binary = directory / f"{variant}.exe"
            run([args.compiler, "-std=c++17", "-O2", body,
                ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *markers, *includes,
                "-lbcrypt", "-o", binary])
            final = directory / f"{variant}.final.json"
            if variant == "protected": verify_image(checker, binary, report, final)
            else:
                run([*checker, binary, report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain mixed body borrowed protected final evidence")
            if variant == "protected": run([binary, *inputs])
            for mode in ("wrong-owned", "wrong-measured", "bad-snapshot", "bad-material"):
                denied = subprocess.run(list(map(str, [binary, *inputs, mode])), capture_output=True, text=True, timeout=15)
                code = denied.returncode & 0xffffffff
                if variant == "plain" and code != 91:
                    raise AssertionError(f"plain {mode} did not reach its effect: {code}, {denied.stderr}")
                if variant == "protected" and code != 0xe04f0702:
                    raise AssertionError(f"protected {mode} crossed its source gate: {code}, {denied.stderr}")
                if variant == "protected": print(f"protected {mode} exit: 0x{code:08x}")
        print(f"mixed site source-{args.optimization} actual CNG/context, runtime refusals and final image pass")


if __name__ == "__main__": main()
