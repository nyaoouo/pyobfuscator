"""Exercise two distinct measured Scope sources in one actual protected function."""
import argparse
import copy
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
from check_functions import prepare_fixture
from check_reference import WORDS
from code_subject import text_subject
from code_observation import reference_digest
from code_reference import build_reference
from measured_scope import build_material
from pe_layout import parse_image
from reference_identity import Identity, identity_bytes
from cff_contribution_groups import check_contribution_groups


def private_input():
    return {"schema_version": 2, "provider": "measured-scope-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {"site_scope_body": 7},
        "sources": [{"id": "first-code", "word_label": 13, "group": "code"},
            {"id": "second-code", "word_label": 29, "group": "code"}],
        "bindings": {"site_scope_body": {"default": {"sources": ["first-code"],
            "mixing_domain": "first-site", "groups": [{"id": "code", "minimum": 1}]},
            "sites": {"702": {"sources": ["second-code"], "mixing_domain": "second-site",
                "groups": [{"id": "code", "minimum": 1}]}}}}}


def check_report(report, expected):
    rows = [row for row in report["functions"] if row.get("selected") and not row.get("generated")]
    if len(rows) != 1 or rows[0].get("function") != "site_scope_body" or rows[0].get("status") != "transformed":
        raise AssertionError("two-site function is absent from actual CFF output")
    proof = rows[0]["runtime_contribution"]
    sites = proof.get("sites", [])
    check_contribution_groups(proof, 2, "site_scope_body")
    if (proof.get("provider") != "measured-scope-v1" or proof.get("scheme_version") != 2 or
            proof.get("query_count") != 2 or proof.get("generated_owner_independence_verified") is not False or
            proof.get("source_subset_contract_verified") is not True or
            sorted(site.get("label") for site in sites) != [701, 702]):
        raise AssertionError(f"actual two-site source proof is missing or overstated: "
            f"{proof.get('provider')}, {proof.get('scheme_version')}, {proof.get('query_count')}, "
            f"{proof.get('generated_owner_independence_verified')}, "
            f"{proof.get('source_subset_contract_verified')}, {[site.get('label') for site in sites]}")
    catalog = {source["id"]: source for source in expected["sources"]}
    for site in sites:
        rule = expected["bindings"]["site_scope_body"]["sites"].get(str(site["label"]),
            expected["bindings"]["site_scope_body"]["default"])
        source = catalog[rule["sources"][0]]
        actual = site.get("sources")
        if (site.get("mixing_domain") != rule["mixing_domain"] or actual != [{
                "id": source["id"], "word_label": source["word_label"], "encoding": 1,
                "group": source["group"], "class": "referenced-evidence",
                "sharing": "owner-independent", "use": "required-binding"}]):
            raise AssertionError("site report differs from independently supplied private policy")
    return rows[0]


def negative_compiler(args, directory, source, requests, configuration, private, protected):
    command = [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
        f"-pyobf-cff-config={configuration}", f"-pyobf-cff-requests-input={requests}"]
    for label, change, reason in (
            ("unknown-provider", lambda d: d["sources"][1].update(provider="missing-scope"), "unsupported provider/version"),
            ("provider-version", lambda d: d["sources"][1].update(provider_version=2), "unsupported provider/version"),
            ("two-per-site", lambda d: d["bindings"]["site_scope_body"]["sites"]["702"]["sources"].append("first-code"),
                "exactly one source"),
            ("missing-site", lambda d: d["bindings"]["site_scope_body"]["sites"].update({"999999":
                d["bindings"]["site_scope_body"]["sites"].pop("702")}), "point label was not retained")):
        data = copy.deepcopy(private_input()); change(data)
        candidate = directory / f"{label}.json"; candidate.write_text(json.dumps(data))
        output = directory / f"{label}.ll"
        report = directory / f"{label}.coverage.json"
        failure = run([*command, f"-pyobf-cff-contribution-input={candidate}",
            f"-pyobf-cff-report={report}", "-S", source, "-o", output], succeeds=False)
        if reason not in failure.stderr or output.exists() or report.exists():
            raise AssertionError(f"invalid policy escaped compiler gate: {label}")
    actual = protected.read_text()
    queries = list(re.finditer(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_measured_contribution_word_v1\([^\n]+", actual))
    if len(queries) != 2: raise AssertionError("actual protected body lost its two source queries")
    second = next((query for query in queries if "i32 702, i32 29," in query.group()), None)
    if second is None: raise AssertionError("second site did not query its distinct source label")
    mutants = {
        "wrong-query-source": actual[:second.start()] + second.group().replace("i32 29,", "i32 13,") + actual[second.end():],
        "wrong-query-abi": actual.replace("@pyobf_native_measured_contribution_word_v1", "@pyobf_native_contribution_word_v1"),
        "detached-second-result": actual[:second.end()] + re.sub(re.escape(second[1]) + r"(?![-\w.$])", "0", actual[second.end():]),
    }
    for label, changed in mutants.items():
        if changed == actual: raise AssertionError(f"mutation did not change actual protected IR: {label}")
        mutant = directory / f"{label}.ll"; mutant.write_text(changed)
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", mutant], succeeds=False)
    return directory / "detached-second-result.ll"


def actual_subject(args, directory, *, material_root=bytes(range(32))):
    _, _, dll = prepare_fixture(args.compiler, directory)
    data = dll.read_bytes(); image = parse_image(data)
    subject = text_subject(image, 0x901)
    identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), 7, subject.tag, 1, 2, 4096)
    metadata = directory / "metadata.bin"; metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
    reference = directory / "reference.bin"; reference.write_bytes(build_reference(data, subject, identity, WORDS))
    digest = reference_digest(data, image, subject, 7)
    material = directory / "material.bin"; material.write_bytes(build_material(material_root, WORDS, identity, digest))
    return [metadata, reference, material, dll]


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    for name in ("core", "backend"): parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    with tempfile.TemporaryDirectory(prefix="site-scope-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        raw, requested, requests, optimized, protected, report, configuration, private = [
            directory / ("site-scope." + suffix) for suffix in
            ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "config.json", "private.json")]
        configuration.write_text(json.dumps({"schema_version": 1, "functions": {"site_scope_body": {
            "components": {"runtime-contribution": "required", "external-calls": "required"},
            "contribution": {"selection": "explicit-points"}}}}))
        policy = private_input(); private.write_text(json.dumps(policy))
        run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
            *includes, ROOT / "tests/contribution/site_scope_body.cpp", "-o", raw])
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
        document = json.loads(report.read_text()); row = check_report(document, policy)
        detached = negative_compiler(args, directory, source, requests, configuration, private, protected)
        for label, mutation in (("source-label", lambda p: next(s for s in p["sites"] if s["label"] == 702)["sources"][0].update(word_label=13)),
                ("site-label", lambda p: next(s for s in p["sites"] if s["label"] == 702).update(label=703))):
            false = copy.deepcopy(document)
            fake = next(item["runtime_contribution"] for item in false["functions"]
                if item.get("function") == "site_scope_body")
            mutation(fake)
            try: check_report(false, policy)
            except (AssertionError, SystemExit): pass
            else: raise AssertionError(f"independent private policy admitted forged {label}")
        protected_obj, plain_obj = directory / "protected.obj", directory / "plain.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", protected_obj])
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", plain_obj])
        core = list(dict.fromkeys([*args.core, *args.backend]))
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        inputs = actual_subject(args, directory)
        for variant, body, extra in (("protected", protected_obj, []),
                ("plain", plain_obj, [ROOT / "src/contribution/scope_marker.cpp"])):
            binary = directory / f"{variant}.exe"
            run([args.compiler, "-std=c++17", "-O2", body,
                ROOT / "tests/contribution/site_scope_probe.cpp", *core, *extra, *includes,
                "-lbcrypt", "-o", binary])
            final = directory / f"{variant}.final.json"
            if variant == "protected": verify_image(checker, binary, report, final)
            else:
                run([*checker, binary, report, "--output", final], succeeds=False)
                if final.exists(): raise AssertionError("plain source borrowed protected final-image proof")
            if variant == "protected": run([binary, *inputs])
            for mode in ("swapped", "wrong-spec", "bad-snapshot", "bad-material"):
                denied = subprocess.run(list(map(str, [binary, *inputs, mode])), capture_output=True, text=True, timeout=15)
                expected = 0xe04f0702 if variant == "protected" else 91
                if denied.returncode & 0xffffffff != expected:
                    raise AssertionError(f"{variant} {mode} reached a wrong boundary: {denied.returncode}, {denied.stderr}")
        detached_obj, detached_image = directory / "detached.obj", directory / "detached.exe"
        run([args.compiler, "-O0", "-fno-lto", "-c", detached, "-o", detached_obj])
        run([args.compiler, "-std=c++17", "-O2", detached_obj,
            ROOT / "tests/contribution/site_scope_probe.cpp", *core, *includes,
            "-lbcrypt", "-o", detached_image])
        detached_final = directory / "detached.final.json"
        refusal = run([*checker, detached_image, report, "--output", detached_final], succeeds=False)
        if detached_final.exists() or "lost measured query return flow" not in refusal.stderr:
            raise AssertionError(f"second-site detached image escaped final proof: {refusal.stderr}")
        print(f"site-specific measured Scope labels 13/29, source-{args.optimization} actual CNG/final image, seven compiler, eight runtime and detached-image refusals pass")


if __name__ == "__main__": main()
