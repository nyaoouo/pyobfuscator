"""Exercise schema2 measured Scope groups through the existing measured runtime driver."""

import copy
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"), str(ROOT / "demo")]

import check_observer_cff
import scope_cff
from cff_build import run
from layer_cases import strip_layer
from cff_transition_evidence import check_transition_evidence
from cff_data_evidence import check_data_evidence


def grouped_input():
    return {"schema_version": 2, "provider": "measured-scope-v1", "routing_tag": 0x1020,
        "domain": 1, "private_words": list(int.from_bytes(bytes(range(index, index + 4)), "little")
            for index in range(0, 32, 4)), "owners": {"measured_scope_body": 7},
        "sources": [{"id": "measured-material", "word_label": 13, "group": "bootstrap"}],
        "bindings": {"measured_scope_body": {"default": {"sources": ["measured-material"],
            "mixing_domain": "measured-body", "groups": [{"id": "bootstrap", "minimum": 1}]}}}}


COMPOSED = ("opaque-choices", "reachable-junk", "decoy-transitions",
    "integer-literals", "comparison-constants")


def prepare(args, directory, includes, composed=False, artifacts=None):
    raw, requested, requests, optimized, protected, report, configuration, private = [
        directory / ("grouped-scope." + suffix) for suffix in
        ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "config.json", "private.json")]
    components = {"runtime-contribution": "required", "external-calls": "required", "call-preparation": "required"}
    if composed:
        components.update({name: "optional" if args.optimization == "O2" else "required"
            for name in COMPOSED})
    configuration.write_text(json.dumps({"schema_version": 1, "functions": {"measured_scope_body": {
        "components": components,
        "contribution": {"selection": "original-edges", "minimum_edges": 1, "minimum_percent": 100}}}}))
    data = grouped_input(); private.write_text(json.dumps(data))
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        *includes, ROOT / "tests/measurement/scope_body.cpp", "-o", raw])
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
        "-S", raw, "-o", requested])
    source = requested
    if args.optimization == "O2":
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized])
        source = optimized
    transform = [*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}"]
    run([*transform, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
        "-verify-each", "-S", source, "-o", protected])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
        "-disable-output", protected])
    if artifacts is not None:
        artifacts.update(args=args, directory=directory, includes=includes, source=source,
            transform=transform, private=private, configuration=configuration, protected=protected)
    rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"] and not row.get("generated")]
    if len(rows) != 1 or rows[0]["function"] != "measured_scope_body":
        raise AssertionError("grouped measured owner was not transformed")
    if composed:
        actual = {item["component"]: item["applied"] for item in rows[0]["components"]}
        missing = [name for name in COMPOSED if actual[name] < 1]
        if missing:
            raise AssertionError(f"measured Scope lacks retained composed sites: {missing}")
        if rows[0].get("transition_layer_contract_verified") is not True:
            raise AssertionError("measured Scope lacks transition composition proof")
    proof = rows[0]["runtime_contribution"]
    sites = proof["sites"]
    if (proof["provider"] != "measured-scope-v1" or proof["scheme_version"] != 2 or
            not proof["ir_binding_contract_verified"] or not proof["source_subset_contract_verified"] or
            proof["generated_owner_independence_verified"] is not False or
            proof["query_count"] != len(sites) or not sites or
            any(site["sources"] != [{"id": "measured-material", "word_label": 13, "encoding": 1,
                "group": "bootstrap", "class": "referenced-evidence", "sharing": "owner-independent",
                "use": "required-binding"}] for site in sites)):
        raise AssertionError("grouped measured report overstated or lost its actual source binding")
    body = protected.read_text()
    if body.count("call i32 @pyobf_native_measured_contribution_word_v1") != proof["query_count"]:
        raise AssertionError("grouped measured query count differs from protected IR")
    for label, change, reason in (
            ("unknown-provider", lambda d: d["sources"][0].update(provider="missing"), "unsupported provider/version"),
            ("provider-version", lambda d: d["sources"][0].update(provider_version=2), "unsupported provider/version"),
            ("unready-source", lambda d: d["sources"][0].update(earliest_readiness=5), "unknown field"),
            ("two-sources", lambda d: (d["sources"].append({"id": "second", "word_label": 29,
                "group": "bootstrap"}), d["bindings"]["measured_scope_body"]["default"]["sources"].append("second")),
                "exactly one source"),
            ("independence", lambda d: d["bindings"]["measured_scope_body"]["default"]["groups"][0].update(
                independent_evidence=True), "grouped independence is not proven")):
        candidate = copy.deepcopy(data); change(candidate)
        path = directory / f"grouped-{label}.json"; path.write_text(json.dumps(candidate))
        output = directory / f"grouped-{label}.ll"
        result = run([*transform, f"-pyobf-cff-contribution-input={path}", "-S", source, "-o", output], succeeds=False)
        if reason not in result.stderr or output.exists():
            raise AssertionError(f"grouped measured {label} did not refuse at source boundary")
    varied = copy.deepcopy(data)
    varied["sources"].append({"id": "second", "word_label": 29, "group": "bootstrap"})
    varied["bindings"]["measured_scope_body"]["sites"] = {"701": {
        "sources": ["second"], "mixing_domain": "other", "groups": [{"id": "bootstrap", "minimum": 1}]}}
    varied_input = directory / "grouped-different-label.json"
    varied_output = directory / "grouped-different-label.ll"
    varied_report = directory / "grouped-different-label.coverage.json"
    varied_input.write_text(json.dumps(varied))
    run([*transform, f"-pyobf-cff-contribution-input={varied_input}",
        f"-pyobf-cff-report={varied_report}", "-verify-each", "-S", source, "-o", varied_output])
    varied_row = next(row for row in json.loads(varied_report.read_text())["functions"]
        if row.get("function") == "measured_scope_body")
    varied_sites = varied_row["runtime_contribution"]["sites"]
    if (not any(site["label"] == 701 and site["sources"][0]["word_label"] == 29 for site in varied_sites) or
            any(site["label"] != 701 and site["sources"][0]["word_label"] != 13 for site in varied_sites)):
        raise AssertionError("explicit measured source policy did not override only its selected site")
    for label, changed in (("abi", body.replace("@pyobf_native_measured_contribution_word_v1",
            "@pyobf_native_contribution_word_v1")),):
        if changed == body: raise AssertionError("measured source query missing")
        mutant = directory / f"grouped-{label}.ll"; mutant.write_text(changed)
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", mutant], succeeds=False)
    query = re.search(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_measured_contribution_word_v1\([^\n]+", body)
    if query is None: raise AssertionError("grouped measured query missing")
    tail = re.sub(re.escape(query[1]) + r"(?![-\w.$])", "0", body[query.end():])
    mutant = directory / "grouped-detached.ll"; mutant.write_text(body[:query.end()] + tail)
    run([args.opt, "-passes=verify", "-disable-output", mutant])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
        "-disable-output", mutant], succeeds=False)
    result = {"report": report, "source_ir": source}
    for role, path in (("protected", protected), ("plain", source)):
        obj = directory / f"grouped-scope.{role}.obj"
        run([args.compiler, "-O0", "-fno-lto", "-c", path, "-o", obj]); result[role] = obj
    return result


def composed_refusals(artifacts, checker, report):
    args = artifacts["args"]
    directory = artifacts["directory"]
    row = next(row for row in json.loads(report.read_text())["functions"]
        if row["function"] == "measured_scope_body")
    counts = {item["component"]: item["applied"] for item in row["components"]}
    original = artifacts["protected"].read_text()
    config = json.loads(artifacts["configuration"].read_text())
    for component in COMPOSED:
        source = directory / f"composed-erased-{component}.ll"
        if component in ("opaque-choices", "reachable-junk", "decoy-transitions"):
            source.write_text(strip_layer(original, "measured_scope_body", component, counts[component]))
            run([args.opt, "-passes=verify", "-disable-output", source])
            refused = run([args.opt, f"-load-pass-plugin={args.plugin}",
                "-passes=pyobf-native-contribution-verify", "-disable-output", source], succeeds=False)
            if "transition layer" not in refused.stderr:
                raise AssertionError(f"{component} loss escaped retained transition verification")
        else:
            changed = copy.deepcopy(config)
            changed["functions"]["measured_scope_body"]["components"][component] = "off"
            recipe = directory / f"composed-erased-{component}.json"
            recipe.write_text(json.dumps(changed))
            command = [f"-pyobf-cff-config={recipe}" if str(item).startswith("-pyobf-cff-config=") else item
                for item in artifacts["transform"]]
            run([*command, f"-pyobf-cff-contribution-input={artifacts['private']}",
                "-verify-each", "-S", artifacts["source"], "-o", source])
            run([args.opt, f"-load-pass-plugin={args.plugin}",
                "-passes=pyobf-native-contribution-verify", "-disable-output", source])
        obj = directory / f"composed-erased-{component}.obj"
        image = directory / f"composed-erased-{component}.exe"
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", obj])
        run([args.compiler, "-std=c++17", "-O2", directory / "observer.obj",
            ROOT / "tests/measurement/measured_key_probe.cpp",
            ROOT / "tests/measurement/measured_contribution_cases.cpp",
            ROOT / "tests/measurement/scope_cases.cpp", obj,
            "-DPYOBF_TEST_MEASURED_CONTRIBUTION=1", "-DPYOBF_TEST_MEASURED_SCOPE=1",
            *args.backend, *artifacts["includes"], *(["-flto=thin"] if args.ipo else []),
            "-lbcrypt", "-o", image])
        code = run([args.objdump, "-d", "--disassemble-symbols=measured_scope_body", image]).stdout.lower()
        if component in ("integer-literals", "comparison-constants"):
            try: check_data_evidence(row, code)
            except SystemExit as error:
                if component == "integer-literals" and "lost state-dependent literals" not in str(error):
                    raise AssertionError(f"scalar loss failed in another proof: {error}") from error
                if component == "comparison-constants" and "lost state-dependent comparison keys" not in str(error):
                    raise AssertionError(f"scalar loss failed in another proof: {error}") from error
            else: raise AssertionError(f"{component} loss borrowed other data evidence")
        else:
            try: check_transition_evidence(row, code)
            except SystemExit as error:
                reason = {"opaque-choices": "lost opaque transition products",
                    "reachable-junk": "lost reachable junk coefficients",
                    "decoy-transitions": "lost decoy transition coefficients"}[component]
                if reason not in str(error):
                    raise AssertionError(f"transition loss failed in another proof: {error}") from error
            else: raise AssertionError(f"{component} loss borrowed other transition evidence")
        final = directory / f"composed-erased-{component}.final.json"
        run([*checker, image, report, "--output", final], succeeds=False)
        if final.exists(): raise AssertionError(f"{component} loss borrowed complete final evidence")


def main():
    composed = "--composed" in sys.argv
    if composed:
        sys.argv.remove("--composed")
    artifacts = {}
    scope_cff.prepare = lambda args, directory, includes: prepare(args, directory, includes, composed, artifacts)
    original = check_observer_cff.verify_image

    def verify(checker, binary, report, final):
        original(checker, binary, report, final)
        if report.name != "grouped-scope.coverage.json": return
        linked = json.loads(final.read_text())
        row = next(row for row in linked["functions"] if row["function"] == "measured_scope_body")
        if not row["runtime_contribution"]["final_query_presence_verified"]:
            raise AssertionError("linked grouped measured query was not verified")
        if composed:
            composed_refusals(artifacts, checker, report)
        base = json.loads(report.read_text())
        for label, change in (
                ("class", lambda p: p["sites"][0]["sources"][0].update({"class": "authenticated-material"})),
                ("sharing", lambda p: p["sites"][0]["sources"][0].update({"sharing": "context-material"})),
                ("independence", lambda p: p["sites"][0]["groups"][0].update(independent_evidence=True)),
                ("provider", lambda p: p.update(provider="owned-context-v1")),
                ("source-label", lambda p: p["sites"][0]["sources"][0].update(word_label=29)),
                ("query-count", lambda p: p.update(query_count=0))):
            candidate = copy.deepcopy(base)
            proof = next(row["runtime_contribution"] for row in candidate["functions"]
                if row["function"] == "measured_scope_body")
            change(proof)
            altered = final.parent / f"grouped-final-{label}.json"
            rejected = final.parent / f"grouped-final-{label}.result.json"
            altered.write_text(json.dumps(candidate))
            run([*checker, binary, altered, "--output", rejected], succeeds=False)
            if rejected.exists(): raise AssertionError(f"false grouped final report survived: {label}")
        if composed:
            for label, change in (
                    ("transition-proof", lambda row: row.update(transition_layer_contract_verified=False)),
                    ("scalar-width", lambda row: next(item for item in row["components"]
                        if item["component"] == "comparison-constants")["applied_types"].update(i32=999))):
                candidate = copy.deepcopy(base)
                selected = next(row for row in candidate["functions"] if row["function"] == "measured_scope_body")
                change(selected)
                altered = final.parent / f"composed-final-{label}.json"
                rejected = final.parent / f"composed-final-{label}.result.json"
                altered.write_text(json.dumps(candidate))
                run([*checker, binary, altered, "--output", rejected], succeeds=False)
                if rejected.exists(): raise AssertionError(f"false composed final report survived: {label}")

    check_observer_cff.verify_image = verify
    check_observer_cff.main()


if __name__ == "__main__":
    main()
