"""Actual scoped source body through existing request/transform/final gates."""
import json
import re
import struct
from pathlib import Path

from cff_build import run

ROOT = Path(__file__).resolve().parents[2]


def prepare(args, directory, includes):
    raw, requested, requests, optimized, protected, report, configuration, private = [
        directory / ("scope-body." + suffix) for suffix in
        ("ll", "requested.ll", "requests.json", "optimized.ll", "protected.ll", "coverage.json", "config.json", "private.json")]
    configuration.write_text(json.dumps({"schema_version": 1, "functions": {"measured_scope_body": {
        "components": {"runtime-contribution": "required", "external-calls": "required", "call-preparation": "required"}, "contribution": {
            "selection": "original-edges", "minimum_edges": 1, "minimum_percent": 100}}}}))
    private.write_text(json.dumps({"schema_version": 1, "provider": "measured-scope-v1", "routing_tag": 0x1020,
        "domain": 1, "source": 13, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
        "owners": {"measured_scope_body": 7}}))
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        *includes, ROOT / "tests/measurement/scope_body.cpp", "-o", raw])
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={configuration}"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}", "-S", raw, "-o", requested])
    source = requested
    if args.optimization == "O2":
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", source, "-o", optimized]); source = optimized
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
        f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", protected])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", protected])
    for label, update in (("wrong-provider", {"provider": "owned-context-v1"}),
            ("unknown-provider", {"provider": "missing-scope-provider"}), ("unsupported-groups", {"schema_version": 2})):
        changed_private = directory / (label + ".json")
        changed_private.write_text(json.dumps({**json.loads(private.read_text()), **update}))
        refused = directory / (label + ".ll")
        run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={changed_private}", "-S", source, "-o", refused], succeeds=False)
        if refused.exists(): raise AssertionError("refused scoped provider produced transformed output")
    rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
    authored = [row for row in rows if not row.get("generated")]
    if len(authored) != 1 or authored[0]["function"] != "measured_scope_body" or authored[0]["coverage_kind"] != "decision-flow" or any(row["status"] != "transformed" for row in rows):
        raise AssertionError("scoped measured body lost its actual selected decisions")
    helpers = [row for row in rows if row.get("generated_owner") == "measured_scope_body"]
    if len(helpers) != 1:
        raise AssertionError("measured source marker entered frame inventory or actual effect lost its owned frame")
    proof = authored[0]["runtime_contribution"]; edges = proof["original_edges"]
    if proof["provider"] != "measured-scope-v1" or not proof["ir_binding_contract_verified"] or not edges["density_verified"]:
        raise AssertionError("scoped source did not bind actual normal transitions")
    # Valid IR ABI substitutions must not borrow a frozen measured-source proof.
    text = protected.read_text()
    changed = text.replace("@pyobf_native_measured_contribution_word_v1", "@pyobf_native_contribution_word_v1")
    if changed == text: raise AssertionError("measured source query missing")
    mutant = directory / "scope-body.abi-mutant.ll"; mutant.write_text(changed)
    run([args.opt, "-passes=verify", "-disable-output", mutant])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", mutant], succeeds=False)
    query = re.search(r"(?m)^  (%[-\w.$]+) = call i32 @pyobf_native_measured_contribution_word_v1\([^\n]+", text)
    if query is None: raise AssertionError("scoped detached-value fixture lost its actual query")
    tail = re.sub(re.escape(query[1]) + r"(?![-\w.$])", "0", text[query.end():])
    detached = directory / "scope-body.detached.ll"; detached.write_text(text[:query.end()] + tail)
    run([args.opt, "-passes=verify", "-disable-output", detached])
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", detached], succeeds=False)
    result = {"source_ir": source}
    for role, source in (("protected", protected), ("plain", source)):
        obj = directory / ("scope-body." + role + ".obj")
        run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", obj]); result[role] = obj
    result["report"] = report
    return result
