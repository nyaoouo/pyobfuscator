"""LLVM-valid changes that must fail acquisition/dataflow validation."""
import json
import re

from cff_build import run


def graph_refusals(args, directory, protected):
    original = protected.read_text()
    owner = "contribution_hybrid" if args.hybrid else "contribution_region" if args.region else "contribution_compute"
    match = re.search(r"(?ms)^define [^\n]*@" + owner + r"\([^\n]+\).*?^}", original)
    body = match[0]
    query = re.search(r"(?m)^  (%[^ ]+) = call i32 @pyobf_native_contribution_word_v1\(([^\n]+)\)[^\n]*", body)
    name, line = query[1], query[0]
    current = re.search(r", i32 (%[^), ]+)\)", line)[1]
    source = re.search(r", i32 (-?\d+), i32 " + re.escape(current) + r"\)", line)[1]
    mutations = {
        "route": body.replace(line, line.replace(", i32 7,", ", i32 8,", 1), 1),
        "source": body.replace(line, line.replace(", i32 " + source + ", i32 " + current,
            ", i32 " + str(int(source) ^ 1) + ", i32 " + current, 1), 1),
        "frozen-current": body.replace(line, line.replace("i32 " + current, "i32 0", 1), 1),
        "untracked-query": body.replace(line, re.sub(r", !pyobf\.contribution\.query !\d+", "", line), 1),
        "unused-result": re.sub(r"(?m)( = xor i32 )" + re.escape(name) + r"(,)", r"\g<1>0\2", body, count=1),
        "canceled-result": re.sub(r"(?m)( = xor i32 )" + re.escape(name) + r", -?\d+",
            lambda hit: hit[1] + name + ", " + name, body, count=1),
        "unchecked-update": re.sub(r"(?m)^(  store i32 )%[^,]+(, [^\n]*!pyobf\.contribution\.transition !\d+[^\n]*)$",
            r"\g<1>0\2", body, count=1),
        "overflow-contract": body[:query.end()] + re.sub(r"\bmul i32 ([^\n]+), 2146121005",
            r"mul nuw i32 \1, 2146121005", body[query.end():], count=1),
        "missing-root": re.sub(r", !pyobf\.contribution\.root !\d+", "", body, count=1),
    }
    texts = {name: original[:match.start()] + changed + original[match.end():] for name, changed in mutations.items()}
    group = re.search(r"#\d+", body.splitlines()[0])[0]
    attributes = re.search(r"(?m)^attributes " + re.escape(group) + r" = \{[^\n]+", original)[0]
    texts["lost-function-binding"] = original.replace(attributes, attributes.replace('"pyobf.contribution.bound"', "", 1), 1)
    texts["wrong-inventory"] = original.replace(attributes, re.sub(r'"pyobf\.contribution\.count"="\d+"',
        '"pyobf.contribution.count"="0"', attributes, count=1), 1)
    for name, text in texts.items():
        if text == original: raise AssertionError(f"graph mutation {name} did not change IR")
        path = directory / (name + ".ll"); path.write_text(text)
        run([args.opt, "-passes=verify", "-disable-output", path])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", path], succeeds=False)
        if "contribution" not in result.stderr: raise AssertionError(f"graph refusal {name} failed outside contribution validation")
    return len(texts)


def input_refusals(args, directory, transform, private):
    original = json.loads(private.read_text())
    mutations = {}
    for field, value in (("schema_version", 3 if args.grouped else 2), ("provider", "absent"), ("routing_tag", 0),
            ("domain", -1), ("source", 2**32), ("owners", {}), ("owners", {"other": 13}),
            ("private_words", [1] * 7), ("private_words", [1] * 7 + [-1]),
            ("private_words", [1] * 7 + [True]), ("owners", {"contribution_compute": 0}),
            ("owners", {"contribution_compute": 13, "other": 13})):
        changed = dict(original); changed[field] = value; mutations[str(len(mutations))] = changed
    extra = dict(original); extra["unknown"] = 1; mutations["unknown"] = extra
    for name, changed in mutations.items():
        path = directory / ("input-" + name + ".json"); path.write_text(json.dumps(changed))
        output = directory / ("input-" + name + ".ll")
        result = run([*transform, f"-pyobf-cff-contribution-input={path}", "-o", output], succeeds=False)
        if "contribution" not in result.stderr: raise AssertionError("private-input refusal failed outside contribution validation")
        if output.exists() and output.stat().st_size: raise AssertionError("invalid private input emitted usable IR")
    result = run([*transform, "-o", directory / "absent-reference.ll"], succeeds=False)
    if "independent private owner reference" not in result.stderr: raise AssertionError("missing owner reference failed elsewhere")
    return len(mutations) + 1


def forwarded_query(original, owner=None):
    declaration = "\ndeclare i32 @contribution_forwarded_word(ptr, i32, i32, i32, i32, i32, i32) nounwind\n"
    if owner is not None:
        body = re.search(r"(?ms)^define [^\n]*@" + owner + r"\([^\n]+\).*?^}", original)
        changed = body[0].replace("call i32 @pyobf_native_contribution_word_v1(", "call i32 @contribution_forwarded_word(", 1)
        return original[:body.start()] + changed + original[body.end():] + declaration
    return original.replace("call i32 @pyobf_native_contribution_word_v1(", "call i32 @contribution_forwarded_word(", 1) + declaration


def source_refusals(args, directory, source, common, requests, private, configuration):
    original = source.read_text()
    mutations = {}
    helper = re.search(r"(?ms)^define [^\n]*@pyobf_native_contribution_word_v1\([^\n]+\).*?^}", original)
    changed = helper[0].replace("i32 @pyobf_native_contribution_word_v1", "i64 @pyobf_native_contribution_word_v1", 1)
    changed = re.sub(r"\brange\(i32 [^)]+\)\s*", "", changed, count=1)
    changed = re.sub(r"(?m)^  ret i32 ([^,\n]+)(.*)$",
        r"  %wide.result = zext i32 \1 to i64\n  ret i64 %wide.result\2", changed)
    mutations["helper-abi"] = (original[:helper.start()] + changed + original[helper.end():], "conflicting ABI")
    declaration = re.search(r"(?m)^declare [^\n]*void @pyobf_native_contribution_site_v1\([^\n]+", original)
    defined = "\ndefine void @pyobf_native_contribution_site_v1(ptr %lease, i32 %site) nounwind {\nentry:\n  ret void\n}\n"
    mutations["defined-marker"] = (original[:declaration.start()] + original[declaration.end():] + defined, "source marker declaration")
    mutations["escaped-marker"] = (original + "\n@escaped_marker = global ptr @pyobf_native_contribution_site_v1\n", "marker address escapes")
    zero = re.sub(r"(call void @pyobf_native_contribution_site_v1\([^\n]+, i32(?: noundef)? )101", r"\g<1>0", original, count=1)
    mutations["zero-point"] = (zero, "nonzero fixed i32")
    for name, (text, reason) in mutations.items():
        if text == original: raise AssertionError(f"source mutation {name} did not change IR")
        path = directory / (name + ".ll"); path.write_text(text)
        run([args.opt, "-passes=verify", "-disable-output", path])
        report = directory / (name + ".json")
        result = run([*common, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-disable-output", path], succeeds=False)
        reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
        if reason not in result.stderr + "\n".join(reasons):
            raise AssertionError(f"source refusal {name} failed for another reason: {reasons}")
    config = json.loads(configuration.read_text())
    variants = [({"coverage": "hybrid-eh", "components": {"runtime-contribution": "required"}},
                    "hybrid-eh requires the Windows GNU C++ landingpad personality"),
                ({"budgets": {"max_contribution_sites": 1}}, "max_contribution_sites")]
    if args.bogus == "bogus-synthesis" and args.automatic and not args.hybrid and args.optimization == "none" and not args.ssa_source:
        variants.append(({"components": {"runtime-contribution": "required", "bogus-clones": "required"}},
            "no self-contained wrapping i32 donor"))
    if args.composed == "all" and args.optimization == "O2":
        variants.append(({"components": {name: "required" for name in (
            "runtime-contribution", "opaque-choices", "reachable-junk", "decoy-transitions")}},
            "requested site did not survive ordinary optimization"))
    for index, (override, reason) in enumerate(variants):
        changed = json.loads(json.dumps(config)); changed["functions"]["contribution_compute"].update(override)
        path = directory / f"scope-{index}.json"; path.write_text(json.dumps(changed))
        report = directory / f"scope-{index}-report.json"
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={path}",
            "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-disable-output", source], succeeds=False)
        reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
        if reason not in result.stderr + "\n".join(reasons):
            raise AssertionError(f"unsupported contribution profile failed elsewhere: {reason}; {reasons}; {result.stderr[:400]}")
    # Preserve the former unsupported automatic/bogus case as acceptance in its
    # actual source fixture now that this composition is implemented.
    if args.bogus == "bogus-synthesis" and args.automatic and not args.hybrid and args.optimization == "none":
        changed = json.loads(json.dumps(config))
        changed["functions"]["contribution_compute"].update({
            "components": {"runtime-contribution": "required", "bogus-synthesis": "optional"},
            "contribution": {"selection": "original-edges"}})
        path = directory / "automatic-bogus-acceptance.json"; path.write_text(json.dumps(changed))
        report = directory / "automatic-bogus-acceptance.report.json"
        run([args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={path}",
            "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
            f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-disable-output", source])
        row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "contribution_compute")
        if row["status"] != "transformed" or not row.get("bogus_control_contract_verified") or not row["runtime_contribution"]["original_real_edge_density_verified"]:
            raise AssertionError("former automatic/bogus refusal did not earn actual control/source coverage")
        print("former automatic optional-bogus preparation refusal now has actual positive source/control coverage")
    return len(mutations) + len(variants)
