"""Hybrid model, legal point and original-edge budget refusals."""
import json
import re

from cff_build import run


def hybrid_refusals(args, directory, source, configuration, private):
    original = source.read_text()
    config = json.loads(configuration.read_text())
    body = re.search(r"(?ms)^define [^\n]*@contribution_hybrid\([^\n]+\).*?^}", original)
    marker = re.search(r"(?m)^  call void @pyobf_native_contribution_site_v1[^\n]+", body[0])[0]
    blocks = re.split(r"(?m)(?=^[A-Za-z0-9_.-]+:)", body[0])
    pad = next(block for block in blocks if " = landingpad " in block)
    branch = re.search(r"(?m)^  (?:br |resume )[^\n]+", pad)
    if branch is None: raise AssertionError("hybrid source has no legal landingpad-header insertion point")
    inserted = pad[:branch.start()] + marker + "\n" + pad[branch.start():]
    bad_point = original.replace(pad, inserted, 1)
    variants = [
        (original.replace('target triple = "x86_64-w64-windows-gnu"', 'target triple = "x86_64-pc-windows-msvc"', 1), config,
         "hybrid-eh target model is not verified"),
        (original.replace("__gxx_personality_seh0", "__gxx_personality_other"), config,
         "hybrid-eh requires the Windows GNU C++ landingpad personality"),
        (bad_point, config, "explicit contribution point cannot use an EH pad header"),
    ]
    budget = json.loads(json.dumps(config))
    budget["functions"]["contribution_hybrid"]["contribution"] = {
        "selection": "original-edges", "minimum_percent": 100, "maximum_edges": 0}
    variants.append((original, budget, "cannot satisfy minimum count/density"))
    for index, (text, recipe, expected) in enumerate(variants):
        if index < 3 and text == original: raise AssertionError("hybrid refusal did not mutate its source")
        path, config_path, report, output = [directory / f"hybrid-refusal-{index}{suffix}" for suffix in (".ll", ".json", ".report.json", ".out.ll")]
        path.write_text(text); config_path.write_text(json.dumps(recipe))
        run([args.opt, "-passes=verify", "-disable-output", path])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", "-verify-each",
            f"-pyobf-cff-config={config_path}", f"-pyobf-cff-contribution-input={private}",
            f"-pyobf-cff-report={report}", "-S", path, "-o", output], succeeds=False)
        reasons = [row.get("reason", "") for row in json.loads(report.read_text())["functions"]] if report.exists() else []
        if expected not in result.stderr + "\n".join(reasons):
            raise AssertionError(f"hybrid refusal failed elsewhere: {expected}; {reasons}; {result.stderr[:400]}")
        if output.exists() and output.stat().st_size: raise AssertionError("unsupported hybrid combination emitted usable IR")
    return len(variants)
