"""Actual control/work erasures preserving the remaining source-gated CFG."""
import json
import re

from cff_build import run
from preparation_cases import alternate


def descriptor_refusals(args, directory, protected):
    original = protected.read_text()
    tag = re.search(r"!pyobf\.bogus\.guard !(\d+)", original)[1]
    malformed, changed = re.subn(r"(?m)^(!" + tag + r" = !\{)i32 1,", r"\g<1>i8 1,", original)
    if changed != 1: raise AssertionError("malformed descriptor did not change its actual version word")
    bad = directory / "bogus-malformed-descriptor.ll"; bad.write_text(malformed)
    run([args.opt, "-passes=verify", "-disable-output", bad])
    result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", bad], succeeds=False)
    if "descriptor is malformed" not in result.stderr: raise AssertionError("malformed descriptor failed outside its typed parser")
    config = directory / "bogus-reserved-input.json"
    config.write_text(json.dumps({"schema_version": 1, "functions": {"reserved": {}}}))
    for label, text in (("attribute", 'define i32 @reserved(i32 %x) "pyobf.bogus.controls"="1" { ret i32 %x }\n'),
            ("descriptor", 'define i32 @reserved(i32 %x) { ret i32 %x, !pyobf.bogus.guard !0 }\n!0 = !{i8 0}\n')):
        bad = directory / ("bogus-reserved-" + label + ".ll"); bad.write_text(text)
        run([args.opt, "-passes=verify", "-disable-output", bad])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}",
            "-passes=pyobf-native-cff", "-disable-output", bad], succeeds=False)
        if "reserved bogus control" not in result.stderr: raise AssertionError("reserved input failed outside the artifact boundary")
    return 3


def raw_clone_fallback(args, directory, transform, private, configuration, checker, build_image):
    config = json.loads(configuration.read_text())
    config["functions"]["contribution_compute"]["components"].update({"bogus-clones": "optional", "bogus-synthesis": "required"})
    # Mixed-provider quotas change original requests. Keep the base fixture's frozen
    # requests intact and collect an independent manifest for this different recipe.
    recipe, requests, requested = [directory / ("fallback-input" + suffix) for suffix in (".json", ".requests.json", ".ll")]
    recipe.write_text(json.dumps(config))
    run([args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={recipe}",
        "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
        "-verify-each", "-S", transform[-1], "-o", requested])
    fresh = [f"-pyobf-cff-requests-input={requests}" if str(item).startswith("-pyobf-cff-requests-input=") else item for item in transform]
    fresh[-1] = requested
    source, report = alternate(args, directory, fresh, private, config, "optional-raw-clone-fallback")
    row = next(row for row in report["functions"] if row["function"] == "contribution_compute")
    components = {item["component"]: item for item in row["components"]}
    if components["bogus-clones"]["applied"] != 0 or components["bogus-synthesis"]["applied"] < 1 or not row.get("bogus_control_contract_verified"):
        raise AssertionError("raw donor absence did not preserve honest optional-clone/synthesis coverage")
    binary = build_image("optional-raw-clone-fallback", source)
    if "gate-normal-completed" not in run([binary]).stdout:
        raise AssertionError("optional raw clone fallback changed normal source-gated behavior")
    claimed = directory / "optional-raw-clone-fallback.report.json"
    claimed.write_text(json.dumps(report))
    run([*checker, binary, claimed, "--output", directory / "optional-raw-clone-fallback.final.json"])
    print("raw required clone rejects absent donor; optional clone remains zero while actual source-gated synthesis fallback executes")


def bogus_refusals(args, directory, protected, report, binary, checker, build_image):
    payload = json.loads(report.read_text())
    row = next(row for row in payload["functions"] if row["function"] == "contribution_compute")
    row["bogus_control_contract_verified"] = False
    claimed, final = directory / "bogus-false-proof.json", directory / "bogus-false-proof.final.json"
    claimed.write_text(json.dumps(payload))
    rejected = run([*checker, binary, claimed, "--output", final], succeeds=False)
    if "lack compiler ownership proof" not in rejected.stderr or final.exists():
        raise AssertionError("false bogus-control proof escaped the final gate")
    original = protected.read_text()
    function = re.search(r"(?ms)^define [^\n]*@contribution_compute\(.*?^}", original)
    kinds = {tag: int(kind) for tag, kind in re.findall(r"(?m)^!(\d+) = !\{i32 1, i32 \d+, i32 ([12]), i32", original)}
    selected = {item["component"]: item["applied"] for item in row["components"]}
    count = 1 + (descriptor_refusals(args, directory, protected) if args.bogus == "bogus-synthesis" else 0)
    for component, kind, label in (("bogus-clones", 1, "bogus clone"), ("bogus-synthesis", 2, "bogus synthesis")):
        if not selected[component]: continue
        results = [value for value, tag in re.findall(r"(?m)^  store i32 (%[\w.$-]+), ptr [^\n]+!pyobf\.bogus\.work !(\d+)", function[0])
            if kinds.get(tag) == kind]
        predicates = [value for value, tag in re.findall(r"(?m)^  (%[\w.$-]+) = [^\n]+!pyobf\.bogus\.guard !(\d+)", function[0])
            if kinds.get(tag) == kind]
        if len(results) != selected[component] or len(predicates) != selected[component]:
            raise AssertionError("actual bogus descriptor/feature count differs from its planned claim")
        for erasure, reason in (("guard", "lost opaque transition products"), ("work", f"lost {label} coefficients")):
            changed = function[0]
            for value in predicates if erasure == "guard" else results:
                if erasure == "guard":
                    changed, replaced = re.subn(r"(select i1 )" + re.escape(value) + r"(, i32 )", r"\g<1>true\2", changed)
                else:
                    changed, replaced = re.subn(r"(?m)^(  " + re.escape(value) + r" = )xor i32 [^,\n]+, [^,\n]+(, !pyobf\.cff\.bogus-result !\d+.*)$",
                        r"\g<1>add i32 0, 0\2", changed)
                if replaced != 1: raise AssertionError(f"{component} {erasure} did not reach its exact real use")
            source = directory / (component + "-" + erasure + ".ll")
            source.write_text(original[:function.start()] + changed + original[function.end():])
            run([args.opt, "-passes=verify", "-disable-output", source])
            if erasure == "guard":
                result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
                    "-disable-output", source], succeeds=False)
                if "bogus control" not in result.stderr:
                    raise AssertionError("constant guard erasure failed outside the actual control proof")
            image = build_image(component + "-" + erasure, source)
            if "gate-normal-completed" not in run([image]).stdout:
                raise AssertionError("removing bogus protection changed normal reference semantics")
            final = directory / (component + "-" + erasure + ".final.json")
            result = run([*checker, image, report, "--output", final], succeeds=False)
            if reason not in result.stderr or final.exists():
                raise AssertionError(f"{component}/{erasure} borrowed unrelated final evidence: {result.stderr}")
            count += 1
    return count
