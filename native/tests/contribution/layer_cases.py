"""Actual retained/final layer refusals, with other protections left in place."""
import json
import re

from cff_build import run

VALUE = r"(?:%[-a-zA-Z$._0-9]+|-?\d+)"


def strip_layer(text, owner, strategy, expected):
    function = re.search(r"(?ms)^define [^\n]*@" + owner + r"\([^\n]+\).*?^}", text)
    body = function[0]
    if strategy == "reachable-junk":
        pattern = rf"(?m)^(  %pyobf\.junk\.transition\d* = )xor i32 ({VALUE}), %pyobf\.junk\.correction\d*$"
        changed, count = re.subn(pattern, lambda hit: hit[1] + "add i32 " + hit[2] + ", 0", body)
    else:
        name = "opaque.choice" if strategy == "opaque-choices" else "decoy.pick"
        pattern = rf"(?m)^(  %pyobf\.{re.escape(name)}\d* = )select i1 {VALUE}, i32 ({VALUE}), i32 ({VALUE})$"

        def replace(hit):
            normal = hit[3]
            if strategy == "opaque-choices":
                choices = []
                for candidate, fake in ((hit[2], hit[3]), (hit[3], hit[2])):
                    if re.search(r"(?m)^  " + re.escape(fake) + r" = xor i32 " + re.escape(candidate) + r", -?\d+$", body):
                        choices.append(candidate)
                if len(choices) != 1: raise AssertionError("opaque erasure did not locate the independent normal arm")
                normal = choices[0]
            return hit[1] + "add i32 " + normal + ", 0"

        changed, count = re.subn(pattern, replace, body)
    if count != expected or not count:
        raise AssertionError(f"{strategy} erasure count {count} differs from actual planned sites {expected}")
    return text[:function.start()] + changed + text[function.end():]


def layer_refusals(args, directory, protected, report, binary, checker, build_image):
    # Each source optimization has a real consumer; group/automatic variants reuse these
    # grammar/final-evidence cases rather than recompiling equivalent mutants.
    owner = "contribution_hybrid" if args.hybrid else "contribution_compute"
    payload = json.loads(report.read_text())
    row = next(row for row in payload["functions"] if row["function"] == owner)
    if row.get("transition_layer_contract_verified") is not True:
        raise AssertionError("actual composed owner lacks compiler proof")
    row["transition_layer_contract_verified"] = False
    claimed, final = directory / "layer-false-proof.json", directory / "layer-false-proof.final.json"
    claimed.write_text(json.dumps(payload))
    result = run([*checker, binary, claimed, "--output", final], succeeds=False)
    if "lack compiler composition proof" not in result.stderr or final.exists():
        raise AssertionError("false layer-proof report escaped the final gate")
    selected = {item["component"]: item["applied"] for item in row["components"]}
    for strategy, reason in (("opaque-choices", "lost opaque transition products"),
            ("reachable-junk", "lost reachable junk coefficients"),
            ("decoy-transitions", "lost decoy transition coefficients")):
        source = directory / ("erased-" + strategy + ".ll")
        source.write_text(strip_layer(protected.read_text(), owner, strategy, selected[strategy]))
        run([args.opt, "-passes=verify", "-disable-output", source])
        result = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify",
            "-disable-output", source], succeeds=False)
        if "transition layer" not in result.stderr:
            raise AssertionError("layer removal failed outside retained graph verification")
        image = build_image("erased-" + strategy, source)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("erasing an entry-identity layer changed normal fixture behavior")
        final = directory / ("erased-" + strategy + ".final.json")
        result = run([*checker, image, report, "--output", final], succeeds=False)
        if reason not in result.stderr or final.exists():
            raise AssertionError(f"{strategy} erasure borrowed another component's final evidence: {result.stderr}")
    return 4
