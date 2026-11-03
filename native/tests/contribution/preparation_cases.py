"""Closed-marker frame inventory and real initializer feature-removal consumers."""
import json

from cff_build import run


def alternate(args, directory, transform, private, config, label):
    recipe, report, output = [directory / (label + suffix) for suffix in (".json", ".report.json", ".ll")]
    recipe.write_text(json.dumps(config))
    command = [f"-pyobf-cff-config={recipe}" if str(item).startswith("-pyobf-cff-config=") else item for item in transform]
    try:
        run([*command, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}", "-o", output])
    except AssertionError:
        if report.exists():
            failures = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                if row["selected"] and row["status"] != "transformed"]
            raise AssertionError(f"{label} transform failed: {failures}") from None
        raise
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-contribution-verify", "-disable-output", output])
    return output, json.loads(report.read_text())


def preparation_refusals(args, directory, transform, private, configuration, claimed, checker, build_image):
    config = json.loads(configuration.read_text())
    frames = json.loads(json.dumps(config))
    frames["functions"]["contribution_compute"]["components"] = {
        "runtime-contribution": "required", "external-calls": "required"}
    _, frame_report = alternate(args, directory, transform, private, frames, "closed-marker-frames")
    row = next(row for row in frame_report["functions"] if row["function"] == "contribution_compute")
    helpers = [row for row in frame_report["functions"] if row.get("generated_owner") == "contribution_compute"]
    count = next(item["applied"] for item in row["components"] if item["component"] == "external-calls")
    # The conditional fixture has exactly one real external identity call, three
    # closed point markers and one defined identity call. Markers cannot create helpers.
    if count != 1 or len(helpers) != 1 or not row["runtime_contribution"]["ir_binding_contract_verified"]:
        raise AssertionError("closed contribution markers entered external-frame candidate inventory")
    for component, reason in (("reference-routes", "lost state-dependent reference routes"),
            ("import-routes", "lost state-dependent reference routes"),
            ("indexed-locals", "lost indexed local address routes")):
        changed = json.loads(json.dumps(config))
        changed["functions"]["contribution_compute"]["components"][component] = "off"
        source, _ = alternate(args, directory, transform, private, changed, "erased-" + component)
        image = build_image("erased-" + component, source)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("removing a data initializer changed normal reference semantics")
        final = directory / ("erased-" + component + ".final.json")
        result = run([*checker, image, claimed, "--output", final], succeeds=False)
        if reason not in result.stderr or final.exists():
            raise AssertionError(f"{component} removal borrowed another component's evidence: {result.stderr}")
    return 4
