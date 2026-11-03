"""Scalar/contribution composition and independent feature-removal consumers."""
import json

from cff_build import run
from preparation_cases import alternate
from cff_data_evidence import check_data_evidence


def configure_scalar_gates(args, configuration):
    if not args.scalars:
        return ()
    selected = ("integer-literals", "comparison-constants") if args.scalars == "all" else (args.scalars,)
    config = json.loads(configuration.read_text())
    for owner in ("contribution_compute", *(("contribution_hybrid",) if args.hybrid else ())):
        config["functions"][owner]["components"].update({name:
            "optional" if args.optimization == "O2" else "required" for name in selected})
    if args.hybrid:
        config["functions"]["contribution_hybrid_literal"] = {"coverage": "hybrid-eh", "components": {
            "runtime-contribution": "required", **{name: "optional" if args.optimization == "O2" else "required" for name in selected}},
            "contribution": {"selection": "original-edges" if args.automatic else "explicit-points"}}
    configuration.write_text(json.dumps(config))
    return selected


def check_scalar_gates(rows, selected, hybrid=False):
    for owner in ("contribution_compute", *(("contribution_hybrid", "contribution_hybrid_literal") if hybrid else ())):
        row = next(row for row in rows if row["function"] == owner)
        components = {item["component"]: item for item in row["components"]}
        for name in selected:
            if components[name]["applied"] < 1:
                raise AssertionError("actual scalar/contribution composition lacks " + owner + ":" + name)


def scalar_refusals(args, directory, transform, private, configuration, claimed, checker, build_image):
    config = json.loads(configuration.read_text())
    owner = "contribution_hybrid_literal" if args.hybrid else "contribution_compute"
    for component, reason in (("integer-literals", "lost state-dependent literals"),
            ("comparison-constants", "lost state-dependent comparison keys")):
        changed = json.loads(json.dumps(config))
        changed["functions"][owner]["components"][component] = "off"
        source, _ = alternate(args, directory, transform, private, changed, "erased-" + component)
        image = build_image("erased-" + component, source)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("removing scalar protection changed normal reference semantics")
        final = directory / ("erased-" + component + ".final.json")
        result = run([*checker, image, claimed, "--output", final], succeeds=False)
        if final.exists():
            raise AssertionError(f"{component} removal borrowed unrelated final evidence: {result.stderr}")
        # Removing a data layer can also alter a transition layer's emitted masks.
        # Isolate the production data proof as well as requiring full-image refusal.
        row = next(row for row in json.loads(claimed.read_text())["functions"] if row["function"] == owner)
        code = run([args.objdump, "-d", f"--disassemble-symbols={owner}", image]).stdout.lower()
        try: check_data_evidence(row, code)
        except SystemExit as error:
            if reason not in str(error): raise AssertionError(f"{component} removal failed another data proof: {error}") from error
        else: raise AssertionError(f"{component} removal borrowed unrelated data evidence")
    return 2 + scalar_loss_refusals(args, directory)


def scalar_loss_refusals(args, directory):
    source = directory / "scalar-loss.ll"
    source.write_text('''declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
define i32 @scalar_loss(ptr %lease, i32 %value) {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101)
  %dead = add i32 %value, 5
  %unused = icmp eq i32 %value, 42
  ret i32 %value
}
''')
    private = directory / "scalar-loss.private.json"
    private.write_text(json.dumps({"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 7,
        "domain": 11, "source": 17, "private_words": list(range(1, 9)), "owners": {"scalar_loss": 13}}))
    for component, missing in (("integer-literals", 2), ("comparison-constants", 1)):
        recipe, requests, requested, optimized = [directory / (component + suffix)
            for suffix in (".loss.json", ".loss.requests.json", ".loss.requested.ll", ".loss.optimized.ll")]
        config = {"schema_version": 1, "functions": {"scalar_loss": {"components": {
            "runtime-contribution": "required", component: "required"}}}}
        recipe.write_text(json.dumps(config))
        plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={recipe}"]
        run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
            "-verify-each", "-S", source, "-o", requested])
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", optimized])
        if "%dead =" in optimized.read_text() or "%unused =" in optimized.read_text():
            raise AssertionError("scalar loss fixture did not lose its independent source operations")
        for required in (True, False):
            config["functions"]["scalar_loss"]["components"][component] = "required" if required else "optional"
            recipe.write_text(json.dumps(config))
            report = directory / (component + (".strict" if required else ".optional") + ".loss.report.json")
            result = run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
                f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
                "-verify-each", "-disable-output", optimized], succeeds=not required)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == "scalar_loss")
            if required:
                if component + " required site" not in row.get("reason", "") or "did not survive ordinary optimization" not in row["reason"]:
                    raise AssertionError("lost scalar requirement failed outside original-site accounting")
            else:
                actual = next(item for item in row["components"] if item["component"] == component)
                if row["status"] != "transformed" or actual["applied"] != 0 or actual["optimized_away"] != missing:
                    raise AssertionError("optional lost scalar requests received false coverage")
    return 4
