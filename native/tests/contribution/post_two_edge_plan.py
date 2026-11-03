"""Exercise the opt-in two-owner POST original-edge plan on retained IR."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent
OWNERS = ("pyobf_demo_bound_compute", "pyobf_demo_protection_wrapper")
PAIR = ",".join(OWNERS)
SELECTION = f"{PAIR},extra_sdk"


def run(command, success=True, reason=None):
    result = subprocess.run([str(item) for item in command], capture_output=True,
                            text=True, timeout=30)
    if (result.returncode == 0) != success or (reason and reason not in result.stderr):
        raise AssertionError(f"unexpected result {result.returncode} for {command}:\n{result.stderr}")
    return result


def source(shape="compute", extra_return=5):
    compute = (ROOT / f"source_mixed_bounded_{shape}.ll").read_text().replace(
        "@mixed_bounded_body", f"@{OWNERS[0]}")
    wrapper = (ROOT / "source_mixed_bounded_wrapper.ll").read_text().replace(
        "@mixed_bounded_body", f"@{OWNERS[1]}")
    return compute + "\n" + wrapper + f"\ndefine i32 @extra_sdk() {{\nentry:\n  ret i32 {extra_return}\n}}\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="post-two-plan-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        raw = directory / "input.ll"
        raw.write_text(source())
        config = directory / "config.json"
        recipe = {"components": {"runtime-contribution": "required"},
                  "contribution": {"selection": "original-edges", "minimum_edges": 3,
                                   "maximum_edges": 8, "minimum_percent": 100}}
        configuration = {"schema_version": 1,
                         "functions": {owner: copy.deepcopy(recipe) for owner in OWNERS}}
        config.write_text(json.dumps(configuration))
        retained = directory / "retained.ll"
        requests = directory / "requests.json"

        def flags(selection=SELECTION, owners=PAIR, configuration_path=config):
            return [args.opt, f"-load-pass-plugin={args.plugin}",
                    f"-pyobf-cff-config={configuration_path}",
                    f"-pyobf-cff-functions={selection}", "-pyobf-cff-markers=false",
                    f"-pyobf-cff-edge-owners={owners}"]

        run([*flags(), "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", raw,
             "-o", retained])

        def plan(label, input_ir=retained, selection=SELECTION, owners=PAIR,
                 configuration_path=config, success=True, reason=None):
            output = directory / f"{label}.json"
            run([*flags(selection, owners, configuration_path),
                 "-passes=pyobf-native-cff-edge-plan",
                 f"-pyobf-cff-edge-ir-input={input_ir}",
                 f"-pyobf-cff-edge-plan-output={output}", "-disable-output", input_ir],
                success, reason)
            if output.exists() != success:
                raise AssertionError(f"plan artifact status disagrees with {label}")
            return output

        frozen = plan("frozen")
        first = json.loads(frozen.read_text())
        if (set(first) != {"schema_version", "profile", "input_ir_encoding",
                           "input_ir_sha256", "owners"} or first["schema_version"] != 2 or
                first["profile"] != "schema4-original-edges-post-two-v1" or
                [owner["owner"] for owner in first["owners"]] != list(OWNERS)):
            raise AssertionError("two-owner plan schema or canonical owner order differs")
        if [len(owner["edges"]) for owner in first["owners"]] != [7, 4]:
            raise AssertionError("original normal-edge inventories differ")
        for owner in first["owners"]:
            edges = owner["edges"]
            if (len({edge["id"] for edge in edges}) != len(edges) or
                    len({edge["label"] for edge in edges}) != len(edges) or
                    not all(edge["id"].startswith("original.") for edge in edges)):
                raise AssertionError("retained edge identities are not unique and original")
        if frozen.read_bytes() != plan("repeat").read_bytes():
            raise AssertionError("identical retained module did not produce identical bytes")

        def verify(candidate=frozen, input_ir=retained, pass_name="pyobf-native-cff-edge-plan-verify",
                   success=True, reason=None):
            run([*flags(), f"-pyobf-cff-edge-plan-input={candidate}",
                 f"-passes={pass_name}", "-disable-output", input_ir], success, reason)

        verify()
        changed = directory / "changed.ll"
        changed.write_text(retained.read_text().replace("ret i32 5", "ret i32 6"))
        changed_plan = json.loads(plan("changed", changed).read_text())
        if (changed_plan["owners"] != first["owners"] or
                changed_plan["input_ir_sha256"] == first["input_ir_sha256"]):
            raise AssertionError("plan is not bound to full retained module IR")
        verify(input_ir=changed, success=False, reason="frozen plan differs")

        for label, mutation in (
            ("missing", lambda p: p["owners"].pop()),
            ("extra", lambda p: p["owners"].append(copy.deepcopy(p["owners"][0]))),
            ("duplicate", lambda p: p["owners"][1].update(owner=OWNERS[0])),
            ("swapped", lambda p: p["owners"].reverse()),
            ("label", lambda p: p["owners"][0]["edges"][0].update(label=1)),
            ("recipe", lambda p: p["owners"][0].update(recipe={})),
        ):
            tampered = copy.deepcopy(first)
            mutation(tampered)
            candidate = directory / f"tampered-{label}.json"
            candidate.write_text(json.dumps(tampered))
            verify(candidate, success=False, reason="frozen plan differs")
        verify(candidate, pass_name="pyobf-native-cff", success=False,
               reason="frozen plan differs")

        for label, selection, owners, reason in (
            ("wrong-order", SELECTION, ",".join(reversed(OWNERS)), "canonical role pair"),
            ("extra-list", SELECTION, PAIR + ",extra_sdk", "canonical role pair"),
            ("duplicate-list", SELECTION, PAIR + "," + OWNERS[1], "canonical role pair"),
        ):
            plan(label, selection=selection, owners=owners, success=False, reason=reason)

        missing_config = copy.deepcopy(configuration)
        del missing_config["functions"][OWNERS[1]]
        missing_config_path = directory / "missing.config.json"
        missing_config_path.write_text(json.dumps(missing_config))
        plan("missing-selection", selection=f"{OWNERS[0]},extra_sdk",
             configuration_path=missing_config_path, success=False, reason="POST owner is missing")

        incomplete = directory / "incomplete.ll"
        incomplete.write_text(retained.read_text().replace(f"@{OWNERS[1]}", "@removed_wrapper"))
        plan("missing-definition", incomplete, success=False, reason="definition is absent")
        plan("unstamped", raw, success=False, reason="source-retained terminator provenance")

        for label, owner, mutate in (
            ("percent", OWNERS[0], lambda c: c["contribution"].update(minimum_percent=99)),
            ("range", OWNERS[1], lambda c: c["contribution"].update(maximum_edges=7)),
            ("selection", OWNERS[0], lambda c: c["contribution"].update(selection="explicit-points")),
            ("runtime", OWNERS[1], lambda c: c["components"].clear()),
        ):
            altered = copy.deepcopy(configuration)
            mutate(altered["functions"][owner])
            candidate = directory / f"{label}.config.json"
            candidate.write_text(json.dumps(altered))
            plan(label, configuration_path=candidate, success=False, reason="strict whole bounded")
        extra_owner = copy.deepcopy(configuration)
        extra_owner["functions"]["extra_sdk"] = copy.deepcopy(recipe)
        candidate = directory / "extra-owner.config.json"
        candidate.write_text(json.dumps(extra_owner))
        plan("extra-owner", configuration_path=candidate, success=False,
             reason="extra selected original-edge owner")

        marker = directory / "marked.ll"
        marker.write_text(retained.read_text().replace(
            f"define i32 @{OWNERS[1]}",
            "declare void @pyobf_native_mixed_contribution_site_v1(ptr, ptr, i32)\n\n"
            f"define i32 @{OWNERS[1]}").replace(
            "  %choose = icmp", "  call void @pyobf_native_mixed_contribution_site_v1("
            "ptr %owned, ptr %measured, i32 1)\n  %choose = icmp"))
        plan("marker", marker, success=False, reason="explicit contribution marker")
        aliased_marker = directory / "aliased-marker.ll"
        aliased_marker.write_text(marker.read_text().replace(
            "declare void @pyobf_native_mixed_contribution_site_v1(ptr, ptr, i32)",
            "@marker_alias = alias void (ptr, ptr, i32), "
            "ptr @pyobf_native_mixed_contribution_site_v1\n"
            "define void @pyobf_native_mixed_contribution_site_v1(ptr, ptr, i32) "
            "{\nentry:\n  ret void\n}").replace(
            "call void @pyobf_native_mixed_contribution_site_v1(",
            "call void @marker_alias("))
        plan("aliased-marker", aliased_marker, success=False,
             reason="explicit contribution marker")

        ninth = directory / "ninth.ll"
        ninth.write_text(source("ninth"))
        ninth_retained = directory / "ninth-retained.ll"
        run([*flags(), "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-requests-output={directory / 'ninth-requests.json'}", "-S", ninth,
             "-o", ninth_retained])
        plan("ninth", ninth_retained, success=False,
             reason="three to eight retained normal edges")
        print("POST two-owner retained-IR plan and fail-closed negatives pass")


if __name__ == "__main__":
    main()
