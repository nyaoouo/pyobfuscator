"""Check a production retained POST plan and its fail-closed consumers."""

import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile


OWNERS = ("pyobf_demo_bound_compute", "pyobf_demo_protection_wrapper")


def run(command, success=True, reason=None):
    result = subprocess.run([str(item) for item in command], capture_output=True,
                            text=True, timeout=60)
    if (result.returncode == 0) != success or (reason and reason not in result.stderr):
        raise AssertionError(f"unexpected result {result.returncode} for {command}:\n{result.stderr}")


def cache(build, name):
    text = (build / "CMakeCache.txt").read_text()
    match = re.search(rf"(?m)^{re.escape(name)}:[^=]*=(.*)$", text)
    if not match:
        raise AssertionError(f"missing build option {name}")
    return match[1].strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("build", type=Path)
    parser.add_argument("retained", type=Path)
    args = parser.parse_args()
    build, retained = args.build.resolve(), args.retained.resolve()
    demo = build / "demo"
    plan = demo / "payload.post-mixed.edges.json"
    configuration = demo / "payload.binding.recipe.json"
    private = demo / "payload.binding.private.json"
    requests = demo / ("payload.archive.requests.json" if cache(build, "PYOBF_NATIVE_DEMO_ARCHIVE") == "ON"
                       else "payload.cff.requests.json")
    expected = (6, 3) if cache(build, "PYOBF_NATIVE_CFF_SOURCE_OPT") == "O2" else (7, 4)
    parsed = json.loads(plan.read_bytes())
    if (parsed["profile"] != "schema4-original-edges-post-two-v1" or
            [row["owner"] for row in parsed["owners"]] != list(OWNERS) or
            tuple(len(row["edges"]) for row in parsed["owners"]) != expected):
        raise AssertionError("production frozen plan has the wrong role or edge inventory")
    flags = [args.opt.resolve(), f"-load-pass-plugin={args.plugin.resolve().as_posix()}",
             "-pyobf-cff-functions=", f"-pyobf-cff-config={configuration.as_posix()}",
             f"-pyobf-cff-deep-functions={cache(build, 'PYOBF_NATIVE_CFF_DEEP_FUNCTIONS')}",
             f"-pyobf-cff-seed={cache(build, 'PYOBF_NATIVE_CFF_SEED')}",
             "-pyobf-cff-markers=true", "-pyobf-cff-strategy=relative-tree",
             f"-pyobf-cff-edge-owners={','.join(OWNERS)}"]

    def verify(candidate, input_ir=retained, transform=False, success=True, reason=None):
        command = [*flags, f"-pyobf-cff-edge-plan-input={candidate.as_posix()}"]
        if transform:
            command.extend((f"-pyobf-cff-contribution-input={private.as_posix()}",
                            f"-pyobf-cff-requests-input={requests.as_posix()}"))
        command.extend((f"-passes={'pyobf-native-cff' if transform else 'pyobf-native-cff-edge-plan-verify'}",
                        "-disable-output", input_ir.as_posix()))
        run(command, success, reason)

    verify(plan)
    with tempfile.TemporaryDirectory(prefix="post-real-plan-", dir=build) as temporary:
        directory = Path(temporary)
        for label, mutate in (
            ("missing-owner", lambda value: value["owners"].pop()),
            ("duplicate-owner", lambda value: value["owners"][1].update(owner=OWNERS[0])),
            ("swapped-owners", lambda value: value["owners"].reverse()),
            ("extra-owner", lambda value: value["owners"].append(copy.deepcopy(value["owners"][0]))),
            ("edge-label", lambda value: value["owners"][0]["edges"][0].update(label=1)),
            ("wrong-recipe", lambda value: value["owners"][1].update(recipe={})),
        ):
            altered = copy.deepcopy(parsed)
            mutate(altered)
            candidate = directory / f"{label}.json"
            candidate.write_text(json.dumps(altered))
            verify(candidate, success=False, reason="frozen plan differs")
        padded = directory / "padded.json"
        padded.write_bytes(plan.read_bytes() + b" ")
        verify(padded, success=False, reason="frozen plan differs")
        verify(padded, transform=True, success=False, reason="frozen plan differs")

        stale = directory / "stale.ll"
        stale.write_bytes(retained.read_bytes() + b"\ndeclare void @post_stale_ir_witness()\n")
        verify(plan, stale, success=False, reason="frozen plan differs")
        altered = json.loads(configuration.read_bytes())
        altered["functions"][OWNERS[1]]["contribution"]["minimum_percent"] = 99
        wrong_recipe = directory / "wrong-recipe-config.json"
        wrong_recipe.write_text(json.dumps(altered))
        command = [item for item in flags if not str(item).startswith("-pyobf-cff-config=")]
        run([*command, f"-pyobf-cff-config={wrong_recipe.as_posix()}",
             f"-pyobf-cff-edge-plan-input={plan.as_posix()}",
             "-passes=pyobf-native-cff-edge-plan-verify", "-disable-output",
             retained.as_posix()], success=False, reason="strict whole bounded")
    print(f"real POST {build.name} plan: {expected[0]}/{expected[1]} edges, exact and negative gates pass")


if __name__ == "__main__":
    main()
