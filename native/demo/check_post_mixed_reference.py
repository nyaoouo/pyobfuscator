"""Verify the two-role reference producer against actual mixed build inputs."""

import argparse
import copy
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from post_reference_plan import create  # noqa: E402
from prepare_scope_material import read_material  # noqa: E402


def refused(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("mixed POST reference admitted a substituted input")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("material", "scoped", "plan", "private"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    material = args.material.read_bytes()
    scoped = read_material(args.scoped)
    plan = args.plan.read_bytes()
    private = args.private.read_bytes()
    reference = json.loads(private)
    for pre_release in (False, True):
        result = create(material, "pyobf_native_demo_outer_unfinalized", private, scoped,
                        pre_release=pre_release, mixed_plan=plan)
        if len(result.records) != (3 if pre_release else 2):
            raise AssertionError("mixed reference lost a parent or child role")
    changed = copy.deepcopy(reference)
    changed["private_words"][0] ^= 1
    refused(lambda: create(material, "pyobf_native_demo_outer_unfinalized", json.dumps(changed).encode(),
                           scoped, pre_release=False, mixed_plan=plan))
    changed = copy.deepcopy(reference)
    owner = next(iter(changed["bindings"]))
    site = next(iter(changed["bindings"][owner]["sites"]))
    changed["bindings"][owner]["sites"][site]["sources"] = ["post-owner-code"]
    refused(lambda: create(material, "pyobf_native_demo_outer_unfinalized", json.dumps(changed).encode(),
                           scoped, pre_release=False, mixed_plan=plan))
    changed_plan = json.loads(plan)
    changed_plan["owners"][0]["edges"][0]["label"] ^= 1
    refused(lambda: create(material, "pyobf_native_demo_outer_unfinalized", private,
                           scoped, pre_release=False, mixed_plan=json.dumps(changed_plan).encode()))
    print("mixed POST exact parent/child references and root/site/plan refusals passed")


if __name__ == "__main__":
    main()
