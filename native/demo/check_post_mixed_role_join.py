"""Check the actual mixed POST cross-artifact join and bypass refusals."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from post_role_join import verify_post_mixed_role_join  # noqa: E402
from reference_plan import parse_plan  # noqa: E402


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def refused(values):
    try:
        verify_post_mixed_role_join(*values)
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError("mixed POST accepted a substituted role/site/root artifact")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("parent_report", "parent_final", "parent_plan", "parent_image", "release_report",
                 "release_plan", "child_image", "child_final", "child_report", "private", "scoped",
                 "material", "mixed_plan"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    names = tuple(vars(args))
    raw = [getattr(args, name).read_bytes() for name in names]
    values = [raw[0], json.loads(raw[1]), parse_plan(raw[2]), *raw[3:]]
    joined = verify_post_mixed_role_join(*values)
    if (joined != values[1].get("post_role_join") or joined["individual_site_machine_verified"] is not True or
            len(joined["roles"]) != 2 or any(not 3 <= len(role["sites"]) <= 8 for role in joined["roles"])):
        raise AssertionError("actual mixed POST report lost a final owner/site join")

    changed = list(values)
    parent = json.loads(raw[0])
    parent["post_role_flow"]["roles"][0]["owner"] ^= 1
    changed[0] = encoded(parent)
    changed[1] = deepcopy(values[1])
    changed[1]["input_report_sha256"] = hashlib.sha256(changed[0]).hexdigest()
    changed[1]["owner_creators"]["compiler_report_sha256"] = changed[1]["input_report_sha256"]
    refused(changed)

    changed = list(values)
    child = json.loads(raw[8])
    child["post_child_flow"]["roles"][0]["site"] = 1
    changed[8] = encoded(child)
    child_final = json.loads(raw[7])
    child_final["input_report_sha256"] = hashlib.sha256(changed[8]).hexdigest()
    changed[7] = encoded(child_final)
    release_plan = json.loads(raw[5])
    release_plan["child_report_sha256"] = hashlib.sha256(changed[7]).hexdigest()
    changed[5] = encoded(release_plan)
    release = json.loads(raw[4])
    release["child_report_sha256"] = hashlib.sha256(changed[7]).hexdigest()
    changed[4] = encoded(release)
    refused(changed)

    changed = list(values)
    private = json.loads(raw[9])
    private["private_words"][0] ^= 1
    changed[9] = encoded(private)
    refused(changed)

    changed = list(values)
    plan = json.loads(raw[12])
    plan["owners"][0]["edges"][0]["label"] ^= 1
    changed[12] = encoded(plan)
    refused(changed)
    print("actual mixed POST parent/child join and role, site, root and plan refusals verified")


if __name__ == "__main__":
    main()
