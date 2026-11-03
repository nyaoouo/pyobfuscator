"""Check the actual POST parent/child final join and swapped-artifact refusals."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from post_role_join import verify_post_role_join
from reference_plan import parse_plan


def encode(document):
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rejected(label, inputs, phrase):
    try:
        verify_post_role_join(*inputs)
    except (ValueError, KeyError, TypeError) as error:
        if phrase not in str(error):
            raise AssertionError(f"{label} rejected for another reason: {error}") from error
    else:
        raise AssertionError(f"{label} passed the POST parent/child final join")


def main():
    parser = argparse.ArgumentParser()
    for name in ("parent_report", "parent_final", "parent_plan", "parent_image",
            "release_report", "release_plan", "child_image", "child_final", "child_report",
            "private", "scoped"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    paths = [getattr(args, name) for name in ("parent_report", "parent_final", "parent_plan",
        "parent_image", "release_report", "release_plan", "child_image", "child_final",
        "child_report", "private", "scoped")]
    parent_raw, parent_final_raw, plan_raw, parent_image, release_raw, release_plan_raw, \
        child_image, child_final_raw, child_raw, private, scoped = [path.read_bytes() for path in paths]
    plan = parse_plan(plan_raw)
    actual = json.loads(parent_final_raw)
    inputs = [parent_raw, actual, plan, parent_image, release_raw, release_plan_raw,
        child_image, child_final_raw, child_raw, private, scoped]
    joined = verify_post_role_join(*inputs)
    if (actual.get("post_role_join") != joined or joined["individual_site_machine_verified"] is not False or
            [row["site"] for row in joined["roles"]] != [702, 701]):
        raise AssertionError("actual final POST role/site inventory differs from its independent join")

    def parent_mutation(label, change, phrase):
        report = json.loads(parent_raw)
        final = deepcopy(actual)
        change(report)
        changed = encode(report)
        final["input_report_sha256"] = digest(changed)
        final["owner_creators"]["compiler_report_sha256"] = digest(changed)
        trial = list(inputs)
        trial[0], trial[1] = changed, final
        rejected(label, trial, phrase)

    parent_mutation("swapped roles", lambda report: report["post_role_flow"]["roles"].reverse(),
        "parent producer differs")
    parent_mutation("missing creator", lambda report: report["post_role_flow"]["roles"][0].update(
        creator="missing_creator"), "parent producer differs")
    parent_mutation("wrong owner", lambda report: report["post_role_flow"]["roles"][0].update(
        owner=report["post_role_flow"]["roles"][1]["owner"]), "parent producer differs")

    def move_both_offsets(report):
        role = report["post_role_flow"]["roles"][0]
        role["code_offset"] += 16
        role["material_offset"] += 16
    parent_mutation("same-distance offset shift", move_both_offsets, "parent producer differs")

    child_report = json.loads(child_raw)
    child_report["post_child_flow"]["roles"][0]["site"] = 703
    changed_child_raw = encode(child_report)
    child_final = json.loads(child_final_raw)
    child_final["input_report_sha256"] = digest(changed_child_raw)
    changed_child_final = encode(child_final)
    release_plan = json.loads(release_plan_raw)
    release_plan["child_report_sha256"] = digest(changed_child_final)
    release = json.loads(release_raw)
    release["child_report_sha256"] = digest(changed_child_final)
    trial = list(inputs)
    trial[4], trial[5], trial[7], trial[8] = encode(release), encode(release_plan), \
        changed_child_final, changed_child_raw
    rejected("child site remap", trial, "child Scope/site path")

    for label, index, changed, phrase in (
            ("stale parent compiler report", 0, parent_raw + b" ", "swapped or stale"),
            ("stale parent image", 3, parent_image + b"\0", "swapped or stale"),
            ("stale release identity", 4, encode({**json.loads(release_raw),
                "child_image_sha256": "0" * 64}), "swapped or stale"),
            ("stale child image", 6, child_image + b"\0", "private release child image/report identity differs"),
            ("stale child report", 7, child_final_raw + b" ", "private release plan belongs"),
            ("stale release plan", 5, encode({**json.loads(release_plan_raw),
                "child_image_sha256": "0" * 64}), "private release plan belongs"),
            ("stale private source", 9, private + b" ", "private-reference binding proof")):
        trial = list(inputs)
        trial[index] = changed
        rejected(label, trial, phrase)
    print("actual POST final join and role, slot, site and stale-artifact refusals verified")


if __name__ == "__main__":
    main()
