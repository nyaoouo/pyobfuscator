"""Actual detached DLL behavior and strict source-reference package refusals."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from payload_binding import OWNER, binding_recipe, requires_bound_child, validate_bound_child
from prepare_scope_material import read_material
from release_plan import parse_plan
from post_mixed_binding import validate_mixed_bound_child


def rejects(function):
    try: function()
    except ValueError: return
    raise AssertionError("invalid strict payload binding received packaging authority")


def main():
    parser = argparse.ArgumentParser()
    for name in ("probe", "image", "report", "plan", "header", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--profile", choices=("strict", "decoupled"), required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--scope-material", type=Path)
    parser.add_argument("--mixed-plan", type=Path)
    parser.add_argument("--release-material", type=Path)
    args = parser.parse_args()
    report = args.report.read_bytes()
    strict = args.profile == "strict"
    measured = args.scope_material is not None
    if measured and not strict: parser.error("measured binding requires the strict profile")
    if bool(args.mixed_plan) != bool(args.release_material) or (args.mixed_plan and not measured):
        parser.error("mixed binding needs a frozen plan, early material and measured scope")
    validation = {"provider": "measured-scope-v1", "scoped_material": read_material(args.scope_material)} if measured else {}
    def validate(private, evidence):
        if args.mixed_plan:
            return validate_mixed_bound_child(plan, private, evidence,
                material_bytes=args.release_material.read_bytes(),
                scoped_material=validation["scoped_material"],
                mixed_plan_bytes=args.mixed_plan.read_bytes())
        return validate_bound_child(plan, private, evidence, **validation)
    if requires_bound_child(report) != strict:
        raise AssertionError("actual child owner inventory differs from configured protection profile")
    for mode in ("detached", "wrong", "unavailable"):
        try:
            result = subprocess.run([args.probe, args.image, "measured" if measured else args.profile, mode], capture_output=True, text=True, timeout=3)
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            result = None
            output = error.stdout or b""
            if isinstance(output, bytes): output = output.decode(errors="replace")
        if mode == "detached":
            if result is None or result.returncode != 0 or "detached-profile-verified" not in output:
                raise AssertionError("actual detached export behavior differs from declared profile")
        elif measured:
            if (result is None or result.returncode != 0 or "legacy-admitted" not in output or
                    "payload-refused" not in output or "source-request" in output or "payload-completed" in output):
                raise AssertionError(f"measured child did not demonstrate rejection after legacy admission: "
                    f"{mode}, code={None if result is None else result.returncode}, output={output!r}, "
                    f"error={'' if result is None else result.stderr[:500]}")
        elif strict:
            if "legacy-admitted" not in output or "source-request" not in output or "payload-completed" in output:
                raise AssertionError(f"strict child bypassed its actual query or failed before the old admission boundary: "
                    f"{mode}, code={None if result is None else result.returncode}, output={output!r}, "
                    f"error={'' if result is None else result.stderr[:500]}")
        elif result is None or result.returncode != 0 or "payload-completed" not in output or "source-request" in output:
            raise AssertionError("decoupled fixture did not demonstrate its declared weaker boundary")
    if not strict:
        print("decoupled actual exports and admitted fake-source behavior verified; no runtime-bound claim")
        return
    if args.reference is None: raise AssertionError("strict verification needs actual compile references")
    private = args.reference.read_bytes()
    plan = parse_plan(args.plan.read_bytes())
    validate(private, report)
    if args.mixed_plan:
        reference = json.loads(private)
        changed = copy.deepcopy(reference)
        changed["private_words"], changed["measured_private_words"] = (
            changed["measured_private_words"], changed["private_words"])
        rejects(lambda: validate(json.dumps(changed).encode(), report))
        with tempfile.TemporaryDirectory(prefix="mixed-payload-binding-", dir=args.build_dir) as temporary:
            directory = Path(temporary)
            packed, record = directory / "candidate.hpp", directory / "candidate.record"
            packed.write_bytes(b"preserve-header"); record.write_bytes(b"preserve-record")
            wrong = directory / "wrong-private.json"
            wrong.write_text(json.dumps(changed), encoding="utf-8")
            command = [sys.executable, ROOT / "demo/pack_payload.py", args.image, packed, record,
                       args.plan, args.header, args.report, "--binding-provider", "measured-scope-v1",
                       "--scope-material", args.scope_material, "--mixed-plan", args.mixed_plan,
                       "--release-material", args.release_material]
            for extra, reason in (((), "mixed POST packaging needs measured scope and its private source"),
                                  (("--contribution-input", wrong),
                                   "private source differs from immutable roots or frozen plan")):
                result = subprocess.run([*map(str, command), *map(str, extra)],
                                        capture_output=True, text=True, timeout=10)
                if (result.returncode == 0 or reason not in result.stderr or
                        packed.read_bytes() != b"preserve-header" or
                        record.read_bytes() != b"preserve-record"):
                    raise AssertionError("mixed package bypassed its exact private source boundary")
        print("actual mixed detached/admitted-fake-source and private-root/package refusals verified")
        return
    reference, coverage = json.loads(private), json.loads(report)
    words = b"".join(word.to_bytes(4, "little") for word in reference["private_words"])
    if words in args.image.read_bytes():
        raise AssertionError("strict child contains its complete raw private fold table")
    private_mutations = [("schema_version", True), ("routing_tag", 0), ("domain", True),
        ("private_words", [0] * 8), ("owners", {OWNER: True})]
    private_mutations.append(("sources", []) if measured else ("source", None))
    for field, value in private_mutations:
        changed = copy.deepcopy(reference); changed[field] = value
        rejects(lambda changed=changed: validate(json.dumps(changed).encode(), report))
    if measured:
        for change in (lambda source: source["sources"][0].update(word_label=0),
                lambda source: source["bindings"][OWNER]["sites"].pop("701"),
                lambda source: source["bindings"][OWNER]["default"].update(mixing_domain="foreign")):
            changed = copy.deepcopy(reference); change(changed)
            rejects(lambda changed=changed: validate(json.dumps(changed).encode(), report))
    for field, value in (("private_input_sha256", "0" * 64), ("ir_binding_contract_verified", False),
            ("final_query_presence_verified", False), ("original_real_edge_density_verified", False),
            ("original_edges", {"original_edges": 0, "selected_edges": 0, "bound_edges": 0, "minimum_percent": 100})):
        changed = copy.deepcopy(coverage)
        row = next(row for row in changed["functions"] if row["function"] == OWNER)
        row["runtime_contribution"][field] = value
        rejects(lambda changed=changed: validate(private, json.dumps(changed).encode()))
    for field, value in (("selected", False), ("final_binary_verified", False), ("runtime_contribution", None)):
        changed = copy.deepcopy(coverage)
        next(row for row in changed["functions"] if row["function"] == OWNER)[field] = value
        rejects(lambda changed=changed: validate(private, json.dumps(changed).encode()))
    if measured:
        for change in (lambda proof: proof["sites"][0]["sources"][0].update(word_label=1),
                lambda proof: proof["sites"].clear(),
                lambda proof: proof.update(query_count=0)):
            changed = copy.deepcopy(coverage)
            proof = next(row["runtime_contribution"] for row in changed["functions"] if row["function"] == OWNER)
            change(proof)
            rejects(lambda changed=changed: validate(private, json.dumps(changed).encode()))
    rejects(lambda: binding_recipe({"schema_version": True}))
    rejects(lambda: binding_recipe({"schema_version": 1, "functions": {OWNER: {"components": {"runtime-contribution": "off"}}}}))
    base = {"schema_version": 1, "functions": {"pyobf_demo_compute": {"components": {"integer-literals": "required"}}}}
    if binding_recipe(base)["functions"][OWNER]["components"]["integer-literals"] != "required" or OWNER in base["functions"]:
        raise AssertionError("strict helper lost requested math protection or mutated the input recipe")
    with tempfile.TemporaryDirectory(prefix="payload-binding-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        packed, record = directory / "candidate.hpp", directory / "candidate.record"
        packed.write_bytes(b"preserve-header"); record.write_bytes(b"preserve-record")
        bad = directory / "wrong-reference.json"
        changed = copy.deepcopy(reference); changed["private_words"][0] ^= 1
        bad.write_text(json.dumps(changed), encoding="utf-8")
        equivalent = directory / "reformatted-reference.json"
        equivalent.write_text(json.dumps(reference, separators=(",", ":")), encoding="utf-8")
        if equivalent.read_bytes() == private: raise AssertionError("byte-identity negative did not change its input")
        command = [sys.executable, ROOT / "demo/pack_payload.py", args.image, packed, record, args.plan, args.header, args.report]
        if measured: command.extend(["--binding-provider", "measured-scope-v1", "--scope-material", args.scope_material])
        missing_reason = "measured payload requires its private source reference" if measured else "requires its actual contribution reference"
        for extra, reason in (([], missing_reason),
                (["--contribution-input", bad], "differs from the early release fold"),
                (["--contribution-input", equivalent], "lacks its exact private-reference binding proof")):
            result = subprocess.run([*command, *extra], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 or reason not in result.stderr or packed.read_bytes() != b"preserve-header" or record.read_bytes() != b"preserve-record":
                raise AssertionError("strict package omission/foreign-root refusal changed artifacts or failed elsewhere")
    print("actual strict detached/admitted-fake-source refusals and private-root/report/recipe/package controls verified")


if __name__ == "__main__":
    main()
