"""Tamper the complete two-owner POST final input before linked-image analysis."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(ROOT / "tests/contribution")]

from cff_joint_machine_evidence import DIRECT, MEASURED, OWNED, _instructions  # noqa: E402
from cff_post_mixed_final import _sites, verify_post_mixed_child  # noqa: E402
from linked_machine_mutations import _replace, _retarget_call  # noqa: E402
from payload_binding import OWNER, WRAPPER  # noqa: E402
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402
from post_mixed_binding import PROFILE, mixed_private_reference  # noqa: E402


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def fixture():
    material = {"schema_version": 1, "seed": 11,
                "events": {role: {"tag": index * 2 + 21, "word": index * 2 + 22}
                           for index, role in enumerate(("environment", "support", "release"))}}
    recipe = {"strategy": "relative-tree", "coverage": "whole",
              "contribution": {"selection": "original-edges", "minimum_edges": 3,
                               "maximum_edges": 8, "minimum_percent": 100},
              "components": [{"component": "runtime-contribution", "requirement": "required"}]}
    plan = {"schema_version": 2, "profile": PROFILE, "input_ir_encoding": "llvm-module-print-v1",
            "input_ir_sha256": "1" * 64,
            "owners": [{"owner": owner, "recipe": recipe,
                        "edges": [{"id": f"{owner}:edge:{index}", "label": base + index,
                                   "successor_index": index % 2} for index in range(count)]}
                       for owner, base, count in ((OWNER, 101, 7), (WRAPPER, 201, 4))]}
    plan_bytes = encoded(plan)
    scoped = bytes(range(32))
    private = mixed_private_reference(material, 123, scoped, plan_bytes)
    private_bytes = encoded(private)
    rows = []
    for item in plan["owners"]:
        owner = item["owner"]
        count = len(item["edges"])
        sites = _sites(private, owner)
        proof = {"scheme_version": 4, "provider": "source-mixed-v1",
                 "acquisition": "original-edges-and-explicit-points",
                 "joint_helper_contract": "source-mixed-context-v1",
                 "ir_binding_contract_verified": True, "source_subset_contract_verified": True,
                 "cross_provider_owner_binding_verified": False,
                 "generated_owner_independence_verified": False,
                 "individual_sites_verified": False,
                 "private_input_sha256": hashlib.sha256(private_bytes).hexdigest(),
                 "sites": sites, "query_count": sum(len(site["sources"]) for site in sites),
                 "helper_counts": {"owned-context-v1": sum(len(site["sources"]) - 1 for site in sites),
                                   "measured-scope-v1": count},
                 "original_real_edge_density_verified": True,
                 "original_edges": {"basis": "retained-cff-input-normal-successor-edges",
                                    "original_edges": count, "selected_edges": count, "bound_edges": count,
                                    "physical_selected_edges": count, "coalesced_selected_edges": 0,
                                    "explicit_points": 0, "minimum_edges": 3, "maximum_edges": 8,
                                    "minimum_percent": 100, "excluded_unwind_edges": 0,
                                    "generated_edges_in_denominator": 0, "density_percent": 100,
                                    "density_verified": True, "alias_contract_verified": True,
                                    "edges": [{"id": edge["id"], "canonical": edge["id"],
                                               "point": edge["label"], "canonical_point": edge["label"],
                                               "successor": edge["successor_index"],
                                               "dispatch_state": edge["label"],
                                               "selected": True, "status": "bound"}
                                              for edge in item["edges"]]}}
        rows.append({"function": owner, "selected": True, "status": "transformed",
                     "strategy": "relative-tree", "coverage_kind": "decision-flow",
                     "effective_recipe": recipe,
                     "components": [{"component": "runtime-contribution", "applied": count}],
                     "runtime_contribution": proof})
    rows.append({"function": "pyobf_demo_post_payload", "selected": True,
                 "status": "transformed", "strategy": "relative-tree"})
    report = {"original_edge_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
              "functions": rows}
    return {"image": b"PE", "report": report, "report_bytes": encoded(report),
            "private_bytes": private_bytes, "plan_bytes": plan_bytes,
            "material_bytes": encoded(material), "scoped_material": scoped,
            "codes": {OWNER: "compute code", WRAPPER: "wrapper code"},
            "helper_codes": {OWNED: "owned code", MEASURED: "measured code"}}


def refuse(values, label):
    try:
        verify_post_mixed_child(**values)
    except ValueError:
        return
    raise AssertionError(f"accepted tampered {label}")


def _real_refuse(command, output, reason):
    output.write_text("stale accepted output", encoding="ascii")
    process = subprocess.run([*map(str, command), "--output", str(output)],
                             capture_output=True, text=True, timeout=60)
    if (process.returncode == 0 or output.exists() or
            "Traceback" in process.stderr or not process.stderr.strip()):
        raise AssertionError(f"{reason} did not fail closed: {process.stderr}")


def _unwind_push_mutation(image, layout, entry):
    directory, size = data_directory(layout, 3)
    table = struct.iter_unpack("<III", read_rva(image, layout, directory, size))
    starts = [unwind for start, _, unwind in table if start == entry - layout.preferred_base]
    if len(starts) != 1:
        raise AssertionError("compute lacks one exact PE unwind record")
    unwind = starts[0]
    header = read_rva(image, layout, unwind, 4)
    codes = read_rva(image, layout, unwind + 4, header[2] * 2)
    pushes = [index for index in range(header[2]) if codes[index * 2 + 1] == 0x60]
    if len(pushes) != 1:
        raise AssertionError("compute unwind lost its unique saved RSI")
    rva = unwind + 4 + pushes[0] * 2 + 1
    section = rva_section(layout, rva, 1, logical=True)
    offset = section.raw_offset + rva - section.rva
    changed = bytearray(image)
    if changed[offset] != 0x60:
        raise AssertionError("unwind mutation no longer addresses PE data")
    changed[offset] = 0x30  # Describe a saved RBX while the code saves RSI.
    return bytes(changed)


def real_cases(directory, objdump, expect_saved_rsi):
    artifacts = directory / "demo"
    binary = artifacts / "libpyobf_native_demo_inner.dll"
    report = artifacts / "payload.cff.coverage.json"
    plan = artifacts / "payload.post-mixed.edges.json"
    private = artifacts / "payload.binding.private.json"
    material = artifacts / "release-material.private.json"
    scoped = artifacts / "payload.scope-material.private.bin"
    checker = [sys.executable, str(ROOT / "demo/check_linked_cff.py"), str(objdump),
               str(binary), str(report), "--post-mixed-plan", str(plan),
               "--post-mixed-private", str(private), "--post-mixed-material", str(material),
               "--post-mixed-scoped", str(scoped)]
    with TemporaryDirectory(prefix="post-mixed-final-", dir=directory) as temporary:
        scratch = Path(temporary)
        positive = scratch / "positive.final.json"
        process = subprocess.run([*checker, "--output", str(positive)],
                                 capture_output=True, text=True, timeout=60)
        if process.returncode or not positive.exists():
            raise AssertionError(f"real linked POST child was refused: {process.stderr}")
        expected = {row["owner"]: len(row["edges"]) for row in json.loads(plan.read_bytes())["owners"]}
        final = json.loads(positive.read_bytes())
        actual = {row["function"]: row["runtime_contribution"]["original_edge_machine"]
                  for row in final["functions"] if row.get("function") in expected}
        if (set(actual) != set(expected) or
                any(actual[owner].get("verified") is not True or
                    any(actual[owner].get(key) != count for key in
                        ("planned_edges", "selected_edges", "bound_edges"))
                    for owner, count in expected.items())):
            raise AssertionError("final report lacks both actual PE original-edge proofs")

        changed = json.loads(plan.read_bytes())
        changed["owners"][0]["edges"][0]["label"] += 1
        changed_plan = scratch / "changed-plan.json"
        changed_plan.write_bytes(encoded(changed))
        _real_refuse([*checker[:5], "--post-mixed-plan", changed_plan,
                      "--post-mixed-private", private, "--post-mixed-material", material,
                      "--post-mixed-scoped", scoped], scratch / "changed-plan.final.json",
                     "replaced frozen plan")

        image = binary.read_bytes()
        layout = parse_image(image)
        code = subprocess.check_output([str(objdump), "-d", f"--disassemble-symbols={OWNER}",
                                        str(binary)], text=True, timeout=20).lower()
        instructions = _instructions(code, image, OWNER)
        calls = [(item, DIRECT.fullmatch(item.operands[0])) for item in instructions
                 if item.opcode in ("call", "callq") and len(item.operands) == 1 and
                 DIRECT.fullmatch(item.operands[0]) is not None]
        owned = next((item for item, target in calls if target[2] == OWNED), None)
        measured_target = next((int(target[1], 16) for _, target in calls
                                if target[2] == MEASURED), None)
        if owned is None or measured_target is None:
            raise AssertionError("linked owner lacks both distinct helper targets")
        redirected = _replace(image, layout, owned, _retarget_call(owned, measured_target))
        redirected_path = scratch / "redirected-helper.dll"
        redirected_path.write_bytes(redirected)
        _real_refuse([*checker[:3], redirected_path, *checker[4:]],
                     scratch / "redirected-helper.final.json", "redirected linked helper")

        if expect_saved_rsi:
            if instructions[0].opcode != "pushq" or instructions[0].operands != ("%rsi",):
                raise AssertionError("none compute no longer saves RSI in its PE prologue")
            removed_push = _replace(image, layout, instructions[0], b"\x90")
            removed_path = scratch / "removed-rsi-push.dll"
            removed_path.write_bytes(removed_push)
            _real_refuse([*checker[:3], removed_path, *checker[4:]],
                         scratch / "removed-rsi-push.final.json", "saved-register prologue bypass")
            changed_unwind = _unwind_push_mutation(image, layout, instructions[0].address)
            unwind_path = scratch / "changed-rsi-unwind.dll"
            unwind_path.write_bytes(changed_unwind)
            _real_refuse([*checker[:3], unwind_path, *checker[4:]],
                         scratch / "changed-rsi-unwind.final.json", "saved-register unwind mismatch")
    print(f"real linked POST child accepted both owners and rejected plan/PE bypasses: {directory}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-build", type=Path)
    parser.add_argument("--objdump", type=Path)
    parser.add_argument("--expect-saved-rsi", action="store_true")
    args = parser.parse_args()
    if (args.real_build is None) != (args.objdump is None):
        parser.error("--real-build and --objdump must be supplied together")
    values = fixture()
    visited = []

    def mapped(code, proof, owner, image, helper_codes):
        assert image == b"PE" and helper_codes == values["helper_codes"]
        assert code == values["codes"][owner]
        visited.append(owner)
        return [(site["label"], site["label"] + 1, site["label"])
                for site in proof["sites"]]

    with patch("cff_post_mixed_final.check_private_arguments") as arguments, \
            patch("cff_post_mixed_final.check_bounded_site_map", side_effect=mapped):
        result = verify_post_mixed_child(**values)
        assert set(result) == {OWNER, WRAPPER} and visited == [OWNER, WRAPPER]
        assert arguments.call_count == 2
        assert all(item["verified"] is True and item["bound_edges"] >= 3 for item in result.values())

        bad = copy.deepcopy(values)
        bad["report"]["functions"].pop(1)
        bad["report_bytes"] = encoded(bad["report"])
        refuse(bad, "missing owner")

        bad = copy.deepcopy(values)
        bad["report"]["functions"].append(copy.deepcopy(bad["report"]["functions"][0]))
        bad["report_bytes"] = encoded(bad["report"])
        refuse(bad, "duplicate owner")

        bad = copy.deepcopy(values)
        private = json.loads(bad["private_bytes"])
        private["bindings"][WRAPPER]["sites"]["201"]["sources"] = ["post-owned-2", "post-owner-code"]
        bad["private_bytes"] = encoded(private)
        refuse(bad, "wrong owned subset")

        bad = copy.deepcopy(values)
        private = json.loads(bad["private_bytes"])
        private["private_words"], private["measured_private_words"] = (
            private["measured_private_words"], private["private_words"])
        bad["private_bytes"] = encoded(private)
        refuse(bad, "swapped roots")

        bad = copy.deepcopy(values)
        bad["report_bytes"] = bad["report_bytes"].replace(b'"selected_edges":7',
                                                            b'"selected_edges":6')
        refuse(bad, "report bytes/object mismatch")

        bad = copy.deepcopy(values)
        bad["report"]["functions"][0]["runtime_contribution"]["original_edges"]["edges"][0]["point"] += 1
        bad["report_bytes"] = encoded(bad["report"])
        refuse(bad, "changed original edge label")

        bad = copy.deepcopy(values)
        bad["report"]["functions"][0]["runtime_contribution"]["scheme_version"] = 4.0
        bad["report_bytes"] = encoded(bad["report"])
        refuse(bad, "float schema version")

        bad = copy.deepcopy(values)
        bad["report_bytes"] = bad["report_bytes"].replace(
            b'"original_edge_plan_sha256":', b'"original_edge_plan_sha256":"duplicate",'
            b'"original_edge_plan_sha256":', 1)
        refuse(bad, "duplicate raw report field")

        bad = copy.deepcopy(values)
        plan = json.loads(bad["plan_bytes"])
        plan["owners"][1]["edges"][0]["label"] = 101
        bad["plan_bytes"] = encoded(plan)
        bad["report"]["original_edge_plan_sha256"] = hashlib.sha256(bad["plan_bytes"]).hexdigest()
        bad["report_bytes"] = encoded(bad["report"])
        refuse(bad, "duplicate plan label")

        bad = copy.deepcopy(values)
        bad["helper_codes"].pop(MEASURED)
        refuse(bad, "missing linked helper")

        with patch("cff_post_mixed_final.check_bounded_site_map", side_effect=SystemExit("PE bypass")):
            refuse(values, "linked PE bypass")

    print("two-owner POST final preflight accepted exact report and rejected owner/root/site/edge/PE mutations")
    if args.real_build is not None:
        real_cases(args.real_build, args.objdump, args.expect_saved_rsi)


if __name__ == "__main__":
    main()
