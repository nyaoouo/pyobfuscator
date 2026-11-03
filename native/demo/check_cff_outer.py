"""Check outer-domain source requests and exact linked coverage without key-security claims."""

import argparse
import hashlib
import json
from pathlib import Path
from session_fold_reference import verify_coverage


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("image", "report", "final", "requests", "configuration"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--decoy", action="store_true")
    parser.add_argument("--measured", action="store_true")
    parser.add_argument("--post-measured", action="store_true")
    parser.add_argument("--owner-plan", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    final = json.loads(args.final.read_text())
    requests = json.loads(args.requests.read_text())["functions"]
    configuration = json.loads(args.configuration.read_text())
    if report["domain"] != configuration.get("domain", "module"):
        raise AssertionError("outer domain differs from its own recipe")
    if (final["image_sha256"] != hashlib.sha256(args.image.read_bytes()).hexdigest() or
            final["input_report_sha256"] != hashlib.sha256(args.report.read_bytes()).hexdigest()):
        raise AssertionError("outer final report is stale or belongs to another image/report")
    selected = {row["function"]: row for row in report["functions"] if row["selected"]}
    verify_coverage(list(selected.values()), decoy=args.decoy)
    final_rows = {row["function"]: row for row in final["functions"]}
    owners = 0
    if args.measured or args.post_measured:
        if args.owner_plan is None: raise AssertionError("measured outer needs its independently supplied early owner plan")
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from reference_plan import parse_plan
        plan = parse_plan(args.owner_plan.read_bytes())
        owners = len(plan.records)
        if final.get("owner_readers", {}).get("plan_sha256") != plan.digest.hex():
            raise AssertionError("outer owner proof is absent or belongs to another plan")
        if (final.get("owner_creators", {}).get("plan_sha256") != plan.digest.hex() or
                len(final["owner_creators"].get("entries", [])) != owners):
            raise AssertionError("outer creator proof is absent or incomplete")
        if args.post_measured:
            joined = final.get("post_role_join", {})
            if (joined.get("schema_version") != 1 or
                    joined.get("verification_scope") != "cross-artifact-compiler-role-flow-and-function-final-presence" or
                    joined.get("plan_sha256") != plan.digest.hex() or
                    joined.get("parent_image_sha256") != final["image_sha256"] or
                    joined.get("individual_site_machine_verified") is not False or
                    type(joined.get("roles")) is not list or len(joined["roles"]) != 2):
                raise AssertionError("POST outer final lacks its parent-to-child role/site join")
    elif args.owner_plan is not None: raise AssertionError("unmeasured outer supplied an owner plan")
    if not selected or any(row["status"] != "transformed" for row in selected.values()):
        raise AssertionError("outer domain was not fully transformed")
    for marker, count in (("pyobf.native.bootstrap", (28 if args.decoy else 21) + 3 * int(args.measured) + 6 * int(args.post_measured)),
                          ("pyobf.native.bootstrap.eh", 3 if args.decoy else 2),
                          ("pyobf.native.sdk", (114 if args.measured else 111 if args.post_measured else 43) + 3 * owners)):
        authored = [row for row in requests if row.get("marker") == marker]
        if len(authored) != count or any(not row["defined"] or not row["sites"] for row in authored):
            raise AssertionError(f"missing authored outer requests: {marker}")
        for request in authored:
            row = selected[request["function"]]
            linked = final_rows[row["function"]]
            if row.get("marker") != marker or not row["requested"] or not linked["final_binary_verified"]:
                raise AssertionError("outer authored/generated accounting changed")
            if marker.endswith(".eh"):
                eh = linked["hybrid_eh"]
                if (not row["coverage_kind"].startswith("hybrid-eh-") or eh["full_function_coverage"] or
                        eh["transformed_exceptional_edges"] or not eh["ir_boundary_contract_verified"] or
                        not eh["ir_flow_graph_verified"] or not eh["final_normal_dispatch_presence_verified"] or
                        linked["decision_flow_verified"]):
                    raise AssertionError("outer hybrid presence was lost or promoted to full EH coverage")
            elif row["coverage_kind"].startswith("hybrid"):
                raise AssertionError("ordinary outer marker silently became partial EH coverage")
        if marker == "pyobf.native.sdk" and (args.measured or args.post_measured):
            if sum("copy_snapshot_report" in row["function"] for row in authored) != 1:
                raise AssertionError("measured SDK lost its independent snapshot reporter")
    if any(row["final_binary_verified"] for row in final_rows.values() if not row["selected"]):
        raise AssertionError("unselected outer support was credited")
    if "pyobf_native_demo_run" not in selected:
        raise AssertionError("outer exported entry bypassed source selection")


if __name__ == "__main__":
    main()
