"""Exercise the pre-CFF two-edge inventory on the exact retained IR."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "demo"))
from check_linked_cff import checked_original_edge_result, checked_bounded_edge_result


SOURCE = """define i32 @mixed_original_edges(ptr %owned, ptr %measured, i32 %value) {
entry:
  %pick = icmp slt i32 %value, 0
  br i1 %pick, label %negative, label %other
negative:
  ret i32 11
other:
  ret i32 17
}
"""


def run(command, success=True):
    result = subprocess.run([str(item) for item in command], capture_output=True,
                            text=True, timeout=30)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected edge-plan result {result.returncode}: {result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("opt", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="edge-plan-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source = directory / "source.ll"
        source.write_text(SOURCE)
        config = directory / "config.json"
        recipe = {"schema_version": 1, "functions": {"mixed_original_edges": {
            "components": {"runtime-contribution": "required"},
            "contribution": {"selection": "original-edges", "minimum_edges": 2,
                             "minimum_percent": 100, "maximum_edges": 2}}}}
        config.write_text(json.dumps(recipe))
        retained = directory / "retained.ll"
        requests = directory / "requests.json"
        base = [args.opt, f"-load-pass-plugin={args.plugin}",
                "-pyobf-cff-functions=mixed_original_edges", "-pyobf-cff-markers=false",
                f"-pyobf-cff-config={config}"]
        run([*base, "-passes=pyobf-native-cff-requests",
             f"-pyobf-cff-requests-output={requests}", "-S", source, "-o", retained])

        def plan(label, input_ir=retained, candidate_config=config, success=True):
            output = directory / f"{label}.edge-plan.json"
            command = [args.opt, f"-load-pass-plugin={args.plugin}",
                       "-pyobf-cff-functions=mixed_original_edges", "-pyobf-cff-markers=false",
                       f"-pyobf-cff-config={candidate_config}",
                       f"-pyobf-cff-edge-ir-input={input_ir}",
                       "-passes=pyobf-native-cff-edge-plan",
                       f"-pyobf-cff-edge-plan-output={output}", "-disable-output", input_ir]
            result = run(command, success)
            if output.exists() != success:
                raise AssertionError(f"edge plan artifact disagrees with result: {label}")
            return json.loads(output.read_text()) if success else result.stderr

        first = plan("first")
        second = plan("second")
        if (first != second or first.get("schema_version") != 1 or
                first.get("owner") != "mixed_original_edges" or
                first.get("input_ir_encoding") != "llvm-module-print-v1"):
            raise AssertionError("edge plan is not stable for the same retained IR")
        edges = first.get("edges")
        if (not isinstance(edges, list) or len(edges) != 2 or
                len({edge["id"] for edge in edges}) != 2 or
                len({edge["label"] for edge in edges}) != 2 or
                {edge["successor_index"] for edge in edges} != {0, 1} or
                any(not edge["id"].startswith("original.") or not 0 < edge["label"] < 2**32
                    for edge in edges)):
            raise AssertionError("edge plan lost distinct retained normal edges")
        frozen = directory / "first.edge-plan.json"

        def verify(label, input_ir=retained, candidate=frozen, pass_name="pyobf-native-cff-edge-plan-verify",
                   success=True):
            result = run([args.opt, f"-load-pass-plugin={args.plugin}",
                "-pyobf-cff-functions=mixed_original_edges", "-pyobf-cff-markers=false",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-edge-plan-input={candidate}",
                f"-passes={pass_name}", "-disable-output", input_ir], success)
            return result.stderr

        verify("exact")
        private = directory / "source-mixed.private.json"
        labels = [edge["label"] for edge in edges]
        private.write_text(json.dumps({"schema_version": 4, "provider": "source-mixed-v1",
            "routing_tag": 0x1020, "domain": 1, "private_words": list(range(8)),
            "owners": {"mixed_original_edges": 7},
            "sources": [
                {"id": "owned-a", "word_label": 13, "group": "context-a",
                 "provider": "owned-context-v1", "provider_version": 1},
                {"id": "measured", "word_label": 29, "group": "code",
                 "provider": "measured-scope-v1", "provider_version": 1},
                {"id": "owned-b", "word_label": 37, "group": "context-b",
                 "provider": "owned-context-v1", "provider_version": 1}],
            "bindings": {"mixed_original_edges": {"sites": {
                str(labels[0]): {"sources": ["owned-a", "measured"], "mixing_domain": "first",
                    "groups": [{"id": "context-a", "minimum": 1}, {"id": "code", "minimum": 1}]},
                str(labels[1]): {"sources": ["measured", "owned-b"], "mixing_domain": "second",
                    "groups": [{"id": "code", "minimum": 1}, {"id": "context-b", "minimum": 1}]}}}}}))
        missing_plan = run([args.opt, f"-load-pass-plugin={args.plugin}",
            "-pyobf-cff-functions=mixed_original_edges", "-pyobf-cff-markers=false",
            f"-pyobf-cff-config={config}", f"-pyobf-cff-contribution-input={private}",
            f"-pyobf-cff-requests-input={requests}", "-passes=pyobf-native-cff",
            "-disable-output", retained], success=False)
        if "schema4 original edges require frozen exact-IR plan" not in missing_plan.stderr:
            raise AssertionError(f"mixed automatic CFF accepted missing frozen plan: {missing_plan.stderr}")
        complete = {"verified": True, "profile": "schema4-original-edges-two-v1",
            "planned_edges": 2, "selected_edges": 2, "bound_edges": 2,
            "plan_sha256": hashlib.sha256(frozen.read_bytes()).hexdigest()}
        if checked_original_edge_result(complete, frozen.read_bytes()) != complete:
            raise AssertionError("complete edge proof result was lost")
        for forged in (None, {}, {**complete, "verified": 1},
                       {**complete, "planned_edges": True},
                       {**complete, "bound_edges": 1},
                       {**complete, "plan_sha256": "0" * 64}):
            try:
                checked_original_edge_result(forged, frozen.read_bytes())
            except ValueError:
                pass
            else:
                raise AssertionError("incomplete or stale edge proof result was accepted")
        bounded_plan = {"schema_version": 2, "profile": "schema4-original-edges-bounded-v2",
            "input_ir_encoding": "llvm-module-print-v1", "input_ir_sha256": first["input_ir_sha256"],
            "owners": [{"owner": "mixed_original_edges", "recipe": first["recipe"],
                "edges": [*edges, {"id": "third", "label": 23, "successor_index": 0}]}]}
        bounded_bytes = json.dumps(bounded_plan, sort_keys=True).encode()
        bounded_result = {"verified": True, "profile": "schema4-original-edges-bounded-v2",
            "planned_edges": 3, "selected_edges": 3, "bound_edges": 3,
            "plan_sha256": hashlib.sha256(bounded_bytes).hexdigest()}
        if checked_bounded_edge_result(bounded_result, bounded_bytes) != bounded_result:
            raise AssertionError("complete bounded-edge proof result was lost")
        for forged, raw in (({**bounded_result, "bound_edges": 2}, bounded_bytes),
                            ({**bounded_result, "verified": 1}, bounded_bytes),
                            ({**bounded_result, "plan_sha256": "0" * 64}, bounded_bytes),
                            (bounded_result, bounded_bytes.replace(b'"schema_version": 2', b'"schema_version": 1')),
                            (bounded_result, bounded_bytes.replace(b'"schema_version": 2',
                                b'"schema_version": 2, "schema_version": 2')),
                            (bounded_result, bounded_bytes + b" " * 65536)):
            try:
                checked_bounded_edge_result(forged, raw)
            except ValueError:
                pass
            else:
                raise AssertionError("incomplete or wrong-profile bounded proof was accepted")
        changed = directory / "changed.ll"
        changed.write_text(retained.read_text().replace("ret i32 17", "ret i32 19"))
        changed_plan = plan("changed", changed)
        if changed_plan["edges"] != edges or changed_plan["input_ir_sha256"] == first["input_ir_sha256"]:
            raise AssertionError("edge plan did not bind its exact retained input IR")
        if "frozen plan differs from exact retained IR and recipe" not in verify("changed", changed, success=False):
            raise AssertionError("changed IR passed the frozen-plan consumer")
        tampered = directory / "tampered.edge-plan.json"
        modified = dict(first)
        modified["edges"] = [dict(edge) for edge in edges]
        modified["edges"][0]["label"] ^= 1
        tampered.write_text(json.dumps(modified))
        if "frozen plan differs from exact retained IR and recipe" not in verify("tampered", candidate=tampered, success=False):
            raise AssertionError("changed edge label passed the frozen-plan consumer")
        if "frozen plan differs from exact retained IR and recipe" not in verify(
                "transform-preflight", candidate=tampered, pass_name="pyobf-native-cff", success=False):
            raise AssertionError("CFF transform did not consume the frozen plan before mutation")
        if "source-retained terminator provenance" not in plan("unstamped", source, success=False):
            raise AssertionError("unretained source was accepted")
        partial = directory / "partial.json"
        recipe["functions"]["mixed_original_edges"]["contribution"]["minimum_percent"] = 99
        partial.write_text(json.dumps(recipe))
        if "strict whole relative-tree two-edge" not in plan("partial", candidate_config=partial, success=False):
            raise AssertionError("partial edge selection was accepted")
        recipe["functions"]["mixed_original_edges"]["contribution"]["minimum_percent"] = 100
        recipe["functions"]["mixed_original_edges"]["components"]["deduplicate-blocks"] = "required"
        dedup = directory / "dedup.json"
        dedup.write_text(json.dumps(recipe))
        if "normalization component is outside the bounded profile" not in plan(
                "dedup", candidate_config=dedup, success=False):
            raise AssertionError("deduplicating profile was accepted")
        extra = directory / "extra.ll"
        branch = re.search(r"br i1 %pick[^\n]*!pyobf.cff.site !(\d+)", retained.read_text())
        if branch is None:
            raise AssertionError("retained IR lacks branch provenance")
        extra.write_text(retained.read_text().replace("ret i32 17",
            f"br label %final, !pyobf.cff.site !{branch[1]}\nfinal:\n  ret i32 17"))
        if "exactly two retained normal edges" not in plan("extra", extra, success=False):
            raise AssertionError("a new original edge was accepted")
        linear = directory / "linear.ll"
        linear.write_text(re.sub(r"br i1 %pick[^\n]*!pyobf.cff.site !\d+",
            f"br label %negative, !pyobf.cff.site !{branch[1]}",
            retained.read_text()).replace("ret i32 11",
            f"br label %other, !pyobf.cff.site !{branch[1]}"))
        if "one conditional decision" not in plan("linear", linear, success=False):
            raise AssertionError("two serial unconditional edges entered the bounded profile")
        joined = directory / "joined.ll"
        joined.write_text(retained.read_text().replace(
            "label %negative, label %other", "label %negative, label %negative"))
        if "distinct normal successors" not in plan("joined", joined, success=False):
            raise AssertionError("two aliases of one successor entered the bounded profile")
        wrong_abi = directory / "wrong-abi.ll"
        wrong_abi.write_text(retained.read_text().replace("ptr %measured", "i64 %measured"))
        if "separate owned and measured pointer arguments" not in plan("wrong-abi", wrong_abi, success=False):
            raise AssertionError("wrong reference ABI was accepted")
        explicit = directory / "explicit.ll"
        explicit.write_text(retained.read_text().replace("define i32 @mixed_original_edges",
            "declare void @pyobf_native_mixed_contribution_site_v1(ptr, ptr, i32)\n\n"
            "define i32 @mixed_original_edges").replace("  %pick = icmp",
                "  call void @pyobf_native_mixed_contribution_site_v1(ptr %owned, ptr %measured, i32 701)\n"
                "  %pick = icmp"))
        explicit_error = plan("explicit", explicit, success=False)
        if "cannot contain an explicit contribution marker" not in explicit_error:
            raise AssertionError(f"explicit marker entered the automatic-edge profile: {explicit_error}")
        for label, victim in (("configuration", config), ("retained IR", retained),
                              ("request manifest", requests)):
            before = victim.read_bytes()
            result = run([args.opt, f"-load-pass-plugin={args.plugin}",
                "-pyobf-cff-functions=mixed_original_edges", "-pyobf-cff-markers=false",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-requests-input={requests}",
                f"-pyobf-cff-edge-ir-input={retained}",
                f"-pyobf-cff-edge-plan-output={victim}",
                "-passes=pyobf-native-cff-edge-plan", "-disable-output", retained], success=False)
            if "plan output aliases an input" not in result.stderr or victim.read_bytes() != before:
                raise AssertionError(f"edge plan output damaged {label}")
        print("exact retained two-edge planning, stability and fail-closed negatives pass")


if __name__ == "__main__":
    main()
