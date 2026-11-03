"""Exercise bounded schema4 original edges in the retained IR and linked PE."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "tests/measurement"),
               str(ROOT / "tools"), str(ROOT / "demo")]
from cff_build import run
from site_scope_cff import actual_subject
from source_mixed_bounded_negatives import check_artifacts


OWNER = "mixed_bounded_body"
COUNTS = {("wrapper", "none"): 4, ("wrapper", "O2"): 3,
          ("compute", "none"): 7, ("compute", "O2"): 6}
PATHS = {("wrapper", "none"): {-3: (0, 2), 3: (1, 3)},
         ("wrapper", "O2"): {-3: (0, 2), 3: (1,)},
         ("compute", "none"): {-3: (0, 2), 0: (1, 3, 5), 3: (1, 4, 6)},
         ("compute", "O2"): {-3: (0, 2), 0: (1, 3), 3: (1, 4, 5)}}
CONFIGURATION = {"schema_version": 1, "functions": {OWNER: {
    "components": {"runtime-contribution": "required"},
    "contribution": {"selection": "original-edges", "minimum_edges": 3,
                     "maximum_edges": 8, "minimum_percent": 100}}}}


def policy(edges):
    count = len(edges)
    sources = [{"id": f"owned-{index}", "word_label": 40 + index,
                "group": "context", "provider": "owned-context-v1", "provider_version": 1}
               for index in range(count)]
    sources.append({"id": "measured", "word_label": 29,
                    "group": "code", "provider": "measured-scope-v1", "provider_version": 1})
    sites = {str(edge["label"]): {"sources": [f"owned-{index}", "measured"],
        "mixing_domain": f"bounded-{index}",
        "groups": [{"id": "context", "minimum": 1}, {"id": "code", "minimum": 1}]}
        for index, edge in enumerate(edges)}
    return {"schema_version": 4, "provider": "source-mixed-v1", "routing_tag": 0x1020,
            "domain": 1, "private_words": list(struct.unpack("<8I", bytes(range(32)))),
            "owners": {OWNER: 7}, "sources": sources,
            "bindings": {OWNER: {"sites": sites}}}


def refuse(command, output, reason=None):
    output.write_text("stale final output")
    result = run([*command, "--output", output], succeeds=False)
    if output.exists() or (reason is not None and reason not in result.stderr):
        raise AssertionError(f"expected refusal {reason!r}: {result.stderr}")


def compile_case(args, directory):
    count = COUNTS[(args.shape, args.optimization)]
    raw = ROOT / "tests/contribution" / (
        f"source_mixed_bounded_{args.shape}{'_o2' if args.optimization == 'O2' else ''}.ll")
    source = raw
    if args.optimization == "O2":
        source = directory / "optimized.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", raw, "-o", source])
    configuration = directory / "config.json"
    configuration.write_text(json.dumps(CONFIGURATION))
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}",
              f"-pyobf-cff-config={configuration}", f"-pyobf-cff-functions={OWNER}",
              "-pyobf-cff-markers=false"]
    retained, requests, plan, private, report, protected = (
        directory / name for name in ("retained.ll", "requests.json", "plan.json",
            "private.json", "report.json", "protected.ll"))
    run([*plugin, "-passes=pyobf-native-cff-requests",
         f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S", source,
         "-o", retained])
    run([*plugin, "-passes=pyobf-native-cff-edge-plan", f"-pyobf-cff-edge-ir-input={retained}",
         f"-pyobf-cff-edge-plan-output={plan}", "-disable-output", retained])
    planned = json.loads(plan.read_text())
    if (set(planned) != {"schema_version", "profile", "input_ir_encoding",
            "input_ir_sha256", "owners"} or planned["schema_version"] != 2 or
            planned["profile"] != "schema4-original-edges-bounded-v2" or
            len(planned["owners"]) != 1 or planned["owners"][0]["owner"] != OWNER or
            len(planned["owners"][0]["edges"]) != count):
        raise AssertionError("retained input does not have the required bounded plan")
    edges = planned["owners"][0]["edges"]
    private.write_text(json.dumps(policy(edges)))
    retained_bytes = retained.read_bytes()
    rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan",
        f"-pyobf-cff-edge-ir-input={retained}",
        f"-pyobf-cff-edge-plan-output={retained}", "-disable-output", retained],
        succeeds=False)
    if "plan output aliases an input" not in rejected.stderr or retained.read_bytes() != retained_bytes:
        raise AssertionError("schema2 planner wrote through an aliased retained input")
    if args.shape == "wrapper" and args.optimization == "none":
        marked = directory / "explicit-marker.ll"
        marked.write_text(retained.read_text().replace("entry:\n", "entry:\n"
                "  call void @pyobf_native_mixed_contribution_site_v1(ptr %owned, "
                "ptr %measured, i32 9)\n", 1) +
            "\ndeclare void @pyobf_native_mixed_contribution_site_v1(ptr, ptr, i32)\n")
        marked_plan = directory / "explicit-marker.plan.json"
        rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan",
            f"-pyobf-cff-edge-ir-input={marked}",
            f"-pyobf-cff-edge-plan-output={marked_plan}", "-disable-output", marked],
            succeeds=False)
        if marked_plan.exists() or "explicit contribution marker" not in rejected.stderr:
            raise AssertionError(f"explicit marker crossed bounded automatic-edge planner: "
                                 f"{rejected.stderr}")
    changed_plan = copy.deepcopy(planned)
    changed_plan["owners"][0]["edges"][0]["label"] += 1
    stale = directory / "stale-plan.json"
    stale.write_text(json.dumps(changed_plan))
    rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan-verify",
        f"-pyobf-cff-edge-ir-input={retained}", f"-pyobf-cff-edge-plan-input={stale}",
        "-disable-output", retained], succeeds=False)
    if "frozen plan differs from exact retained IR and recipe" not in rejected.stderr:
        raise AssertionError("changed frozen plan was accepted")
    run([*plugin, "-passes=pyobf-native-cff-edge-plan-verify",
         f"-pyobf-cff-edge-ir-input={retained}", f"-pyobf-cff-edge-plan-input={plan}",
         "-disable-output", retained])
    stale_ir = directory / "stale-ir.ll"
    stale_ir.write_text(retained.read_text() + "\ndeclare void @bounded_stale_ir_witness()\n")
    rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan-verify",
        f"-pyobf-cff-edge-ir-input={stale_ir}", f"-pyobf-cff-edge-plan-input={plan}",
        "-disable-output", stale_ir], succeeds=False)
    if "frozen plan differs from exact retained IR and recipe" not in rejected.stderr:
        raise AssertionError("stale retained IR crossed the frozen plan gate")
    if args.shape == "compute" and args.optimization == "none":
        ninth_raw = ROOT / "tests/contribution/source_mixed_bounded_ninth.ll"
        ninth_retained, ninth_requests, ninth_plan = (
            directory / name for name in ("ninth.retained.ll", "ninth.requests.json",
                "ninth.plan.json"))
        run([*plugin, "-passes=pyobf-native-cff-requests",
            f"-pyobf-cff-requests-output={ninth_requests}", "-S", ninth_raw,
            "-o", ninth_retained])
        rejected = run([*plugin, "-passes=pyobf-native-cff-edge-plan",
            f"-pyobf-cff-edge-ir-input={ninth_retained}",
            f"-pyobf-cff-edge-plan-output={ninth_plan}", "-disable-output",
            ninth_retained], succeeds=False)
        if ninth_plan.exists() or "three to eight edges" not in rejected.stderr:
            raise AssertionError("ninth retained edge crossed bounded planner")
        unused = [value for value in range(1, len(edges) + 3)
                  if value not in {edge["label"] for edge in edges}][:2]
        nine_private = policy(edges + [{"label": value} for value in unused])
        nine_path = directory / "nine-sites.private.json"
        nine_path.write_text(json.dumps(nine_private))
        rejected = run([*plugin, "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-edge-plan-input={plan}",
            f"-pyobf-cff-contribution-input={nine_path}", "-S", retained,
            "-o", directory / "nine-sites.ll"], succeeds=False)
        if "at most eight explicit sites" not in rejected.stderr:
            raise AssertionError("ninth schema4 private site crossed parser cap")
    for kind in ("missing", "aliased"):
        changed = policy(edges)
        sites = changed["bindings"][OWNER]["sites"]
        if kind == "missing":
            sites.pop(str(edges[-1]["label"]))
        else:
            sites[str(edges[-1]["label"])] = copy.deepcopy(sites[str(edges[0]["label"])])
        bad = directory / f"{kind}-private.json"
        bad.write_text(json.dumps(changed))
        output = directory / f"{kind}-protected.ll"
        rejected = run([*plugin, "-passes=pyobf-native-cff",
            f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-edge-plan-input={plan}",
            f"-pyobf-cff-contribution-input={bad}", "-S", retained, "-o", output],
            succeeds=False)
        if output.exists() or "source-mixed" not in rejected.stderr:
            raise AssertionError(f"{kind} private source rule was accepted: {rejected.stderr}")
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
         f"-pyobf-cff-edge-plan-input={plan}", f"-pyobf-cff-contribution-input={private}",
         f"-pyobf-cff-report={report}", "-verify-each", "-S", retained, "-o", protected])
    run([args.opt, f"-load-pass-plugin={args.plugin}",
         "-passes=pyobf-native-contribution-verify", "-disable-output", protected])
    document = json.loads(report.read_text())
    row = next(item for item in document["functions"] if item.get("function") == OWNER)
    original = row.get("runtime_contribution", {}).get("original_edges", {})
    if (row.get("status") != "transformed" or original.get("bound_edges") != count or
            document.get("original_edge_plan_sha256") != hashlib.sha256(plan.read_bytes()).hexdigest()):
        raise AssertionError("compiler did not bind every planned edge to a dispatch state")
    return plan, private, report, protected, edges


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("shape", choices=("wrapper", "compute"))
    parser.add_argument("optimization", choices=("none", "O2"))
    for name in ("core", "backend"):
        parser.add_argument(f"--{name}", nargs="+", type=Path, required=True)
    parser.add_argument("--foreign-provider", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="bounded-edges-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        plan, private, report, protected, edges = compile_case(args, directory)
        labels = ", ".join(str(edge["label"]) + "u" for edge in edges)
        words = ", ".join(str(40 + index) + "u" for index in range(len(edges)))
        paths = PATHS[(args.shape, args.optimization)]
        masks = {value: sum(1 << index for index in indices)
                 for value, indices in paths.items()}
        (directory / "bounded_labels.hpp").write_text(
            "#pragma once\n#include <cstdint>\n"
            f"constexpr unsigned bounded_site_count = {len(edges)};\n"
            f"constexpr std::uint32_t bounded_site_labels[] = {{{labels}}};\n"
            f"constexpr std::uint32_t bounded_source_words[] = {{{words}}};\n"
            f"constexpr std::uint32_t bounded_expected_minus = {masks[-3]}u;\n"
            f"constexpr std::uint32_t bounded_expected_zero = {masks.get(0, 0)}u;\n"
            f"constexpr std::uint32_t bounded_expected_plus = {masks[3]}u;\n"
            f"constexpr bool bounded_compute = {'true' if args.shape == 'compute' else 'false'};\n"
            f"constexpr bool bounded_optimized = {'true' if args.optimization == 'O2' else 'false'};\n")
        obj, binary = directory / "protected.obj", directory / "protected.exe"
        run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", obj])
        core = list(dict.fromkeys([*args.core, *args.backend]))
        run([args.compiler, "-std=c++17", "-O2", obj,
             ROOT / "tests/contribution/source_mixed_bounded_probe.cpp", *core,
             "-I", directory, "-I", ROOT / "include", "-I", ROOT / "src",
             "-lbcrypt", "-o", binary])
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        strict = [*checker, binary, report, "--contribution-input", private,
                  "--source-mixed-bounded-edges", plan]
        final = directory / "final.json"
        refuse([*checker, binary, report, "--contribution-input", private],
               directory / "default.final.json")
        run([*strict, "--output", final])
        document = json.loads(final.read_text())
        row = next(item for item in document["functions"] if item.get("function") == OWNER)
        expected = {"verified": True, "profile": "schema4-original-edges-bounded-v2",
            "planned_edges": len(edges), "selected_edges": len(edges), "bound_edges": len(edges),
            "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest()}
        if row["runtime_contribution"].get("original_edge_machine") != expected:
            raise AssertionError("final PE report lost exact bounded edge binding")
        check_artifacts(checker, args.objdump, binary, report, private, plan,
                        directory, OWNER,
                        saturation=args.shape == "wrapper" and args.optimization == "none")
        inputs = actual_subject(args, directory)
        values = (-3, 3) if args.shape == "wrapper" else (-3, 0, 3)
        for value in values:
            environment = os.environ.copy()
            environment["PYOBF_TEST_BOUNDED_VALUE"] = str(value)
            admitted = subprocess.run(list(map(str, [binary, *inputs, "normal",
                args.foreign_provider])), capture_output=True, text=True, timeout=15,
                env=environment)
            if admitted.returncode != 0:
                raise AssertionError(f"{value} did not reach its valid edge path: "
                                     f"{admitted.returncode}: {admitted.stderr}")
            for mode in ("wrong-owned", "wrong-measured"):
                denied = subprocess.run(list(map(str, [binary, *inputs, mode,
                    args.foreign_provider])), capture_output=True, text=True,
                    timeout=15, env=environment)
                if denied.returncode & 0xffffffff != 0xe04f0702:
                    raise AssertionError(f"{value} {mode} crossed source gate or effect ran: "
                                         f"{denied.returncode}: {denied.stderr}")
        for index, edge in enumerate(edges):
            value = next(value for value, indices in paths.items() if index in indices)
            environment = os.environ.copy()
            environment["PYOBF_TEST_BOUNDED_VALUE"] = str(value)
            environment["PYOBF_TEST_BOUNDED_DENY_LABEL"] = str(edge["label"])
            denied = subprocess.run(list(map(str, [binary, *inputs, "deny-site",
                args.foreign_provider])), capture_output=True, text=True, timeout=15,
                env=environment)
            if (denied.returncode & 0xffffffff != 0xe04f0702 or
                    f"denied-site:{edge['label']}" not in denied.stderr):
                raise AssertionError(f"edge {index} was not individually reached and denied: "
                                     f"{denied.returncode}: {denied.stderr}")
        print(f"bounded {args.shape} {args.optimization}: {len(edges)} actual CNG/PE edges pass",
              flush=True)


if __name__ == "__main__":
    main()
