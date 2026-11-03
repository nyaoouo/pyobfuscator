"""Execute actual owned-context observations in sealed CFF transitions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/context"), str(ROOT / "demo")]
from cff_build import run, verify_image
from gate_mutations import graph_refusals, input_refusals, source_refusals, forwarded_query
from gate_profiles import artifact_refusals, optional_zero
from edge_policies import check_input_density, policy_acceptance, report_refusals
from hybrid_gate_cases import hybrid_refusals
from region_gate_cases import region_acceptance
from group_gate_cases import configure_groups, group_acceptance, grouped_return_refusals
from layer_cases import layer_refusals
from preparation_cases import preparation_refusals
from framed_gate_cases import frame_refusals
from bogus_gate_cases import bogus_refusals, raw_clone_fallback
from scalar_gate_cases import configure_scalar_gates, check_scalar_gates, scalar_refusals
from archive_gate_pipeline import configure_archive_gates, prepare_archive_gates, check_archive_gates
from archive_gate_cases import check_archive_image, archive_refusals
from normalizer_gate_cases import configure_normalizer_gates, check_normalizer_gates, normalizer_loss_refusals
from alias_gate_cases import alias_acceptance
from alias_gate_cost import measure_alias_cost
from scalar_gate_cost import measure_scalar_cost
from contribution_gate_cost import measure_contribution_cost
from hybrid_normalizer_cases import configure_hybrid_normalizers, prepare_hybrid_normalizer_input, check_hybrid_normalizers, hybrid_normalizer_limits
from hybrid_completion_cases import void_completion_cases
from hybrid_local_cases import check_hybrid_locals, hybrid_local_refusals


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none", "O2"))
    parser.add_argument("--ipo", action="store_true")
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--hybrid", action="store_true")
    parser.add_argument("--region", action="store_true")
    parser.add_argument("--grouped", action="store_true")
    parser.add_argument("--preparations", choices=("all", "indexed-locals", "reference-routes", "import-routes"))
    parser.add_argument("--frames", choices=("internal", "external", "both"))
    parser.add_argument("--call-steps", action="store_true")
    parser.add_argument("--split", action="store_true")
    parser.add_argument("--frame-controls", action="store_true")
    parser.add_argument("--bogus", choices=("all", "bogus-clones", "bogus-synthesis"))
    parser.add_argument("--ssa-source", action="store_true")
    parser.add_argument("--literals", action="store_true")
    parser.add_argument("--scalars", choices=("all", "integer-literals", "comparison-constants"))
    parser.add_argument("--archive", action="store_true")
    parser.add_argument("--normalizers", choices=("all", "common-exit", "deduplicate-blocks", "split-blocks"))
    parser.add_argument("--hybrid-normalizers", choices=("all", "common-exit", "deduplicate-blocks", "split-blocks"))
    parser.add_argument("--alias-measurements", type=Path)
    parser.add_argument("--scalar-measurements", type=Path)
    parser.add_argument("--contribution-measurements", type=Path)
    parser.add_argument("--archive-backend-source", action="append", type=Path, default=[])
    parser.add_argument("--composed", choices=("all", "opaque-choices", "reachable-junk", "decoy-transitions"))
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    parser.add_argument("--backend-source", action="append", type=Path, required=True)
    args = parser.parse_args()
    if args.hybrid_normalizers and (not args.hybrid or args.normalizers):
        parser.error("--hybrid-normalizers requires --hybrid and a separate whole fixture")
    if args.archive and not args.archive_backend_source: parser.error("--archive requires archive backend sources")
    if args.normalizers and (args.archive or args.frames or args.preparations):
        parser.error("the normalizer fixture has no archive or frame/preparation payload")
    if args.alias_measurements and (args.normalizers != "all" or not args.automatic or args.optimization != "none" or args.hybrid or args.region):
        parser.error("alias measurements require automatic whole normalizers-all and source none")
    if args.scalar_measurements and (args.optimization != "none" or args.scalars != "all" or not args.grouped or
            not args.automatic or args.composed != "all" or args.hybrid or args.region or args.archive or
            args.normalizers or args.hybrid_normalizers or args.ipo or args.alias_measurements or args.contribution_measurements):
        parser.error("scalar measurements require whole grouped automatic scalar/layer composition with source none")
    if args.contribution_measurements and (args.optimization != "none" or args.scalars != "all" or not args.grouped or
            not args.automatic or args.composed != "all" or args.hybrid or args.region or args.archive or
            args.normalizers or args.hybrid_normalizers or args.ipo or args.alias_measurements or args.scalar_measurements):
        parser.error("contribution measurements require whole grouped automatic scalar/layer composition with source none")
    if args.call_steps and not args.frames: parser.error("--call-steps requires --frames")
    if args.frame_controls and (args.frames != "both" or args.call_steps or args.preparations):
        parser.error("--frame-controls requires both frame kinds without call steps or initializers")
    extended_fixture = bool(args.preparations or args.frames)
    args.scalar_donor = bool(args.scalars and extended_fixture and args.bogus in ("all", "bogus-clones"))
    args.hybrid_scalars = bool(args.scalars and args.hybrid)
    internal_throw = args.frames in ("internal", "both") and args.hybrid
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}"]
    with tempfile.TemporaryDirectory(prefix="contribution-gates-", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        configuration = directory / "recipe.json"
        configuration.write_text(json.dumps({"schema_version": 1, "functions": {name: {
            "components": {"runtime-contribution": "required"}} for name in ("contribution_compute", "contribution_compute_global")}}))
        private = directory / "reference.private.json"
        private.write_text(json.dumps({"schema_version": 1, "provider": "owned-context-v1", "routing_tag": 7,
            "domain": 11, "source": 17, "private_words": list(range(1, 9)), "owners": {"contribution_compute": 13, "contribution_compute_global": 19}}))
        if args.automatic:
            config = json.loads(configuration.read_text())
            config["functions"]["contribution_compute"]["contribution"] = {"selection": "original-edges"}
            config["functions"]["contribution_switch"] = {"components": {"runtime-contribution": "required"}, "contribution": {"selection": "original-edges"}}
            configuration.write_text(json.dumps(config))
            inputs = json.loads(private.read_text()); inputs["owners"]["contribution_switch"] = 23
            private.write_text(json.dumps(inputs))
        if args.hybrid:
            config = json.loads(configuration.read_text())
            config["functions"]["contribution_hybrid"] = {"coverage": "hybrid-eh",
                "components": {"runtime-contribution": "required"}, "contribution": {
                    "selection": "original-edges" if args.automatic else "explicit-points"}}
            configuration.write_text(json.dumps(config))
            inputs = json.loads(private.read_text()); inputs["owners"]["contribution_hybrid"] = 29
            private.write_text(json.dumps(inputs))
        if args.region:
            config = json.loads(configuration.read_text())
            config["functions"]["contribution_region"] = {"components": {"runtime-contribution": "required"},
                "contribution": {"selection": "original-edges" if args.automatic else "explicit-points"}}
            configuration.write_text(json.dumps(config))
            inputs = json.loads(private.read_text()); inputs["owners"]["contribution_region"] = 31
            private.write_text(json.dumps(inputs))
        configure_archive_gates(args, configuration, private)
        if args.frames:
            config = json.loads(configuration.read_text())
            frames = tuple(name for name, kind in (("call-frames", "internal"), ("external-calls", "external"))
                if args.frames in (kind, "both"))
            for name in ("contribution_compute", "contribution_hybrid"):
                if name not in config["functions"]: continue
                config["functions"][name]["components"].update({component:
                    "optional" if args.optimization == "O2" else "required" for component in frames})
                if args.call_steps: config["functions"][name]["components"]["call-preparation"] = "required"
            configuration.write_text(json.dumps(config))
        if args.split:
            config = json.loads(configuration.read_text())
            # This legacy flag selects only the whole owner. Hybrid cuts are selected
            # independently with --hybrid-normalizers.
            config["functions"]["contribution_compute"]["components"]["split-blocks"] = "optional" if args.optimization == "O2" else "required"
            config["functions"]["contribution_compute"]["budgets"] = {"max_block_instructions": 1}
            configuration.write_text(json.dumps(config))
        if args.preparations:
            config = json.loads(configuration.read_text())
            preparations = ("indexed-locals", "reference-routes", "import-routes") if args.preparations == "all" else (args.preparations,)
            config["functions"]["contribution_compute"]["components"].update({name:
                "optional" if args.optimization == "O2" else "required" for name in preparations})
            if args.hybrid:
                config["functions"]["contribution_hybrid"]["components"].update({name:
                    "optional" if args.optimization == "O2" else "required" for name in preparations})
            configuration.write_text(json.dumps(config))
        if args.composed:
            config = json.loads(configuration.read_text())
            strategies = ("opaque-choices", "reachable-junk", "decoy-transitions") if args.composed == "all" else (args.composed,)
            for name in ("contribution_compute", "contribution_hybrid"):
                if name in config["functions"]:
                    # O2 can remove original branch requests; require retained feature
                    # evidence independently below, preserving strict loss refusals.
                    config["functions"][name]["components"].update({strategy:
                        "optional" if args.optimization == "O2" else "required" for strategy in strategies})
            configuration.write_text(json.dumps(config))
        if args.bogus:
            config = json.loads(configuration.read_text())
            bogus = ("bogus-clones", "bogus-synthesis") if args.bogus == "all" else (args.bogus,)
            for name in ("contribution_compute", "contribution_hybrid"):
                if name in config["functions"]:
                    config["functions"][name]["components"].update({component:
                        "optional" if args.optimization == "O2" else "required" for component in bogus})
            configuration.write_text(json.dumps(config))
        if args.literals:
            config = json.loads(configuration.read_text())
            config["functions"]["contribution_compute"]["components"]["integer-literals"] = "optional" if args.optimization == "O2" else "required"
            configuration.write_text(json.dumps(config))
        scalars = configure_scalar_gates(args, configuration)
        normalizers = configure_normalizer_gates(args, configuration)
        hybrid_normalizers = configure_hybrid_normalizers(args, configuration)
        if args.hybrid_scalars:
            inputs = json.loads(private.read_text()); inputs["owners"]["contribution_hybrid_literal"] = 37
            private.write_text(json.dumps(inputs))
        if args.grouped: configure_groups(private)
        units = []
        sources = [*args.sources, ROOT / "src/contribution/gate.cpp", ROOT / "tests/contribution/gate_fixture.cpp"]
        if args.automatic: sources.append(ROOT / "tests/contribution/edge_fixture.cpp")
        if args.hybrid: sources.append(ROOT / "tests/contribution/hybrid_fixture.cpp")
        if extended_fixture: sources.append(ROOT / "tests/contribution/preparation_fixture.cpp")
        if args.archive: sources.append(ROOT / "tests/contribution/archive_fixture.cpp")
        for index, source in enumerate(sources):
            unit = directory / f"source-{index}.ll"
            run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
                 *(["-DPYOBF_CONTRIBUTION_PREPARATION_TEST=1"] if extended_fixture else []),
                 *(["-DPYOBF_CONTRIBUTION_SCALAR_DONOR_TEST=1"] if args.scalar_donor else []),
                 *(["-DPYOBF_CONTRIBUTION_ARCHIVE_TEST=1"] if args.archive else []),
                 *(["-DPYOBF_CONTRIBUTION_NORMALIZER_TEST=1"] if args.normalizers else []),
                 *(["-DPYOBF_CONTRIBUTION_HYBRID_NORMALIZER_TEST=1", "-fno-discard-value-names"]
                   if args.hybrid_normalizers and source.name == "hybrid_fixture.cpp" else []),
                 *(["-DPYOBF_CONTRIBUTION_INTERNAL_THROW_TEST=1"] if internal_throw else []),
                 *includes, source, "-o", unit]); units.append(unit)
        if args.normalizers: units.append(ROOT / "tests/contribution/normalizer_fixture.ll")
        if args.region: units.append(ROOT / "tests/contribution/region_fixture.ll")
        if args.hybrid_scalars: units.append(ROOT / "tests/contribution/hybrid_scalar_fixture.ll")
        combined, requested, requests = (directory / name for name in ("combined.ll", "requested.ll", "requests.json"))
        run([args.llvm_link, "-S", *units, "-o", combined])
        if args.hybrid_normalizers: prepare_hybrid_normalizer_input(combined)
        if args.ssa_source:
            promoted = directory / "promoted.ll"
            run([args.opt, "-passes=function(mem2reg)", "-verify-each", "-S", combined, "-o", promoted])
            # Expose genuine argument arithmetic for the conservative clone donor.
            # This is an explicit source input, not a claim about raw frontend-O0 IR.
            combined = promoted
        common = [*plugin, f"-pyobf-cff-config={configuration}"]
        if args.region: common.append("-pyobf-cff-region=contribution_region:region.start:region.out")
        run([*common, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
             "-verify-each", "-S", combined, "-o", requested])
        source = requested
        if args.optimization == "O2":
            source = directory / "optimized.ll"
            run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
        archive_extra = 0
        if args.archive:
            source, requests, archive_info = prepare_archive_gates(args, directory, source, configuration, requests)
        protected, report = directory / "protected.ll", directory / "coverage.json"
        transform = [*common, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}", "-verify-each", "-S", source]
        retained_source = source
        try:
            run([*transform, f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
                *([f"-pyobf-cff-private-map={directory / 'archive-private-map.json'}"] if args.archive else []), "-o", protected])
        except AssertionError:
            if report.exists():
                failed = [row for row in json.loads(report.read_text())["functions"] if row["selected"] and row["status"] != "transformed"]
                (args.build_dir / f"gate-failure-{args.optimization}.json").write_text(report.read_text())
                (args.build_dir / f"gate-failure-{args.optimization}.ll").write_text(source.read_text())
                (args.build_dir / f"gate-failure-{args.optimization}.requests.json").write_text(requests.read_text())
                (args.build_dir / f"gate-failure-{args.optimization}.config.json").write_text(configuration.read_text())
                raise AssertionError([(row["function"], row.get("reason")) for row in failed]) from None
            raise
        run([*plugin, "-passes=pyobf-native-contribution-verify", "-disable-output", protected])
        if args.archive:
            archive_info["private_map"] = json.loads((directory / "archive-private-map.json").read_text())
        graph_count = graph_refusals(args, directory, protected)
        input_count = input_refusals(args, directory, transform, private)
        source_count = source_refusals(args, directory, source, common, requests, private, configuration)
        artifact_refusals(args, directory, combined, protected)
        if args.hybrid: hybrid_count = hybrid_refusals(args, directory, source, configuration, private)
        rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
        input_hash = hashlib.sha256(private.read_bytes()).hexdigest()
        if any(row.get("runtime_contribution", {}).get("private_input_sha256") != input_hash for row in rows
                if "runtime_contribution" in row):
            raise AssertionError("contribution report lost the actual private-input fingerprint")
        authored = [row for row in rows if not row.get("generated")]
        if scalars: check_scalar_gates(rows, scalars, args.hybrid)
        if normalizers: check_normalizer_gates(rows, normalizers, args.optimization, source)
        if hybrid_normalizers: check_hybrid_normalizers(rows, hybrid_normalizers, args.optimization, source)
        hybrid_locals = args.hybrid and args.preparations in ("all", "indexed-locals")
        if hybrid_locals: check_hybrid_locals(rows, source, protected)
        if hybrid_locals and args.optimization == "O2":
            count = normalizer_loss_refusals(args, directory, transform, private, configuration, rows,
                owner_name="contribution_hybrid", selected=("indexed-locals",))
            if not args.ssa_source and count == 0:
                raise AssertionError("raw hybrid source O2 did not exercise original local loss")
            if count: print("required hybrid original local loss refused independently")
        if args.normalizers == "all" and args.optimization == "O2":
            count = normalizer_loss_refusals(args, directory, transform, private, configuration, rows)
            if count == 0: raise AssertionError("normalizer O2 fixture did not exercise original-request loss")
            print(f"{count} required normalizer original-request losses refused independently")
        if args.hybrid_normalizers and args.optimization == "O2":
            count = normalizer_loss_refusals(args, directory, transform, private, configuration, rows,
                owner_name="contribution_hybrid", selected=hybrid_normalizers)
            if count == 0: raise AssertionError("hybrid source O2 did not exercise original normalizer loss")
            print(f"{count} required hybrid normalizer original-request losses refused independently")
        if args.hybrid_normalizers == "all" and args.optimization == "none" and args.frames == "both" and not args.grouped:
            void_completion_cases(args, directory)
        if args.archive: archive_extra = check_archive_gates(rows, archive_info, args.optimization)
        if len(authored) != (48 if args.automatic else 47) + int(args.hybrid) + int(args.hybrid_scalars) + int(args.region) + int(extended_fixture) + int(internal_throw) + archive_extra or any(row["status"] != "transformed" for row in rows):
            raise AssertionError("actual contribution SDK/user scope escaped CFF")
        if args.frames:
            for name in ("contribution_compute", *(("contribution_hybrid",) if args.hybrid else ())):
                row = next(row for row in rows if row["function"] == name)
                applied = {item["component"]: item["applied"] for item in row["components"]}
                if any(applied[component] < 1 for component in (*frames, *(("call-preparation",) if args.call_steps else ()))):
                    raise AssertionError("an intended frame/preparation escaped actual composition")
        if args.bogus:
            for name in ("contribution_compute", *(("contribution_hybrid",) if args.hybrid else ())):
                row = next(row for row in rows if row["function"] == name)
                applied = {item["component"]: item["applied"] for item in row["components"]}
                if row.get("bogus_control_contract_verified") is not True or any(applied[component] < 1 for component in bogus):
                    raise AssertionError(f"an intended bogus/control proof escaped actual composition: {name}: "
                        f"{row.get('bogus_control_contract_verified')}: " + str([
                            item for item in row["components"] if item["component"] in bogus]))
        if args.literals and next(item["applied"] for row in rows if row["function"] == "contribution_compute"
                for item in row["components"] if item["component"] == "integer-literals") < 1:
            raise AssertionError("actual integer hiding escaped the predicate-template composition")
        if args.split and any(next(item["applied"] for item in row["components"] if item["component"] == "split-blocks") < 1
                for row in rows if row["function"] == "contribution_compute"):
            raise AssertionError("actual split preparation escaped contribution composition")
        if args.composed:
            for name in ("contribution_compute", *(("contribution_hybrid",) if args.hybrid else ())):
                row = next(row for row in rows if row["function"] == name)
                applied = {item["component"]: item["applied"] for item in row["components"]}
                if row.get("transition_layer_contract_verified") is not True or any(applied[strategy] < 1 for strategy in strategies):
                    raise AssertionError("an intended transition layer escaped actual composition")
        if args.preparations:
            for owner in ("contribution_compute", *(("contribution_hybrid",) if args.hybrid else ())):
                row = next(row for row in rows if row["function"] == owner)
                applied = {item["component"]: item["applied"] for item in row["components"]}
                if any(applied[name] < 1 for name in preparations):
                    raise AssertionError("a requested initializer preparation escaped actual composition")
        if args.region: region_count = region_acceptance(args, directory, source, protected, configuration, private, rows)
        if args.grouped: group_counts = group_acceptance(args, directory, transform, private, protected, rows)
        if args.automatic:
            check_input_density(source.read_text(), rows)
            policy_count = policy_acceptance(args, directory)
            report_count = report_refusals(rows)
            for row in rows:
                if row["function"] not in ("contribution_compute", "contribution_switch", "contribution_hybrid", "contribution_region", "contribution_archive_value", "contribution_hybrid_literal"): continue
                edges = row["runtime_contribution"]["original_edges"]
                if (not row["runtime_contribution"]["original_real_edge_density_verified"] or
                        edges["original_edges"] == 0 or edges["bound_edges"] != edges["original_edges"] or
                        edges["generated_edges_in_denominator"] != 0 or edges["density_percent"] != 100):
                    raise AssertionError("automatic original-edge density is incomplete")
        text = protected.read_text()
        for row in rows:
            if row["function"] not in ("contribution_compute", "contribution_compute_global", "contribution_switch", "contribution_hybrid", "contribution_region", "contribution_archive_value", "contribution_hybrid_literal"): continue
            owner_body = re.search(rf"(?ms)^define [^\n]*@{re.escape(row['function'])}\([^\n]+\).*?^}}", text)[0]
            query_bodies = sum("call i32 @pyobf_native_contribution_word_v1" in block
                for block in re.split(r"(?m)^[\w.$-]+:.*$", owner_body))
            if row["site_totals"]["body_roles"].get("routing", 0) < query_bodies:
                raise AssertionError("normalized source gateways lost their owned routing role")
        body = re.search(r"(?ms)^define [^\n]*@contribution_compute\([^\n]+\).*?^}", text)[0]
        if "call void @pyobf_native_contribution_site_v1" in body or body.count("call i32 @pyobf_native_contribution_word_v1") < 3:
            raise AssertionError("source points did not become actual scalar queries")
        backend = []
        for index, source in enumerate(args.backend_source):
            obj = directory / f"backend-{index}.obj"
            run([args.compiler, "-std=c++17", "-O2", *(["-flto=thin"] if args.ipo else []), *includes,
                 "-c", source, "-o", obj]); backend.append(obj)
        checker = [sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump]
        forwarded = directory / "forwarded.ll"
        forwarded.write_text(forwarded_query(protected.read_text(), "contribution_hybrid" if args.hybrid else "contribution_region" if args.region else None))
        run([args.opt, "-passes=verify", "-disable-output", forwarded])
        def build_image(label, source):
            obj, binary = directory / (label + ".obj"), directory / (label + ".exe")
            run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", obj])
            run([args.compiler, "-std=c++17", "-O2", obj, *backend, *includes,
                 ROOT / "tests/contribution/gate_host.cpp", *([ROOT / "src/contribution/marker.cpp"] if label == "plain" or args.region else []),
                 *(["-DPYOBF_CONTRIBUTION_AUTO_TEST=1"] if args.automatic else []),
                 *(["-DPYOBF_CONTRIBUTION_HYBRID_TEST=1"] if args.hybrid else []),
                 *(["-DPYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST=1"] if args.hybrid_scalars else []),
                 *(["-DPYOBF_CONTRIBUTION_NORMALIZER_TEST=1"] if args.normalizers else []),
                 *(["-DPYOBF_CONTRIBUTION_COST_TEST=1"] if args.scalar_measurements or args.contribution_measurements else []),
                 *(["-DPYOBF_CONTRIBUTION_REGION_TEST=1"] if args.region else []),
                 *(["-DPYOBF_CONTRIBUTION_GROUPED_TEST=1"] if args.grouped else []),
                 *(["-DPYOBF_CONTRIBUTION_PREPARATION_TEST=1"] if extended_fixture else []),
                 *(["-DPYOBF_CONTRIBUTION_SCALAR_DONOR_TEST=1"] if args.scalar_donor else []),
                 *(["-DPYOBF_CONTRIBUTION_ARCHIVE_TEST=1"] if args.archive else []),
                 *(["-DPYOBF_CONTRIBUTION_INTERNAL_THROW_TEST=1"] if internal_throw else []),
                 *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", binary])
            return binary

        for label, source in (("protected", protected), ("plain", combined), ("forwarded", forwarded)):
            binary = build_image(label, source)
            output = run([binary]).stdout
            if "gate-normal-completed" not in output: raise AssertionError("normal material did not execute the full fixture")
            for mode in (() if label == "forwarded" else ("wrong", "provider", "closed", "unbound", "empty", "foreign",
                    *(("warm-wrong", "warm-provider", "warm-closed", "warm-unbound") if args.archive else ()),
                    *(("source-17", "source-29", "source-41") if args.grouped else ()))):
                try:
                    result = subprocess.run([binary, mode], capture_output=True, text=True, timeout=2)
                    output = result.stdout
                    entered, completed = "gate-enter" in result.stdout, result.returncode == 0 and "gate-normal-completed" in result.stdout
                except subprocess.TimeoutExpired as error:
                    output = error.stdout or ""
                    if isinstance(output, bytes): output = output.decode(errors="replace")
                    entered, completed = "gate-enter" in output, False
                if args.archive and mode.startswith("warm-") and "archive-warm" not in output:
                    raise AssertionError("archive context failure occurred before actual cache warmup")
                if not entered or completed != (label == "plain"):
                    raise AssertionError(f"{label} source observation boundary did not distinguish {mode}")
            final = directory / (label + ".final.json")
            if label == "protected":
                protected_image = binary
                try: verify_image(checker, binary, report, final)
                except AssertionError:
                    assembly = run([args.objdump, "-d", "--disassemble-symbols=contribution_compute", binary]).stdout
                    (args.build_dir / f"gate-machine-failure-{args.optimization}.txt").write_text(assembly)
                    raise
                if args.grouped and not any((args.hybrid, args.region)):
                    grouped_return = grouped_return_refusals(args, directory, protected, report, checker,
                                                              build_image, rows, binary)
                    print(f"grouped owned return routing: {grouped_return[0]} members at one site; "
                          f"{grouped_return[1]} linked detachment and bounded route mutants refused")
                if args.archive:
                    check_archive_image(binary, archive_info)
                    if not args.automatic and args.optimization == "none":
                        archive_count = archive_refusals(args, directory, protected, archive_info, report, checker, build_image)
                        if args.hybrid:
                            archive_count += archive_refusals(args, directory, protected, archive_info, report, checker, build_image,
                                owner="contribution_hybrid")
                if args.composed == "all" and not args.grouped and not args.automatic:
                    layer_count = layer_refusals(args, directory, protected, report, binary, checker, build_image)
                if args.preparations == "all" and not args.hybrid and not args.grouped and not args.automatic and args.optimization == "none":
                    preparation_count = preparation_refusals(args, directory, transform, private, configuration, report, checker, build_image)
                if hybrid_locals and args.optimization == "none" and not any((args.grouped, args.automatic, args.frames)):
                    hybrid_local_refusals(args, directory, transform, private, configuration,
                        protected, report, checker, build_image)
                if args.frame_controls:
                    frame_count = frame_refusals(args, directory, protected, report, binary, checker, build_image)
                if args.automatic and args.normalizers in ("all", "deduplicate-blocks") and args.optimization == "none":
                    positive, negative, reports = alias_acceptance(args, directory, transform, private, configuration, retained_source, combined,
                        rows, checker, build_image)
                    print(f"{positive} compatible alias images/{negative} policy, budget, selection and donor refusals/{reports} independent source-map refusals verified")
                if args.hybrid_normalizers == "all" and args.optimization == "none" and not any((args.automatic, args.grouped, args.frames)):
                    hybrid_normalizer_limits(args, directory, transform, private, configuration, retained_source,
                        rows, checker, build_image)
                if args.scalars == "all" and not args.automatic and args.optimization == "none":
                    scalar_count = scalar_refusals(args, directory, transform, private, configuration, report, checker, build_image)
                if args.bogus and not args.hybrid and not args.grouped and not args.automatic and args.optimization == "none":
                    bogus_count = bogus_refusals(args, directory, protected, report, binary, checker, build_image)
                if args.bogus == "bogus-synthesis" and args.automatic and not args.hybrid and args.optimization == "none" and not args.ssa_source:
                    raw_clone_fallback(args, directory, transform, private, configuration, checker, build_image)
            else:
                rejected = run([*checker, binary, report, "--output", final], succeeds=False)
                if label == "forwarded" and "lost owned contribution query/mask presence" not in rejected.stderr:
                    raise AssertionError("forwarded query failed outside the new final presence gate")
                if final.exists(): raise AssertionError("unverified source points received final CFF proof")
        optional_zero(args, directory, combined, configuration, backend, includes, checker)
        if args.alias_measurements:
            measure_alias_cost(args, directory, transform, private, configuration, retained_source,
                report, protected_image, checker, build_image)
        if args.scalar_measurements:
            measure_scalar_cost(args, directory, transform, private, configuration, retained_source,
                requests, report, protected_image, checker, build_image)
        if args.contribution_measurements:
            measure_contribution_cost(args, directory, combined, private, configuration, retained_source,
                requests, report, protected_image, checker, build_image)
        if (args.composed == "all" or args.scalars == "all") and args.hybrid and not args.grouped and not args.automatic:
            optional_zero(args, directory, combined, configuration, backend, includes, checker, disabled=True)
            print("hybrid data/layers without runtime contribution preserve reference semantics")
        if args.composed == "all" and not args.grouped and not args.automatic:
            print(f"{layer_count} false-proof/individually erased layer graphs and runnable final images refused")
        if args.preparations == "all" and not args.hybrid and not args.grouped and not args.automatic and args.optimization == "none":
            print(f"{preparation_count} closed-marker frame/initializer erasure controls verified")
        if args.frame_controls: print(f"{frame_count} runnable frame/route erasures and helper inventory refusals verified")
        if args.scalars == "all" and not args.automatic and args.optimization == "none":
            print(f"{scalar_count} scalar erasure and strict/optional original-request loss controls verified")
        if args.archive:
            print("actual typed archive acquisitions/key lanes and original semantic edges verified; four warmed-cache context failures refused")
            if not args.automatic and args.optimization == "none":
                print(f"{archive_count} archive key/erasure and strict/optional empty-source controls verified")
        if args.bogus and not args.hybrid and not args.grouped and not args.automatic and args.optimization == "none":
            print(f"{bogus_count} false proof/control/work erasures preserve normal execution but fail retained/final claim")
        if args.grouped: print(f"actual per-point ordered subsets and separate site/query counts verified; {group_counts[0]} group inputs/{group_counts[1]} false reports refused; each member source failure changes behavior")
        if args.hybrid: print(f"hybrid caught/escaping exceptions, exact cleanup, nested call and four concurrent readers verified; {hybrid_count} model/point/budget refusals")
        if args.hybrid_scalars:
            print("actual equal-literal EH returns, condition identity, cleanup/escaping exceptions and concurrent literal invocations verified; source fixture retains closed calls with nomerge")
        if args.region: print(f"region loop/repeated admission and exact outside effects verified; outside markers retained as plain references; {region_count} source/boundary/quota/optimized-away controls")
        if args.automatic: print(f"{policy_count} automatic edge policy cases/{report_count} false report refusals; independent retained-input denominator verified")
        print(f"{len(authored)} authored/{len(rows) - len(authored)} generated definitions; input{'mem2reg' if args.ssa_source else 'frontend-O0'}/source{args.optimization}/IPO{args.ipo}; actual CNG source-gated transitions with argument/global lease, six material/identity failures, {graph_count} valid-IR graph/{input_count} input/{source_count} source-ABI-scope refusals; runnable final-query replacement rejected; three artifact guards and optional-zero no-coverage verified")


if __name__ == "__main__":
    main()
