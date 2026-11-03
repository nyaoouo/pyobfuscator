"""Existing archive planning/packing/materialization stages for the actual CNG driver."""
import json
import re
from pathlib import Path
import sys

from cff_build import run
from edge_policies import function_body, input_edge_count

ROOT = Path(__file__).resolve().parents[2]
CORE = tuple(ROOT / "src/archive" / name for name in ("format.cpp", "acquire.cpp", "require.cpp"))


def configure_archive_gates(args, configuration, private):
    if not args.archive:
        return
    config = json.loads(configuration.read_text())
    config["functions"]["contribution_archive_value"] = {"components": {
        "runtime-contribution": "required", "constant-archive": "optional" if args.optimization == "O2" else "required"},
        "contribution": {"selection": "original-edges" if args.automatic else "explicit-points"}}
    if args.hybrid:
        config["functions"]["contribution_hybrid"]["components"]["constant-archive"] = "optional" if args.optimization == "O2" else "required"
    configuration.write_text(json.dumps(config))
    inputs = json.loads(private.read_text())
    inputs["owners"]["contribution_archive_value"] = 35
    private.write_text(json.dumps(inputs))
    args.backend_source = list(dict.fromkeys([*args.backend_source, *args.archive_backend_source]))


def prepare_archive_gates(args, directory, source, configuration, requests):
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", "-verify-each"]
    plan, pending, package, generated, bindings = [directory / ("archive" + suffix)
        for suffix in (".plan.json", ".pending.ll", ".bin", ".cpp", ".bindings.json")]
    run([*plugin, "-passes=pyobf-native-archive-plan", f"-pyobf-cff-config={configuration}",
        f"-pyobf-archive-plan-output={plan}", "-S", source, "-o", pending])
    run([sys.executable, ROOT / "tools/pack_archive.py", plan, package, generated, bindings, "--allow-empty-plan"])
    units = []
    for index, path in enumerate((*CORE, generated)):
        unit = directory / f"archive-runtime-{index}.ll"
        run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
            "-I", ROOT / "include", "-I", ROOT / "src", path, "-o", unit])
        units.append(unit)
    runtime, requested, runtime_requests, merged, linked, prepared = [directory / name for name in (
        "archive-runtime.ll", "archive-runtime.requested.ll", "archive-runtime.requests.json",
        "archive-merged.requests.json", "archive-linked.ll", "archive-prepared.ll")]
    run([args.llvm_link, "-S", *units, "-o", runtime])
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={runtime_requests}",
        "-S", runtime, "-o", requested])
    run([sys.executable, ROOT / "tools/merge_requests.py", merged, requests, runtime_requests])
    run([args.llvm_link, "-S", pending, requested, "-o", linked])
    run([*plugin, "-passes=pyobf-native-archive-materialize", f"-pyobf-archive-bindings={bindings}",
        "-S", linked, "-o", prepared])
    config = json.loads(configuration.read_text())
    owners = [name for name in ("contribution_archive_value", "contribution_hybrid") if
        config.get("functions", {}).get(name, {}).get("components", {}).get("constant-archive", "off") != "off"]
    inventory = {}
    for name in owners:
        body = function_body(prepared.read_text(), name)
        inventory[name] = {"acquisitions": body.count("!pyobf.archive.gate"), "lanes": body.count("!pyobf.archive.key-slot"),
            "original_edges": input_edge_count(source.read_text(), name)}
    info = {"plan": json.loads(plan.read_text()), "bindings": json.loads(bindings.read_text()),
        "owners": inventory, **inventory["contribution_archive_value"]}
    if "contribution_hybrid" in inventory:
        original = function_body(source.read_text(), "contribution_hybrid")
        planned = function_body(prepared.read_text(), "contribution_hybrid")
        controls = r"(?:catch ptr @[^\s,]+|@llvm\.eh\.typeid\.for(?:\.p0)?\(ptr @[^)]+\))"
        if not re.findall(controls, original) or re.findall(controls, original) != re.findall(controls, planned):
            raise AssertionError("archive preparation changed original EH clause/type-ID identities")
    return prepared, merged, info


def check_archive_gates(rows, info, optimization):
    for name, inventory in info["owners"].items():
        row = next(row for row in rows if row["function"] == name)
        sources = row.get("archive_sources", {})
        component = next(item for item in row["components"] if item["component"] == "constant-archive")
        count = sources.get("acquisitions", 0)
        if (not count or count != inventory["acquisitions"] or inventory["lanes"] != count * 8 or count != sources.get("complete_acquisitions") or
                component["applied"] != count * 9 or component["applied_types"].get("key-word32") != count * 8):
            raise AssertionError("actual source-gated archive lacks complete acquisitions/key lanes: " + name)
        if row["runtime_contribution"].get("original_edges", {}).get("original_edges", inventory["original_edges"]) != inventory["original_edges"]:
            raise AssertionError("archive preparation changed the original semantic-edge denominator: " + name)
        print(f"{name}: {count} independent acquisitions/{inventory['lanes']} key lanes verified")
    selected = {row["function"] for row in rows}
    if any(record["wrapper"] not in selected for record in info["bindings"]["records"]):
        raise AssertionError("an actual generated archive wrapper escaped selected CFF")
    for name in ("read32", "read64", "valid_type", "parse_record", "valid_plaintext", "overlaps",
            "verify_access", "decode", "acquire_record", "require_record"):
        if not any(name in owner for owner in selected):
            raise AssertionError("an archive SDK source escaped CFF: " + name)
    kinds = {record["kind"] for record in info["plan"]["records"]}
    if optimization == "none" and not {"bytes", "code_units8", "code_units16", "integer", "binary64"}.issubset(kinds):
        raise AssertionError("typed source-gated archive fixture lost string/bytes/float records")
    return 11 + len(info["bindings"]["records"])
