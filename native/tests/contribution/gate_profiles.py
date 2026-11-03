"""Stage replay refusal and the explicitly unbound optional-zero profile."""
import json
from pathlib import Path
import re
import sys

from cff_build import run, verify_image
from archive_gate_pipeline import prepare_archive_gates

ROOT = Path(__file__).resolve().parents[2]


def artifact_refusals(args, directory, combined, protected):
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}"]
    for pass_name in ("pyobf-native-cff", "pyobf-native-cff-requests"):
        result = run([*plugin, "-passes=" + pass_name,
            f"-pyobf-cff-requests-output={directory / 'replay-requests.json'}", "-disable-output", protected], succeeds=False)
        if "contribution input already contains" not in result.stderr: raise AssertionError("replay failed outside contribution input guards")
    raw = directory / "raw-query.ll"
    raw.write_text(combined.read_text() + "\ndefine i32 @raw_query(ptr %lease) {\nentry:\n"
        "  %word = call i32 @pyobf_native_contribution_word_v1(ptr %lease, i32 7, i32 11, i32 13, i32 101, i32 17, i32 0)\n"
        "  ret i32 %word\n}\n")
    run([args.opt, "-passes=verify", "-disable-output", raw])
    result = run([*plugin, "-passes=pyobf-native-cff", "-disable-output", raw], succeeds=False)
    if "reserved generated query" not in result.stderr: raise AssertionError("raw generated ABI failed outside its stage guard")


def optional_zero(args, directory, combined, configuration, backend, includes, checker, *, disabled=False):
    config = json.loads(configuration.read_text())
    for owner in config["functions"].values():
        owner["components"]["runtime-contribution"] = "off" if disabled else "optional"
        owner["contribution"] = {"selection": "explicit-points"}
    directory = directory / ("disabled" if disabled else "optional-zero")
    directory.mkdir()
    recipe = directory / "zero.json"; recipe.write_text(json.dumps(config))
    empty = directory / "zero.ll"
    empty.write_text(re.sub(r"(?m)^  call void @pyobf_native_contribution_site_v1[^\n]*\n", "", combined.read_text()))
    requests, requested = directory / "zero.requests.json", directory / "zero.requested.ll"
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={recipe}"]
    if args.region: plugin.append("-pyobf-cff-region=contribution_region:region.start:region.out")
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}", "-S", empty, "-o", requested])
    source = requested
    if args.optimization == "O2":
        source = directory / "zero.optimized.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    if args.archive:
        source, requests, _ = prepare_archive_gates(args, directory, source, recipe, requests)
    protected, report = directory / "zero.protected.ll", directory / "zero.report.json"
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={report}",
         "-verify-each", "-S", source, "-o", protected])
    obj, binary = directory / "zero.obj", directory / "zero.exe"
    run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", obj])
    run([args.compiler, "-std=c++17", "-O2", obj, *backend, *includes, ROOT / "tests/contribution/gate_host.cpp",
         *(["-DPYOBF_CONTRIBUTION_AUTO_TEST=1"] if args.automatic else []),
         *(["-DPYOBF_CONTRIBUTION_HYBRID_TEST=1"] if args.hybrid else []),
         *(["-DPYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST=1"] if args.hybrid_scalars else []),
         *(["-DPYOBF_CONTRIBUTION_NORMALIZER_TEST=1"] if args.normalizers else []),
         *(["-DPYOBF_CONTRIBUTION_REGION_TEST=1"] if args.region else []),
         *(["-DPYOBF_CONTRIBUTION_PREPARATION_TEST=1"] if args.preparations or args.frames else []),
         *(["-DPYOBF_CONTRIBUTION_SCALAR_DONOR_TEST=1"] if args.scalar_donor else []),
         *(["-DPYOBF_CONTRIBUTION_ARCHIVE_TEST=1"] if args.archive else []),
         *(["-DPYOBF_CONTRIBUTION_INTERNAL_THROW_TEST=1"] if args.frames == "internal" and args.hybrid else []),
         *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", binary])
    for mode in ("normal", "wrong", "provider", "closed", "unbound", "empty", "foreign"):
        if "gate-normal-completed" not in run([binary, mode]).stdout:
            raise AssertionError("optional-zero profile changed ordinary reference semantics")
    final = directory / "zero.final.json"
    verify_image(checker, binary, report, final)
    fields = [row["runtime_contribution"] for row in json.loads(final.read_text())["functions"] if "runtime_contribution" in row]
    if len(fields) != (0 if disabled else len(config["functions"])) or any(row["ir_binding_contract_verified"] or row["final_query_presence_verified"] for row in fields):
        raise AssertionError("optional-zero profile received contribution coverage")
