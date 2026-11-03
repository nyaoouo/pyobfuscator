"""Actual production emission and early-policy/data-only records for generated subjects."""
import hashlib
import json
from pathlib import Path
import sys

from check_capture import ROOT, check_native
from cff_build import run
from code_reference import plaintext, verify_reference
from finalize_references import finalize, _subject
from function_inventory import Ownership, create
from reference_plan import parse_plan
from reference_slots import locate, render_header, render_source
from pe_layout import parse_image
from release_material import create_material, material_fold


def check_slots(args, work, native, ir, report, refuses):
    source, build = work / "emit-source", work / "emit-build"
    source.mkdir()
    def quote(path): return '"' + Path(path).resolve().as_posix() + '"'
    emitted = work / "emitted.obj"
    manifest = Path(str(emitted) + ".ownership.json")
    (source / "CMakeLists.txt").write_text('cmake_minimum_required(VERSION 3.24)\nproject(owned_emission LANGUAGES CXX)\n' +
        f'include({quote(ROOT / "cmake/LLVMCompile.cmake")})\n' +
        f'pyobf_native_emit_object({quote(emitted)} {quote(ir)} FUNCTION_SECTIONS OWNERSHIP_REPORT {quote(report)})\n' +
        f'add_custom_target(emission ALL DEPENDS {quote(emitted)} {quote(manifest)})\n', encoding="utf-8")
    run([args.cmake, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}", f"-DCMAKE_CXX_COMPILER={args.compiler}",
        f"-DPython3_EXECUTABLE={sys.executable}", "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON", "-S", source, "-B", build])
    command = [args.cmake, "--build", build, "--target", "emission"]
    run(command)
    if emitted.read_bytes() != native.read_bytes() or manifest.read_bytes() != create(native.read_bytes(), ir.read_bytes(), report.read_bytes()):
        raise AssertionError("production emission changed code or detached its exact ownership provenance")
    before = [(path.stat().st_mtime_ns, path.read_bytes()) for path in (emitted, manifest)]
    if "no work to do" not in run(command).stdout or before != [(path.stat().st_mtime_ns, path.read_bytes()) for path in (emitted, manifest)]:
        raise AssertionError("unchanged ownership emission regenerated native code or sidecar")
    manifest.unlink()
    run(command)
    if emitted.read_bytes() != native.read_bytes() or manifest.read_bytes() != before[1][1]:
        raise AssertionError("missing ownership output did not rebuild its exact production provenance")
    selection = {"symbol": "owned_root", "aliases": [], "fragments": [], "generated_helpers": True}
    document = {"schema_version": 1, "build_seed": "11" * 16, "container": "22" * 16,
        "records": [{"image": "22" * 16, "owner": 7, "subject": 0x611, "kind": 3, "stage": 2,
            "capacity": 4096, "selector": selection}]}
    plan_data = json.dumps(document).encode()
    plan = parse_plan(plan_data)
    document["records"][0]["selector"]["generated_helpers"] = False
    legacy = parse_plan(json.dumps(document).encode())
    if legacy.records[0].identity.build == plan.records[0].identity.build:
        raise AssertionError("generated coverage policy was not fixed before codegen")
    document["records"][0]["selector"]["generated_helpers"] = 1
    refuses(lambda: parse_plan(json.dumps(document).encode()), "Boolean")
    (work / "reference_slots.hpp").write_text(render_header(plan), encoding="utf-8")
    store = work / "store.cpp"; store.write_text(render_source(plan), encoding="utf-8")
    raw = work / "stored.dll"
    run([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-shared", "-I", work, "-I", ROOT / "src", emitted,
        store, ROOT / "tests/measurement/generated_support.cpp", "-o", raw])
    material = create_material(); words = material_fold(material)
    original = raw.read_bytes(); objects = {0: emitted.read_bytes()}
    ownership = {0: Ownership(manifest.read_bytes(), report.read_bytes())}
    completed, proof = finalize(original, plan, words, objects=objects, ownership=ownership)
    if len(proof["records"][0]["ranges"]) != 3 or proof["records"][0]["ownership_sha256"] != hashlib.sha256(manifest.read_bytes()).hexdigest():
        raise AssertionError("reserved record silently dropped generated contributions")
    subject = _subject(completed, plan.records[0], objects[0], ownership[0])
    _, section, slots = locate(completed, plan)
    package = completed[section.raw_offset + slots.offsets[0]:section.raw_offset + slots.offsets[0] + 4096]
    verify_reference(package, plaintext(completed, subject, plan.records[0].identity), plan.records[0].identity, words)
    again, again_proof = finalize(completed, plan, words, objects=objects, ownership=ownership)
    if again != completed or not again_proof["idempotent"]: raise AssertionError("generated reference fill fed back into code")
    output = work / "stored-final.dll"; output.write_bytes(completed)
    check_native(args.probe, args.runtime_directory, work, output, completed, parse_image(completed), subject)
    refuses(lambda: finalize(original, plan, words, objects=objects), "exactly cover")
    refuses(lambda: finalize(original, legacy, words, objects=objects, ownership=ownership), "exactly cover")
    check_cli(work, raw, emitted, ir, report, manifest, material, plan_data)


def check_cli(work, raw, native, ir, report, manifest, material, plan_data):
    plan_path, material_path = work / "plan.json", work / "material.json"
    plan_path.write_bytes(plan_data); material_path.write_text(json.dumps(material), encoding="utf-8")
    output, result = work / "cli.dll", work / "cli.json"
    command = [sys.executable, ROOT / "tools/finalize_references.py", raw, plan_path, material_path]
    objects = ["--object", f"0={native}"]
    owned = ["--ownership", f"0={manifest}", "--ownership-report", f"0={report}"]
    run([*command, output, "--report", result, *objects, *owned])
    data = output.read_bytes()
    # Fresh sealing uses random nonces; authenticate its contents instead of
    # requiring ciphertext equality with a separate finalization invocation.
    completed, proof = finalize(data, parse_plan(plan_data), material_fold(material), objects={0: native.read_bytes()},
        ownership={0: Ownership(manifest.read_bytes(), report.read_bytes())})
    emitted_proof = json.loads(result.read_bytes())
    def contents(rows):
        # The same-container image hash changes when its data slots are filled.
        return [{key: value for key, value in row.items() if key != "target_sha256"} for row in rows]
    if (completed != data or not proof["idempotent"] or emitted_proof["idempotent"] or
            contents(emitted_proof["records"]) != contents(proof["records"])):
        raise AssertionError("ownership CLI differs from actual authenticated data-only finalization")
    inputs = (raw, plan_path, material_path, native, ir, report, manifest, output, result)
    def reject(arguments, reason):
        snapshots = {path: path.read_bytes() for path in inputs}
        failure = run(arguments, succeeds=False)
        if reason not in failure.stderr or any(path.read_bytes() != data for path, data in snapshots.items()):
            raise AssertionError(f"ownership CLI refused incorrectly or changed an artifact: {failure.stderr}")
    for alias in (manifest, report):
        reject([*command, alias, "--report", result, *objects, *owned], "must not alias")
        reject([*command, output, "--report", alias, *objects, *owned], "must not alias")
    reject([*command, output, "--report", result, *objects], "exactly cover")
    reject([*command, output, "--report", result, *objects, "--ownership", f"0={manifest}"], "identical record indices")
    reject([*command, output, "--report", result, *objects, *owned, "--ownership", f"0={manifest}"], "duplicate artifact")
    reject([*command, output, "--report", result, *objects, "--ownership", f"00={manifest}",
        "--ownership-report", f"0={report}"], "canonical record index")
    stale = work / "stale-report.json"; stale.write_bytes(report.read_bytes() + b" ")
    reject([*command, output, "--report", result, *objects, "--ownership", f"0={manifest}",
        "--ownership-report", f"0={stale}"], "stale")
    missing = work / "missing-ownership.json"
    reject([*command, output, "--report", result, *objects, "--ownership", f"0={missing}",
        "--ownership-report", f"0={report}"], missing.name)
    inventory = [sys.executable, ROOT / "tools/function_inventory.py", native, ir, report]
    for alias in (native, ir, report):
        reject([*inventory, alias], "must be distinct")
