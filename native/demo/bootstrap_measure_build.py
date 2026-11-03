"""Build same-source production bootstrap pairs with explicit phase cost scopes."""

import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_cff_transition_depth import run
from measure_cff import digest, text_size
from pe_release_record import finalize_image
from session_fold_reference import verify_coverage
import measured_artifacts


def timed(command):
    start = time.perf_counter()
    result = run(list(map(str, command)))
    return result, time.perf_counter() - start


def backend_objects(args, directory, root):
    objects = []
    sources = [*args.backend_source, measured_artifacts.record_source(args, root)]
    rows = []
    for index, source in enumerate(sources):
        obj = directory / f"backend-{index}.obj"
        _, seconds = timed([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-I", root / "include",
                            "-I", root / "src", "-c", source, "-o", obj])
        objects.append(obj)
        rows.append({"source": str(source), "source_sha256": digest(source), "compile_seconds": seconds})
    marker = directory / "marker.obj"
    _, seconds = timed([args.compiler, "-std=c++17", "-O2", "-fno-lto", "-I", root / "include",
                        "-c", root / "src/path_fold/marker.cpp", "-o", marker])
    rows.append({"source": "src/path_fold/marker.cpp", "source_sha256": digest(root / "src/path_fold/marker.cpp"),
                 "compile_seconds": seconds, "scope": "plain reference runtime only"})
    return objects, marker, rows


def prepare(args, directory, root, name, optimization, *, decoy):
    combined = args.build_dir / (name + ".combined.ll")
    config = args.decoy_configuration if decoy else args.configuration
    prefix = directory / (name + "-" + optimization)
    requested, requests = prefix.with_suffix(".requested.ll"), prefix.with_suffix(".requests.json")
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}", f"-pyobf-cff-seed={args.seed}"]
    _, request_seconds = timed([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
                               "-verify-each", "-S", combined, "-o", requested])
    source = requested
    optimize_seconds = 0.0
    if optimization == "O2":
        source = prefix.with_suffix(".optimized.ll")
        _, optimize_seconds = timed([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    transformed, report = prefix.with_suffix(".cff.ll"), prefix.with_suffix(".coverage.json")
    _, cff_seconds = timed([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
        f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", transformed])
    rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
    authored = [row for row in rows if not row.get("generated")]
    measured_count = (71 if args.post_inputs and not args.post_pre_release else 73 + 4 * bool(args.post_inputs)) if args.measured_inputs else 0
    if name in args.reader_inputs: measured_count += 3 * len(args.measured_inputs[1][name][0].records)
    if (len(authored) != (74 if decoy else 66) + measured_count or any(row["status"] != "transformed" for row in rows) or
            any(not row["requested"] for row in authored)):
        raise AssertionError("measured production outer changed its authored CFF scope")
    verify_coverage(rows, decoy=decoy)
    record = {"combined_ir_sha256": digest(combined), "recipe_sha256": digest(config),
              "request_seconds": request_seconds, "ordinary_optimize_seconds": optimize_seconds,
              "cff_seconds": cff_seconds, "selected_functions": len(rows)}
    return source, transformed, report, prefix, record


def image(args, root, source, output, objects, marker, coverage, *, name, protected, protected_emission=None):
    native_object, raw = output.with_suffix(".obj"), output.with_suffix(".raw.dll")
    emission = ["-ffunction-sections"] if measured_artifacts.function_sections(args, name) else []
    _, codegen_seconds = timed([args.compiler, "-O0", "-fno-lto", *emission, "-c", source, "-o", native_object])
    _, link_seconds = timed([args.compiler, "-shared", "-fno-lto", native_object, *objects, *measured_artifacts.objects(args, name),
                            *([] if protected else [marker]), *(f"-l{name}" for name in args.library), "-o", raw])
    begin = time.perf_counter()
    ownership = measured_artifacts.emission_ownership(args, name, native_object, source, coverage if protected else None, run)
    completed = measured_artifacts.complete(args, raw.read_bytes(), name, parent_object=native_object, parent_ownership=ownership)
    output.write_bytes(completed)
    completion_seconds = time.perf_counter() - begin
    final_report = output.with_suffix(".final.json")
    command = [sys.executable, root / "demo/check_linked_cff.py", args.objdump, output, coverage, "--output", final_report]
    if name in args.reader_inputs:
        receipt = Path(str(native_object) + ".ownership.json")
        receipt.write_bytes(ownership.manifest)
        if protected:
            command.extend(measured_artifacts.reader_arguments(args, name, native_object=native_object, inventory_path=receipt))
        else:
            if protected_emission is None: raise ValueError("plain reader negative needs this pair's fresh protected emission")
            command.extend(measured_artifacts.reader_arguments(args, name,
                native_object=protected_emission[0], inventory_path=protected_emission[1]))
    begin = time.perf_counter()
    run_result = run(list(map(str, command)), succeeds=protected)
    verify_seconds = time.perf_counter() - begin
    if protected:
        final = json.loads(final_report.read_text())
        if final["image_sha256"] != digest(output) or any(not row["final_binary_verified"] for row in final["functions"] if row["selected"]):
            raise AssertionError("measured protected outer has stale or partial final evidence")
    elif final_report.exists(): raise AssertionError("measured plain image received CFF proof")
    elif name in args.reader_inputs and "owner reader final evidence failed" not in run_result.stderr:
        raise AssertionError("plain owner counterpart failed outside its actual code contribution boundary")
    return {"image_sha256": digest(output), "file_bytes": output.stat().st_size, "text_bytes": text_size(args.objdump, output),
            "function_objects": measured_artifacts.function_object_digests(args, name, native_object),
            "function_ownership": measured_artifacts.function_ownership_digests(args, name, native_object, ownership),
            "owner_reader_emission": {"object_sha256": digest(native_object),
                "inventory_sha256": digest(receipt), "compiler_report_sha256":
                hashlib.sha256(ownership.report).hexdigest(), "plan_sha256": args.measured_inputs[1][name][0].digest.hex(),
                "owner_count": len(args.measured_inputs[1][name][0].records)} if name in args.reader_inputs else {},
            "codegen_seconds": codegen_seconds, "link_seconds": link_seconds,
            "data_completion_seconds": completion_seconds, "final_check_seconds": verify_seconds,
            "final_check": "accepted" if protected else "same-source-rejected"}
