"""Shared context test build steps; every report is checked against its actual image."""

import hashlib
import json
import subprocess


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=90)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"context CFF command failed: {command}\nexit status: {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def protect(args, directory, prefix, units, expected_count):
    combined, requested = directory / f"{prefix}.ll", directory / f"{prefix}.requested.ll"
    requests = directory / f"{prefix}.requests.json"
    run([args.llvm_link, "-S", *units, "-o", combined])
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
         "-verify-each", "-S", combined, "-o", requested])
    source = requested
    if args.optimization == "O2":
        source = directory / f"{prefix}.optimized.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    transformed, report = directory / f"{prefix}.protected.ll", directory / f"{prefix}.coverage.json"
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
         f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", transformed])
    authored = {row["function"] for row in json.loads(requests.read_text())["functions"]
                if row.get("marker") == "pyobf.native.sdk"}
    selected = {row["function"]: row for row in json.loads(report.read_text())["functions"] if row["selected"]}
    if len(authored) != expected_count or set(selected) != authored or any(
            row["status"] != "transformed" or not row["requested"] for row in selected.values()):
        raise AssertionError(f"authored context/SDK definitions escaped CFF: {len(authored)}, {selected.keys()}")
    native_object = directory / f"{prefix}.obj"
    run([args.compiler, "-O0", "-fno-lto", "-c", transformed, "-o", native_object])
    return combined, native_object, report


def verify_image(checker, binary, report, final):
    run([*checker, binary, report, "--output", final])
    linked = json.loads(final.read_text())
    if (linked["image_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest() or
            linked["input_report_sha256"] != hashlib.sha256(report.read_bytes()).hexdigest() or any(
                not row["final_binary_verified"] for row in linked["functions"] if row["selected"])):
        raise AssertionError("context final evidence is incomplete, stale or belongs to another report")
