"""Private plan freshness, strict artifact binding and real host AEAD round trips."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from pe_release_record import finalize_image
from release_format import expansion, record_mask
from release_plan import child_identity, expected_fold, parse_plan, render_header, validate_child
from session_fold_reference import diagnostic_output
from release_material_cases import check_early_material
from payload_binding import requires_bound_child
from post_subjects import artifact_arguments, read_artifacts


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=45)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"private plan command failed: {command}\n{result.stderr[:3000]}")
    return result


def rejects(function):
    try:
        function()
    except ValueError:
        return
    raise AssertionError("malformed private release input was accepted")


def check_payload(header, record, plan, image):
    rows = re.findall(r"inline constexpr unsigned char (\w+)\[\] = \{(.*?)\};", header, re.S)
    arrays = {name: bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", text)) for name, text in rows}
    if len(rows) != 3 or set(arrays) != {"nonce", "tag", "ciphertext"}:
        raise AssertionError("payload header contains a key/fallback or has missing/duplicate fields")
    key = bytes(left ^ right for left, right in zip(record_mask(record), expansion(expected_fold(plan))))
    if AESGCM(key).decrypt(arrays["nonce"], arrays["ciphertext"] + arrays["tag"], b"pyobf-native-demo-v1") != image:
        raise AssertionError("private plan/record did not reconstruct the child AEAD key")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "build_dir", "child_image", "child_report", "raw_image", "image", "finalization"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--measured-plan", type=Path)
    parser.add_argument("--post-material", type=Path)
    parser.add_argument("--post-reference", type=Path)
    parser.add_argument("--post-plan", type=Path)
    parser.add_argument("--pre-release", action="store_true")
    artifact_arguments(parser)
    args = parser.parse_args()
    if (args.post_subjects or args.post_object) and not args.post_plan: parser.error("function subjects need an explicit post plan")
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    image, report = args.child_image.read_bytes(), args.child_report.read_bytes()
    current = parse_plan((args.build_dir / "release-plan.private.json").read_bytes())
    validate_child(current, image, report)
    if (args.build_dir / "path_events_generated.hpp").read_text() != render_header(current):
        raise AssertionError("current generated header differs from its independent input plan")
    record = (args.build_dir / "release-key.record").read_bytes()
    check_payload((args.build_dir / "payload_blob.hpp").read_text(), record, current, image)
    raw, final = args.raw_image.read_bytes(), args.image.read_bytes()
    if args.post_plan:
        from finalize_post_release import verify
        from prepare_scope_material import read_material
        from reference_plan import parse_plan as parse_reference_plan
        if not args.post_material or not args.post_reference: parser.error("post completion needs explicit early source inputs")
        reference_plan = parse_reference_plan(args.post_plan.read_bytes())
        expected_report = verify(raw, final, reference_plan,
            (args.build_dir / "release-material.private.json").read_bytes(), record,
            args.post_reference.read_bytes(), read_material(args.post_material), image, report, current,
            "pyobf_native_demo_outer_unfinalized", pre_release=args.pre_release, **read_artifacts(args, reference_plan))
        expected_final = final
    elif args.measured_plan:
        from finalize_measured_release import verify
        from reference_plan import parse_plan as parse_reference_plan
        from release_material import parse_material
        expected_report = verify(raw, final, parse_reference_plan(args.measured_plan.read_bytes()),
            parse_material((args.build_dir / "release-material.private.json").read_bytes()), record)
        expected_final = final
    else: expected_final, expected_report = finalize_image(raw, record)
    if expected_final != final or json.loads(args.finalization.read_text()) != expected_report:
        raise AssertionError("current final parent is stale or differs from exact raw/data completion")
    bad = []
    def change(path, value):
        result = copy.deepcopy(current)
        place = result
        for key in path[:-1]: place = place[key]
        place[path[-1]] = value
        return result
    for path, value in ((["schema_version"], 2), (["schema_version"], True), (["seed"], -1),
            (["seed"], 1 << 32), (["seed"], True), (["child_image_sha256"], "x" * 64),
            (["child_report_sha256"], None), (["events"], {}),
            (["events", "environment", "word"], "7"), (["events", "release", "tag"], False),
            (["events", "support", "tag"], current["events"]["environment"]["tag"])):
        bad.append(change(path, value))
    missing = copy.deepcopy(current); del missing["seed"]; bad.append(missing)
    extra = copy.deepcopy(current); extra["extra"] = 1; bad.append(extra)
    for document in bad:
        rejects(lambda document=document: parse_plan(json.dumps(document).encode()))
    duplicate = b'{"seed":1,' + json.dumps(current).encode()[1:]
    rejects(lambda: parse_plan(duplicate))
    rejects(lambda: parse_plan(b"x" * 16385))
    rejects(lambda: validate_child(current, image + b"x", report))
    rejects(lambda: validate_child(current, image, report + b"\n"))
    child = json.loads(report)
    for name, value in (("verification_scope", "unverified"), ("strategy", "unknown"), ("functions", [])):
        invalid = dict(child); invalid[name] = value
        rejects(lambda invalid=invalid: child_identity(image, json.dumps(invalid).encode()))
    invalid = copy.deepcopy(child)
    next(row for row in invalid["functions"] if row["selected"])["final_binary_verified"] = False
    rejects(lambda: child_identity(image, json.dumps(invalid).encode()))
    if "bootstrap-fold" in diagnostic_output("bootstrap-fold release 1 2 3\nchecked"):
        raise AssertionError("private key-derived transcript escaped into test diagnostics")
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        check_early_material(args, directory, image, report, current, run, rejects)
        samples = []
        for index in range(2):
            plan_path, header_path = directory / f"plan-{index}.json", directory / f"events-{index}.hpp"
            run([sys.executable, ROOT / "tools/prepare_release.py", args.child_image, args.child_report, plan_path, header_path])
            plan = parse_plan(plan_path.read_bytes())
            validate_child(plan, image, report)
            samples.append(plan)
            source, binary = directory / "header.cpp", directory / "header.exe"
            source.write_text(f'#include "{header_path.name}"\n#include <cstdio>\n'
                'int main(){using namespace pyobfuscator::native::demo::path_events;'
                'unsigned v[]={seed,environment_tag,environment_word,support_tag,support_word,release_tag,release_word};'
                'for(auto x:v)std::printf("%u ",x);}\n')
            run([args.compiler, "-std=c++17", "-O2", source, "-o", binary])
            words = [plan["seed"]] + [plan["events"][role][name] for role in ("environment", "support", "release") for name in ("tag", "word")]
            if list(map(int, run([binary]).stdout.split())) != words:
                raise AssertionError("actual generated C++ descriptors differ from private plan values")
            packed, packed_record = directory / "packed.hpp", directory / "packed.record"
            command = [sys.executable, ROOT / "demo/pack_payload.py", args.child_image, packed, packed_record,
                       plan_path, header_path, args.child_report]
            if requires_bound_child(report):
                previous = {path: path.read_bytes() if path.exists() else None for path in (packed, packed_record)}
                run(command, succeeds=False)
                if any((path.read_bytes() if path.exists() else None) != data for path, data in previous.items()):
                    raise AssertionError("strict child used the child-first unbound packer fallback")
                plan = current
                plan_path.write_text(json.dumps(plan))
                header_path.write_text(render_header(plan))
                command.extend(["--contribution-input", args.build_dir / "payload.binding.private.json"])
                if args.post_plan:
                    command.extend(["--binding-provider", "measured-scope-v1", "--scope-material", args.post_material])
            run(command)
            check_payload(packed.read_text(), packed_record.read_bytes(), plan, image)
            old_header, old_record = packed.read_bytes(), packed_record.read_bytes()
            header_path.write_text(render_header(plan) + "\n")
            run(command, succeeds=False)
            if (packed.read_bytes(), packed_record.read_bytes()) != (old_header, old_record):
                raise AssertionError("header mismatch overwrote existing payload artifacts")
            header_path.write_text(render_header(plan))
            stale = copy.deepcopy(plan); stale["child_image_sha256"] = "0" * 64
            plan_path.write_text(json.dumps(stale))
            run(command, succeeds=False)
            if (packed.read_bytes(), packed_record.read_bytes()) != (old_header, old_record):
                raise AssertionError("stale plan overwrote existing payload artifacts")
        if samples[0] == samples[1] or expected_fold(samples[0]) == expected_fold(samples[1]):
            raise AssertionError("same-child preparations reused fixed descriptor material")
        legacy = directory / "legacy.hpp"
        run([sys.executable, ROOT / "demo/pack_payload.py", args.child_image, legacy], succeeds=False)
        if legacy.exists(): raise AssertionError("legacy raw-key fallback produced a payload")
        collision = directory / "collision.json"
        collision.write_text("preserve")
        run([sys.executable, ROOT / "tools/prepare_release.py", args.child_image, args.child_report,
             collision, collision], succeeds=False)
        if collision.read_text() != "preserve": raise AssertionError("private plan output alias replaced an artifact")
    print("private release: fresh same-child inputs, native header, strict/stale/alias/legacy guards, AEAD round trips and exact raw/final data-only DAG verified")


if __name__ == "__main__":
    main()
