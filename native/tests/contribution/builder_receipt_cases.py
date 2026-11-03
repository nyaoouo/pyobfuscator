"""Exercise a fixed builder receipt with actual linked mixed POST inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))
sys.path.insert(0, str(ROOT / "tools"))

from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
import check_linked_cff  # noqa: E402
import cff_post_mixed_final  # noqa: E402
from pe_layout import parse_image  # noqa: E402


TOOL = ROOT / "demo" / "cff_builder_receipt.py"
FINALIZER = ROOT / "demo" / "check_linked_cff.py"


def refused(action, fragment):
    try:
        action()
    except ValueError as error:
        if fragment not in str(error):
            raise AssertionError(f"unexpected refusal: {error}") from error
        return
    raise AssertionError(f"builder receipt admitted {fragment}")


def run_cli(command, inputs, *, receipt=None, output=None):
    args = [sys.executable, str(TOOL), command]
    for role in ROLES:
        args += [f"--{role.replace('_', '-')}", str(inputs[role])]
    if command == "create":
        args += ["--output", str(output)]
    else:
        args += ["--receipt", str(receipt)]
    return subprocess.run(args, text=True, capture_output=True, check=False)


def run_finalizer(objdump, paths, receipt, output, demo):
    return subprocess.run([sys.executable, str(FINALIZER), *finalizer_args(objdump,
        paths, receipt, output, demo)], text=True, capture_output=True, check=False)


def finalizer_args(objdump, paths, receipt, output, demo):
    return [str(objdump),
        str(paths["image"]), str(paths["report"]), "--output", str(output),
        "--post-mixed-plan", str(paths["plan"]),
        "--post-mixed-private", str(paths["private"]),
        "--post-mixed-material", str(demo / "release-material.private.json"),
        "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
        "--builder-receipt", str(receipt),
        "--builder-input-ir", str(paths["input_ir"]),
        "--builder-object", str(paths["object"])]


def midflight_change(objdump, paths, receipt, output, demo, original_image):
    """A linked file changed after proof must not receive a final report."""
    copied_image = output.with_name("midflight.dll")
    copied_image.write_bytes(original_image)
    candidate = {**paths, "image": copied_image}
    original_proof = cff_post_mixed_final.verify_post_mixed_child
    changed = False

    def change_after_proof(*args, **kwargs):
        nonlocal changed
        proof = original_proof(*args, **kwargs)
        copied_image.write_bytes(original_image + b"\0")
        changed = True
        return proof

    output.write_bytes(b"stale")
    with patch.object(cff_post_mixed_final, "verify_post_mixed_child", change_after_proof), \
            patch.object(sys, "argv", [str(FINALIZER), *finalizer_args(
                objdump, candidate, receipt, output, demo)]):
        try:
            check_linked_cff.main()
        except SystemExit as error:
            if "builder receipt verification failed" not in str(error):
                raise AssertionError(f"unexpected midflight refusal: {error}") from error
        else:
            raise AssertionError("finalizer admitted a PE changed after the machine proof")
    if not changed or output.exists():
        raise AssertionError("midflight mutation did not run or left a stale final report")


def malformed_cases(frozen, inputs):
    document = json.loads(frozen)
    refused(lambda: verify_receipt(b"{", inputs), "invalid JSON")
    refused(lambda: verify_receipt(frozen[:-1] + b" ", inputs), "canonical")
    refused(lambda: verify_receipt(b'{"schema_version":1,"schema_version":1}', inputs), "duplicate")
    for field in ("schema_version", "profile", "inputs"):
        changed = dict(document)
        del changed[field]
        refused(lambda changed=changed: verify_receipt(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n", inputs),
            "schema")
    for field in ("profile", "inputs"):
        changed = dict(document)
        changed[field] = "wrong" if field == "profile" else {"image": "0" * 64}
        refused(lambda changed=changed: verify_receipt(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n", inputs),
            "schema")
    changed = dict(document)
    changed["extra"] = True
    refused(lambda: verify_receipt(
        json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n", inputs),
        "schema")
    changed = json.loads(frozen)
    changed["inputs"]["image"] = "F" * 64
    refused(lambda: verify_receipt(
        json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n", inputs),
        "schema")
    changed = json.loads(frozen)
    del changed["inputs"]["object"]
    refused(lambda: verify_receipt(
        json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n", inputs),
        "schema")
    refused(lambda: create_receipt({"image": inputs["image"]}), "exact")
    refused(lambda: create_receipt({**inputs, "extra": b""}), "exact")
    refused(lambda: create_receipt({**inputs, "object": "text"}), "bytes")


def _changed_text_image(image):
    layout = parse_image(image)
    section = next(section for section in layout.layout.sections
                   if section.name == b".text" and section.raw_size >= 64)
    changed = bytearray(image)
    changed[section.raw_offset + 32] ^= 1
    return bytes(changed)


def cmake_refusal(cmake, build, paths, receipt, changed_image):
    """A changed linked PE must fail the existing final target without refreshing trust."""
    image_path = paths["image"]
    original_image = image_path.read_bytes()
    original_receipt = receipt.read_bytes()
    final_report = build / "demo" / "payload.cff.final.json"
    try:
        image_path.write_bytes(changed_image)
        final_report.unlink(missing_ok=True)
        command = subprocess.run([str(cmake), "--build", str(build),
                                  "--target", "pyobf_native_demo_outer", "-j", "4"],
                                 text=True, capture_output=True, check=False)
        if (command.returncode == 0 or final_report.exists() or
                "builder receipt verification failed" not in command.stdout + command.stderr or
                receipt.read_bytes() != original_receipt):
            raise AssertionError("CMake refreshed trust or admitted a changed linked PE: "
                                 + command.stdout[-1200:] + command.stderr[-1200:])
    finally:
        image_path.write_bytes(original_image)
    restored = subprocess.run([str(cmake), "--build", str(build),
                               "--target", "pyobf_native_demo_outer", "-j", "4"],
                              text=True, capture_output=True, check=False)
    if (restored.returncode or not final_report.exists() or
            receipt.read_bytes() != original_receipt):
        raise AssertionError("CMake did not recover the original fixed inputs: "
                             + restored.stdout[-1200:] + restored.stderr[-1200:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("input_ir", type=Path)
    parser.add_argument("--objdump", type=Path)
    parser.add_argument("--cmake", type=Path)
    args = parser.parse_args()
    demo = args.build / "demo"
    paths = {"image": demo / "libpyobf_native_demo_inner.dll",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json",
             "input_ir": args.input_ir,
             "object": demo / "payload.cff.obj"}
    inputs = {role: paths[role].read_bytes() for role in ROLES}
    frozen = create_receipt(inputs)
    proof = verify_receipt(frozen, inputs)
    if not proof["verified"] or set(proof["inputs"]) != set(ROLES):
        raise AssertionError("actual mixed POST input receipt lacks a closed six-role proof")
    malformed_cases(frozen, inputs)

    changed_image = _changed_text_image(inputs["image"])
    fixed_report = {**inputs, "image": changed_image}
    refused(lambda: verify_receipt(frozen, fixed_report), "image bytes")
    for role in ROLES[1:]:
        changed = {**inputs, role: inputs[role] + b"\0"}
        refused(lambda changed=changed, role=role: verify_receipt(frozen, changed),
                f"{role} bytes")
    changed_private = inputs["private"] + b" "
    old_sha = hashlib.sha256(inputs["private"]).hexdigest().encode("ascii")
    new_sha = hashlib.sha256(changed_private).hexdigest().encode("ascii")
    if old_sha not in inputs["report"]:
        raise AssertionError("real compiler report lacks the original private digest")
    changed_report = inputs["report"].replace(old_sha, new_sha)
    json.loads(changed_private)
    json.loads(changed_report)
    paired = {**inputs, "image": changed_image, "private": changed_private,
              "report": changed_report}
    refused(lambda: verify_receipt(frozen, paired), "image bytes")
    if not verify_receipt(create_receipt(paired), paired)["verified"]:
        raise AssertionError("a replaced receipt should model the out-of-scope trust boundary")

    with TemporaryDirectory(dir=args.build) as directory:
        temp = Path(directory)
        receipt_path = temp / "builder.json"
        created = run_cli("create", paths, output=receipt_path)
        if created.returncode or receipt_path.read_bytes() != frozen:
            raise AssertionError(f"CLI did not freeze actual builder inputs: {created.stderr}")
        accepted = run_cli("verify", paths, receipt=receipt_path)
        if accepted.returncode or not json.loads(accepted.stdout)["verified"]:
            raise AssertionError(f"CLI refused the original fixed receipt: {accepted.stderr}")
        mutated = {role: temp / f"{role}.bin" for role in ROLES}
        for role in ROLES:
            mutated[role].write_bytes(paired[role])
        denied = run_cli("verify", mutated, receipt=receipt_path)
        if denied.returncode == 0 or "image bytes" not in denied.stderr:
            raise AssertionError("CLI admitted a paired PE/report/private replacement")
        if args.objdump is not None:
            final_output = temp / "final.json"
            accepted_final = run_finalizer(args.objdump, paths, receipt_path,
                                           final_output, demo)
            if (accepted_final.returncode or
                    json.loads(final_output.read_text())["builder_consistency"]["verified"] is not True):
                raise AssertionError(f"linked finalizer refused fixed builder inputs: {accepted_final.stderr}")
            for label, candidate in (("fixed-report", {**paths, "image": mutated["image"]}),
                                     ("paired", mutated)):
                final_output.write_bytes(b"stale")
                denied_final = run_finalizer(args.objdump, candidate, receipt_path,
                                             final_output, demo)
                if (denied_final.returncode == 0 or final_output.exists() or
                        "builder receipt verification failed" not in denied_final.stderr):
                    raise AssertionError(f"linked finalizer admitted {label}: {denied_final.stderr}")
            midflight_change(args.objdump, paths, receipt_path, final_output,
                             demo, inputs["image"])
        missing = {**paths, "object": temp / "absent.obj"}
        stale = temp / "stale.json"
        stale.write_bytes(frozen)
        failed_create = run_cli("create", missing, output=stale)
        if failed_create.returncode == 0 or stale.exists():
            raise AssertionError("failed create left a stale trusted receipt")
        same_path = run_cli("create", paths, output=paths["image"])
        if same_path.returncode == 0 or paths["image"].read_bytes() != inputs["image"]:
            raise AssertionError("create clobbered a linked input")
    if args.cmake is not None:
        frozen_receipt = args.build / "builder.fixed.json"
        if frozen_receipt.read_bytes() != frozen:
            raise AssertionError("CMake's receipt differs from the final linked inputs")
        cmake_refusal(args.cmake, args.build, paths, frozen_receipt, changed_image)
    print("builder receipt: actual mixed PE/report/private/plan/IR/object accepted; "
          "fixed-report, paired, per-role, midflight, schema and stale-output negatives refused; "
          "replaced receipt remains outside the builder-controlled boundary")


if __name__ == "__main__":
    main()
