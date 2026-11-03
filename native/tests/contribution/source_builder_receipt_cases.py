"""Prove a fixed builder receipt against an actual two-site source-mixed PE."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"),
                str(ROOT / "tests/contribution"), str(ROOT / "tests/context"),
                str(ROOT / "tests/measurement")]

from cff_build import run  # noqa: E402
from cff_builder_receipt import (PROFILE, SOURCE_PROFILE, create_receipt,
                                 verify_receipt)  # noqa: E402
from cff_joint_machine_evidence import STACK, _instructions  # noqa: E402
from cff_source_mixed_helper_routes import BINDING  # noqa: E402
from linked_machine_mutations import _replace  # noqa: E402
from pe_layout import parse_image  # noqa: E402
from source_mixed_cff import two_site_input  # noqa: E402


ROLES = ("image", "report", "private", "input_ir", "object")
TOOL = ROOT / "demo" / "cff_builder_receipt.py"
FINALIZER = ROOT / "demo" / "check_linked_cff.py"
BINDING_SYMBOL = ("_ZN12pyobfuscator6native12contribution6scoped12_GLOBAL__N_1"
                  "15require_bindingERKNS2_5ScopeERKNS0_21BootstrapContextLeaseE")


def command(args, *items):
    return subprocess.run([str(item) for item in items], text=True,
                          capture_output=True, check=False, timeout=60)


def finalizer(args, image, report, private, receipt, input_ir, obj, output):
    return command(args, sys.executable, FINALIZER, args.objdump, image, report,
                   "--contribution-input", private, "--builder-receipt", receipt,
                   "--builder-input-ir", input_ir, "--builder-object", obj,
                   "--output", output)


def reject_final(args, image, report, private, receipt, input_ir, obj, output):
    output.write_bytes(b"stale")
    result = finalizer(args, image, report, private, receipt, input_ir, obj, output)
    if (result.returncode == 0 or output.exists() or
            "builder receipt verification failed" not in result.stderr):
        raise AssertionError("fixed builder receipt admitted changed source-mixed inputs: "
                             + result.stderr[-1200:])


def actual_inputs(args, directory):
    config = directory / "three-two.config.json"
    config.write_text(json.dumps({"schema_version": 1, "functions": {
        "mixed_site_body": {"components": {"runtime-contribution": "required",
                                            "external-calls": "required"},
                            "contribution": {"selection": "explicit-points"}}}}))
    private = directory / "three-two.private.json"
    private.write_text(json.dumps(two_site_input(True)))
    raw = directory / "three-two.ll"
    requested = directory / "three-two.requested.ll"
    requests = directory / "three-two.requests.json"
    protected = directory / "three-two.protected.ll"
    report = directory / "three-two.coverage.json"
    obj = directory / "three-two.obj"
    image = directory / "three-two.exe"
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone",
         "-DPYOBF_TWO_MIXED_SITES", "-S", "-emit-llvm", *includes,
         ROOT / "tests/contribution/source_mixed_body.cpp", "-o", raw])
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={config}"]
    run([*plugin, "-passes=pyobf-native-cff-requests",
         f"-pyobf-cff-requests-output={requests}", "-verify-each", "-S",
         raw, "-o", requested])
    run([*plugin, "-passes=pyobf-native-cff",
         f"-pyobf-cff-requests-input={requests}",
         f"-pyobf-cff-contribution-input={private}", f"-pyobf-cff-report={report}",
         "-verify-each", "-S", requested, "-o", protected])
    run([args.compiler, "-O0", "-fno-lto", "-c", protected, "-o", obj])
    core = list(dict.fromkeys([*args.core, *args.backend]))
    run([args.compiler, "-std=c++17", "-O2", "-DPYOBF_TWO_MIXED_SITES",
         "-DPYOBF_THREE_OWNED_WORDS", obj,
         ROOT / "tests/contribution/mixed_site_probe.cpp", *core, *includes,
         "-lbcrypt", "-o", image])
    return {"image": image, "report": report, "private": private,
            "input_ir": requested, "object": obj}


def machine_mutants(args, directory, image_path):
    image = image_path.read_bytes()
    layout = parse_image(image)
    helper_code = subprocess.check_output([str(args.objdump), "-d",
        f"--disassemble-symbols={BINDING_SYMBOL}", str(image_path)], text=True, timeout=20)
    helper = _instructions(helper_code.lower(), image, BINDING)
    branch = next((item for item in helper if item.opcode == "jne" and
                   item.raw == bytes.fromhex("75 05")), None)
    if branch is None:
        raise AssertionError("real require_binding lacks the recorded jne 75 05 red shape")
    branch_image = directory / "binding-branch-nop.exe"
    branch_image.write_bytes(_replace(image, layout, branch, bytes.fromhex("66 90")))

    body_code = subprocess.check_output([str(args.objdump), "-d",
        "--disassemble-symbols=mixed_site_body", str(image_path)], text=True, timeout=20)
    body = _instructions(body_code.lower(), image, "mixed_site_body")
    first_branch = min(item.address for item in body if item.opcode in ("jmp", "jmpq", "jae"))
    state = [item for item in body if item.address < first_branch and
             item.opcode == "movl" and len(item.operands) == 2 and
             item.operands[0] == "$0x9f6a197" and STACK.fullmatch(item.operands[1])]
    if len(state) != 1 or len(state[0].raw) < 5:
        raise AssertionError("real entry lacks the recorded 0x09f6a197 initializer")
    state_image = directory / "alternate-entry-state.exe"
    state_image.write_bytes(_replace(image, layout, state[0],
        state[0].raw[:-4] + struct.pack("<I", 0xffffffff)))
    if any(path.stat().st_size != image_path.stat().st_size for path in
           (branch_image, state_image)):
        raise AssertionError("machine red changed the PE length")
    return branch_image, state_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump",
                 "runtime_directory", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("optimization", choices=("none",))
    parser.add_argument("--core", nargs="+", type=Path, required=True)
    parser.add_argument("--backend", nargs="+", type=Path, required=True)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.runtime_directory) + os.pathsep + os.environ.get("PATH", "")
    with TemporaryDirectory(prefix="source-builder-receipt-", dir=args.build_dir) as scratch:
        directory = Path(scratch)
        paths = actual_inputs(args, directory)
        inputs = {role: path.read_bytes() for role, path in paths.items()}
        frozen = create_receipt(inputs, profile=SOURCE_PROFILE)
        proof = verify_receipt(frozen, inputs, profile=SOURCE_PROFILE)
        if proof["profile"] != SOURCE_PROFILE or set(proof["inputs"]) != set(ROLES):
            raise AssertionError("source receipt did not seal its exact five roles")
        receipt = directory / "builder.fixed.json"
        receipt.write_bytes(frozen)
        output = directory / "source.final.json"
        accepted = finalizer(args, paths["image"], paths["report"], paths["private"],
                             receipt, paths["input_ir"], paths["object"], output)
        if accepted.returncode or json.loads(output.read_text())["builder_consistency"]["scope"] != SOURCE_PROFILE:
            raise AssertionError("actual two-site source-mixed finalizer refused: " + accepted.stderr)
        branch_image, state_image = machine_mutants(args, directory, paths["image"])
        for changed in (branch_image, state_image):
            reject_final(args, changed, paths["report"], paths["private"], receipt,
                         paths["input_ir"], paths["object"], output)
        paired_private = directory / "paired.private.json"
        paired_private.write_bytes(inputs["private"] + b" ")
        original_hash = hashlib.sha256(inputs["private"]).hexdigest().encode("ascii")
        changed_hash = hashlib.sha256(paired_private.read_bytes()).hexdigest().encode("ascii")
        if original_hash not in inputs["report"]:
            raise AssertionError("actual source-mixed report lacks private digest")
        paired_report = directory / "paired.coverage.json"
        paired_report.write_bytes(inputs["report"].replace(original_hash, changed_hash))
        json.loads(paired_report.read_bytes())
        reject_final(args, branch_image, paired_report, paired_private, receipt,
                     paths["input_ir"], paths["object"], output)
        if verify_receipt(create_receipt({**inputs, "image": branch_image.read_bytes(),
                "report": paired_report.read_bytes(), "private": paired_private.read_bytes()},
                profile=SOURCE_PROFILE), {**inputs, "image": branch_image.read_bytes(),
                "report": paired_report.read_bytes(), "private": paired_private.read_bytes()},
                profile=SOURCE_PROFILE)["verified"] is not True:
            raise AssertionError("whole receipt replacement boundary changed")
        mixed_inputs = {**inputs, "plan": b"real-plan-only-in-mixed-profile"}
        mixed = create_receipt(mixed_inputs)
        mixed_receipt = directory / "wrong-profile.json"
        mixed_receipt.write_bytes(mixed)
        reject_final(args, paths["image"], paths["report"], paths["private"],
                     mixed_receipt, paths["input_ir"], paths["object"], output)
        try:
            verify_receipt(mixed, inputs, profile=SOURCE_PROFILE)
        except ValueError as error:
            if "profile" not in str(error):
                raise AssertionError(f"wrong cross-profile refusal: {error}") from error
        else:
            raise AssertionError("source profile admitted mixed POST receipt")
        source_with_plan = {**inputs, "plan": b"extra"}
        try:
            create_receipt(source_with_plan, profile=SOURCE_PROFILE)
        except ValueError as error:
            if "exact" not in str(error):
                raise AssertionError(f"wrong extra-role refusal: {error}") from error
        else:
            raise AssertionError("source profile admitted an invented plan")
        cli = command(args, sys.executable, TOOL, "create", "--profile", SOURCE_PROFILE,
                      *[part for role, path in paths.items() for part in
                        (f"--{role.replace('_', '-')}", path)],
                      "--output", directory / "source.cli.json")
        if cli.returncode or (directory / "source.cli.json").read_bytes() != frozen:
            raise AssertionError("source profile CLI create differed from API: " + cli.stderr)
        cli = command(args, sys.executable, TOOL, "verify", "--profile", SOURCE_PROFILE,
                      *[part for role, path in paths.items() for part in
                        (f"--{role.replace('_', '-')}", path)],
                      "--receipt", directory / "source.cli.json")
        if cli.returncode or json.loads(cli.stdout)["profile"] != SOURCE_PROFILE:
            raise AssertionError("source profile CLI refused actual inputs: " + cli.stderr)
        print("two-site source-mixed builder receipt: original linked PE accepted; "
              "same-length require_binding NOP, entry state and paired replacements refused")


if __name__ == "__main__":
    main()
