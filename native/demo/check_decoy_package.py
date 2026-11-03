"""Actual decoy package, role/identity/refusal and declared source ABI tests."""

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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from decoy_test_support import inspect_package
from decoy_contract import validate_ir, validate_child
from release_plan import parse_plan, render_header, expected_fold

ROOT = Path(__file__).resolve().parents[1]


class CommandFailure(AssertionError):
    def __init__(self, command, result):
        self.result = result
        super().__init__(f"decoy command failed: {command}\n{result.stdout[-6000:]}\n{result.stderr[-3000:]}")


def run(command, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=60)
    if (result.returncode == 0) != succeeds:
        raise CommandFailure(command, result)
    return result


def rejects(function, error=ValueError):
    try:
        function()
    except error:
        return
    raise AssertionError("decoy invalid input unexpectedly accepted")


def main():
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "objdump", "build_dir", "image"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    arrays, key, plan = inspect_package(args.build_dir, args.image)
    rejects(lambda: AESGCM(key).decrypt(arrays["nonce"], arrays["ciphertext"] + arrays["tag"], b"pyobf-native-demo-v1"), InvalidTag)
    changed = bytearray(arrays["aad"]); changed[-1] ^= 1
    rejects(lambda: AESGCM(key).decrypt(arrays["nonce"], arrays["ciphertext"] + arrays["tag"], bytes(changed)), InvalidTag)
    real = parse_plan((args.build_dir / "release-plan.private.json").read_bytes())
    assert real != plan and expected_fold(real) != expected_fold(plan)
    digest = hashlib.sha256(b"pyobf.native.release.fold.v1\0" + struct.pack("<8I", *expected_fold(real))).digest()
    wrong_key = bytes(a ^ b for a, b in zip(digest, arrays["record"][24:56]))
    rejects(lambda: AESGCM(wrong_key).decrypt(arrays["nonce"], arrays["ciphertext"] + arrays["tag"], arrays["aad"]), InvalidTag)
    validate_ir((args.build_dir / "decoy.combined.ll").read_text())
    image = args.image.read_bytes()
    coverage = (args.build_dir / "decoy.coverage.json").read_bytes()
    final = (args.build_dir / "decoy.final.json").read_bytes()
    bad_final = json.loads(final)
    next(row for row in bad_final["functions"] if row["selected"])["path_fold"] = {"ir_binding_contract_verified": True}
    rejects(lambda: validate_child(image, coverage, json.dumps(bad_final).encode()))
    missing_entry = json.loads(final)
    for row in missing_entry["functions"]:
        if row["function"] == "pyobf_native_inner_entry": row["selected"] = False
    if any(row["selected"] for row in missing_entry["functions"]):
        rejects(lambda: validate_child(image, coverage, json.dumps(missing_entry).encode()))
    bad_coverage = json.loads(coverage); bad_coverage["domain"] = "outer-bootstrap"
    rejects(lambda: validate_child(image, json.dumps(bad_coverage).encode(), final))
    duplicate = b'{"domain":"decoy-payload",' + coverage.lstrip()[1:]
    duplicate_final = json.loads(final)
    duplicate_final["input_report_sha256"] = hashlib.sha256(duplicate).hexdigest()
    rejects(lambda: validate_child(image, duplicate, json.dumps(duplicate_final).encode()))
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        entry = "define dllexport i32 @pyobf_native_inner_entry(ptr %context, i32 %value) {\n  ret i32 %value\n}\n"
        cases = {
            "missing-entry": entry.replace("@pyobf_native_inner_entry", "@different"),
            "unexported": entry.replace("dllexport ", ""),
            "fastcc": entry.replace("dllexport ", "dllexport fastcc "),
            "wide-result": entry.replace("i32 @", "i64 @").replace("ret i32 %value", "ret i64 1"),
            "wide-argument": entry.replace("i32 %value", "i64 %value").replace("ret i64 %value", "ret i32 1"),
            "variadic": entry.replace("i32 %value)", "i32 %value, ...)"),
            "weak": entry.replace("define dllexport", "define weak dllexport"),
            "tls": "@tls = thread_local global i32 0\n" + entry,
            "dllmain": entry + "define i32 @DllMain(ptr %a, i32 %b, ptr %c) { ret i32 1 }\n",
            "initialization": entry + "@llvm.global_ctors = appending global [1 x {i32, ptr, ptr}] [{i32, ptr, ptr} {i32 65535, ptr @initialize, ptr null}]\ndefine internal void @initialize() {ret void}\n",
            "recursive-fold": entry + "declare void @pyobf_native_path_fold_init_v1(ptr, i32)\n",
            "recursive-release": entry + "declare i32 @pyobf_native_demo_run(i32, i32, ptr, ptr)\n",
        }
        for name, source in cases.items():
            candidate = directory / (name + ".ll"); candidate.write_text(source)
            run([args.opt, "-passes=verify", "-disable-output", candidate])
            rejects(lambda source=source: validate_ir(source))
            run([sys.executable, ROOT / "tools/check_decoy_input.py", candidate], succeeds=False)
        header, manifest = directory / "decoy.hpp", directory / "manifest.json"
        local_plan, events = directory / "plan.json", directory / "events.hpp"
        local_plan.write_text(json.dumps(plan)); events.write_text(render_header(plan, "decoy_events"))
        command = [sys.executable, ROOT / "demo/pack_decoy.py", args.image,
            args.build_dir / "decoy.coverage.json", args.build_dir / "decoy.final.json", local_plan, events, header, manifest]
        run(command)
        before = header.read_bytes(), manifest.read_bytes()
        events.write_text(render_header(plan))
        run(command, succeeds=False)
        assert before == (header.read_bytes(), manifest.read_bytes())
        events.write_text(render_header(plan, "decoy_events"))
        stale = copy.deepcopy(plan); stale["child_report_sha256"] = "0" * 64
        local_plan.write_text(json.dumps(stale))
        run(command, succeeds=False)
        assert before == (header.read_bytes(), manifest.read_bytes())
        local_plan.write_text(json.dumps(plan))
        alias = [*command]; alias[-1] = header
        run(alias, succeeds=False)
        assert before == (header.read_bytes(), manifest.read_bytes())
        raw = directory / "plain.dll"
        run([args.compiler, "-O0", "-fno-lto", "-shared", args.build_dir / "decoy.combined.ll", "-o", raw])
        absent = directory / "rejected.json"
        run([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump, raw,
             args.build_dir / "decoy.coverage.json", "--output", absent], succeeds=False)
        assert not absent.exists()
    print("decoy: exact independent AEAD/identity, wrong role/AAD/real-fold, stale/namespace/alias preservation,12 LLVM-valid source refusals and plain-image rejection passed")


if __name__ == "__main__":
    main()
