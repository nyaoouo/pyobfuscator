"""Frozen gated entry: the wrapper must not break bootstrap stack detection."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pyobfuscator import (MachineGateOptions, ModuleObfOptions, obf_module,
                          obf_project, write_pyinstaller_hook)
from pyobfuscator.machine.device import device_identity, open_device_key
from pyobfuscator.machine.protocol import create_challenge, publisher_id, solve_challenge


@pytest.mark.skipif(importlib.util.find_spec("PyInstaller") is None,
                    reason="PyInstaller optional dependency unavailable")
@pytest.mark.parametrize("bundle_mode", ["onedir", "onefile"])
def test_frozen_machine_gate_stack_and_denial(tmp_path, monkeypatch, bundle_mode):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()

    def public(key):
        return key.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)

    def private(key):
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    enc_pub, sign_pub = public(enc.public_key()), public(sign.public_key())
    original = tmp_path / "original.py"
    original.write_text("print('FROZEN REAL 321')\n")
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('FROZEN DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="frozen-artifact", device_key_name="frozen-device",
        device_policy="software_allowed", mode="offline",
        offline_nonce=b"fixed-frozen-license-id")
    opts = ModuleObfOptions(output="text", pack_body=True, key_from_cff=True,
                            pack_decoy=True, decoy_src="print('FROZEN DECOY')",
                            detect_stack=True, key_binds_env=True, machine_gate=gate)
    records = {}
    wrapped = obf_module(original.read_text(), opts, machine_record_out=records)
    script = tmp_path / "frozen.py"
    script.write_text(wrapped, encoding="utf-8")
    hook = tmp_path / "hook.py"
    write_pyinstaller_hook(original, hook)
    build = subprocess.run([
        sys.executable, "-m", "PyInstaller", "--" + bundle_mode, "--noconfirm", "--clean",
        "--log-level=ERROR", "--runtime-hook", str(hook),
        "--distpath", str(tmp_path / "dist"), "--workpath", str(tmp_path / "work"),
        "--specpath", str(tmp_path / "spec"), "--paths", str(Path(__file__).parents[1] / "src"),
        str(script)], capture_output=True, text=True, timeout=180)
    assert build.returncode == 0, build.stdout + build.stderr
    exe = (tmp_path / "dist" / "frozen" / "frozen.exe" if bundle_mode == "onedir"
           else tmp_path / "dist" / "frozen.exe")
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")

    def run():
        return subprocess.run([str(exe)], capture_output=True, text=True,
                              env=env, timeout=40)

    denied = run()
    assert denied.returncode == 7 and "FROZEN REAL" not in denied.stdout
    with open_device_key("frozen-device", "software_allowed") as device:
        public_der = device.public_key_der()
        challenge, request = create_challenge(
            artifact_id=gate.artifact_id,
            publisher_id_value=publisher_id(enc_pub, sign_pub),
            hardware_id=device_identity(public_der, "software_allowed"),
            device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
            publisher_encryption_public_pem=enc_pub,
            publisher_signing_public_pem=sign_pub)
    _, response = solve_challenge(
        challenge, publisher_encryption_private_pem=private(enc),
        publisher_signing_private_pem=private(sign), artifact_keys=records,
        authorize=lambda fields: fields == request)
    license_path.write_bytes(response)
    allowed = run()
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "FROZEN REAL 321"


@pytest.mark.skipif(importlib.util.find_spec("PyInstaller") is None,
                    reason="PyInstaller optional dependency unavailable")
def test_frozen_machine_gated_project_import_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()

    def public(key):
        return key.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)

    def private(key):
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    enc_pub, sign_pub = public(enc.public_key()), public(sign.public_key())
    root, out = tmp_path / "src_app", tmp_path / "obf"
    root.mkdir()
    (root / "main.py").write_text("import secret\nprint('PROJECT REAL', secret.answer())\n")
    (root / "secret.py").write_text("def answer(): return 321\n")
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('PROJECT DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="frozen-project", device_key_name="frozen-project-device",
        device_policy="software_allowed", mode="offline",
        offline_nonce=b"fixed-frozen-project-id")
    records = {}
    opts = ModuleObfOptions(output="text", pack_body=True, key_from_cff=True,
                            attest=True, detect_stack=True, key_binds_env=True,
                            seed=9988, machine_gate=gate)
    manifest = obf_project(root=str(root), out=str(out), entry="main.py",
                           protect=["secret.py"], options=opts, import_hook=True,
                           machine_record_out=records)
    hook = tmp_path / "hook.py"
    write_pyinstaller_hook(root, hook, manifest=manifest, import_hook=True)
    build = subprocess.run([
        sys.executable, "-m", "PyInstaller", "--onedir", "--noconfirm", "--clean",
        "--log-level=ERROR", "--runtime-hook", str(hook),
        "--distpath", str(tmp_path / "dist"), "--workpath", str(tmp_path / "work"),
        "--specpath", str(tmp_path / "spec"), "--paths", str(out),
        "--paths", str(Path(__file__).parents[1] / "src"),
        str(out / "main.py")], capture_output=True, text=True, timeout=180)
    assert build.returncode == 0, build.stdout + build.stderr
    exe = tmp_path / "dist" / "main" / "main.exe"
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")

    def run():
        return subprocess.run([str(exe)], capture_output=True, text=True,
                              env=env, timeout=40)

    denied = run()
    assert denied.returncode == 7 and "PROJECT REAL" not in denied.stdout
    with open_device_key("frozen-project-device", "software_allowed") as device:
        public_der = device.public_key_der()
        challenge, request = create_challenge(
            artifact_id=gate.artifact_id,
            publisher_id_value=publisher_id(enc_pub, sign_pub),
            hardware_id=device_identity(public_der, "software_allowed"),
            device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
            publisher_encryption_public_pem=enc_pub,
            publisher_signing_public_pem=sign_pub)
    _, response = solve_challenge(
        challenge, publisher_encryption_private_pem=private(enc),
        publisher_signing_private_pem=private(sign), artifact_keys=records,
        authorize=lambda fields: fields == request)
    license_path.write_bytes(response)
    allowed = run()
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "PROJECT REAL 321"
