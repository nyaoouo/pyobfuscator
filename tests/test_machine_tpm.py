"""Opt-in hardware smoke test; creates and then deletes a disposable Windows TPM key."""
from __future__ import annotations

import os
import hashlib
import ctypes
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pyobfuscator import MachineGateOptions, ModuleObfOptions, obf_module
from pyobfuscator.machine.device import WindowsTpmKey
from pyobfuscator.machine.protocol import create_challenge, publisher_id, solve_challenge


@pytest.mark.skipif(sys.platform != "win32" or os.environ.get("PYOBF_TEST_TPM") != "1",
                    reason="set PYOBF_TEST_TPM=1 on a Windows TPM test host")
def test_windows_tpm_nonexportable_key_roundtrip():
    name = "pyobf-test-" + uuid.uuid4().hex
    with WindowsTpmKey(name) as device:
        try:
            public = serialization.load_der_public_key(device.public_key_der())
            label = b"pyobfuscator.machine.cek.v1\0"
            wrapped = public.encrypt(b"c" * 32, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label))
            assert device.unwrap(wrapped, label) == b"c" * 32
            assert device.hardware_id().startswith("tpm-ek:")
            assert device.hardware_id() != "tpm-key:" + hashlib.sha256(device.public_key_der()).hexdigest()
            size = ctypes.c_uint32()
            export_private = device._dll.NCryptExportKey
            export_private.restype = ctypes.c_long
            assert export_private(device._key, None, ctypes.c_wchar_p("RSAFULLPRIVATEBLOB"),
                                  None, None, 0, ctypes.byref(size), 0) != 0
        finally:
            device.delete()


@pytest.mark.skipif(sys.platform != "win32" or os.environ.get("PYOBF_TEST_TPM") != "1",
                    reason="set PYOBF_TEST_TPM=1 on a Windows TPM test host")
def test_windows_tpm_gated_entry(tmp_path):
    name = "pyobf-test-" + uuid.uuid4().hex
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
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="tpm-artifact", device_key_name=name,
        device_policy="tpm_required", mode="offline",
        offline_nonce=b"fixed-tpm-license-id")
    records = {}
    script = tmp_path / "main.py"
    script.write_text(obf_module("print('TPM REAL')", ModuleObfOptions(
        output="text", pack_body=True, key_from_cff=True, machine_gate=gate),
        machine_record_out=records), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    with WindowsTpmKey(name) as device:
        try:
            denied = subprocess.run([sys.executable, str(script)], env=env,
                                    capture_output=True, text=True, timeout=30)
            assert denied.returncode == 7 and "TPM REAL" not in denied.stdout
            public_der = device.public_key_der()
            challenge, request = create_challenge(
                artifact_id=gate.artifact_id,
                publisher_id_value=publisher_id(enc_pub, sign_pub),
                hardware_id=device.hardware_id(),
                device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
                publisher_encryption_public_pem=enc_pub,
                publisher_signing_public_pem=sign_pub)
            _, response = solve_challenge(
                challenge, publisher_encryption_private_pem=private(enc),
                publisher_signing_private_pem=private(sign), artifact_keys=records,
                authorize=lambda fields: fields == request)
            license_path.write_bytes(response)
            allowed = subprocess.run([sys.executable, str(script)], env=env,
                                     capture_output=True, text=True, timeout=30)
            assert allowed.returncode == 0, allowed.stderr
            assert allowed.stdout.strip() == "TPM REAL"
        finally:
            device.delete()
