"""Machine credentials must gate the packed entry before its Python body exists."""
from __future__ import annotations

import os
import base64
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pyobfuscator import MachineGateOptions, ModuleObfOptions, obf_module, obf_project
from pyobfuscator.machine.device import device_identity, open_device_key
from pyobfuscator.machine.protocol import create_challenge, publisher_id, solve_challenge


def _pem_public(key):
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def _pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


@pytest.mark.parametrize("output,rounds", [("text", 0), ("text", 2), ("pyc", 0)])
def test_offline_gate_denies_before_main_and_preserves_stack(tmp_path, monkeypatch, output, rounds):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()
    enc_pub, sign_pub = _pem_public(enc.public_key()), _pem_public(sign.public_key())
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('DENIED')\n    raise SystemExit(7)\n", encoding="utf-8")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="test-artifact", device_key_name="test-device", device_policy="software_allowed",
        mode="offline", offline_nonce=b"fixed-offline-challenge-id")
    opts = ModuleObfOptions(output=output, pack_body=True, key_from_cff=True,
                            pack_decoy=True, decoy_src="print('DECOY')",
                            detect_stack=True, key_binds_env=True,
                            compress_output=rounds > 0, compress_rounds=max(1, rounds),
                            machine_gate=gate)
    records = {}
    artifact = obf_module("print('REAL 321')", opts, machine_record_out=records)
    path = tmp_path / ("main.pyc" if output == "pyc" else "main.py")
    path.write_bytes(artifact if isinstance(artifact, bytes) else artifact.encode("utf-8"))
    assert b"REAL 321" not in path.read_bytes()
    assert records == {"test-artifact": records["test-artifact"]}
    assert records["test-artifact"] not in path.read_bytes()
    assert base64.b64encode(records["test-artifact"]) not in path.read_bytes()
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")

    def run():
        return subprocess.run([sys.executable, str(path)], capture_output=True,
                              text=True, env=env, timeout=30)

    absent = run()
    assert absent.returncode == 7 and "DENIED" in absent.stdout
    assert "REAL 321" not in absent.stdout and "DECOY" not in absent.stdout

    with open_device_key("test-device", "software_allowed") as device:
        public_der = device.public_key_der()
        challenge, request = create_challenge(
            artifact_id=gate.artifact_id,
            publisher_id_value=publisher_id(enc_pub, sign_pub),
            hardware_id=device_identity(public_der, "software_allowed"),
            device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
            publisher_encryption_public_pem=enc_pub,
            publisher_signing_public_pem=sign_pub)
    recovered, license_bytes = solve_challenge(
        challenge, publisher_encryption_private_pem=_pem_private(enc),
        publisher_signing_private_pem=_pem_private(sign), artifact_keys=records,
        authorize=lambda fields: fields == request)
    assert recovered == request
    license_path.write_bytes(license_bytes)
    allowed = run()
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "REAL 321"

    license_path.write_bytes(license_bytes[:-1] + b"x")
    bad = run()
    assert bad.returncode == 7 and "REAL 321" not in bad.stdout


def test_machine_gate_needs_secret_handoff_and_project_boundary(tmp_path):
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()
    entrance = tmp_path / "entrance.py"
    entrance.write_text("def interact_func(x): return b''\ndef on_fail(): pass\n")
    opts = ModuleObfOptions(output="text", machine_gate=MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=_pem_public(enc.public_key()),
        publisher_signing_public_pem=_pem_public(sign.public_key()),
        artifact_id="test", device_key_name="test"))
    with pytest.raises(ValueError, match="machine_record_out"):
        obf_module("print('secret')", opts)


@pytest.mark.parametrize("cohash_integrity", [False, True])
def test_project_gate_centralizes_protected_satellites(tmp_path, monkeypatch,
                                                       cohash_integrity):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()
    enc_pub, sign_pub = _pem_public(enc.public_key()), _pem_public(sign.public_key())
    root, out = tmp_path / "source", tmp_path / "out"
    root.mkdir()
    (root / "main.py").write_text("import secret\nprint('ENTRY', secret.answer())\n")
    (root / "secret.py").write_text("def answer():\n    return 321\n")
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="project-artifact", device_key_name="project-device",
        device_policy="software_allowed", mode="offline",
        offline_nonce=b"fixed-project-license-id")
    opts = ModuleObfOptions(output="text", pack_body=True, key_from_cff=True,
                            attest=True, seed=12345, machine_gate=gate,
                            cohash_integrity=cohash_integrity)
    records = {}
    with pytest.raises(ValueError, match="import_hook"):
        obf_project(root=str(root), out=str(out), entry="main.py", protect=["secret.py"],
                    options=opts, machine_record_out=records)
    manifest = obf_project(root=str(root), out=str(out), entry="main.py",
                           protect=["secret.py"], options=opts, import_hook=True,
                           machine_record_out=records)
    assert manifest["secret.py"] == "protect"
    assert not (out / "secret.py").exists()
    assert b"ENTRY" not in (out / "main.py").read_bytes()
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")

    def run():
        return subprocess.run([sys.executable, str(out / "main.py")],
                              capture_output=True, text=True, env=env, timeout=30)

    denied = run()
    assert denied.returncode == 7 and "ENTRY" not in denied.stdout
    with open_device_key("project-device", "software_allowed") as device:
        public_der = device.public_key_der()
        challenge, request = create_challenge(
            artifact_id=gate.artifact_id,
            publisher_id_value=publisher_id(enc_pub, sign_pub),
            hardware_id=device_identity(public_der, "software_allowed"),
            device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
            publisher_encryption_public_pem=enc_pub,
            publisher_signing_public_pem=sign_pub)
    _, response = solve_challenge(
        challenge, publisher_encryption_private_pem=_pem_private(enc),
        publisher_signing_private_pem=_pem_private(sign), artifact_keys=records,
        authorize=lambda fields: fields == request)
    license_path.write_bytes(response)
    allowed = run()
    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "ENTRY 321"


def test_substituted_publisher_keys_and_forged_license_cannot_open_body(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    original_enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    original_sign = ed25519.Ed25519PrivateKey.generate()
    attacker_enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_sign = ed25519.Ed25519PrivateKey.generate()
    old_enc_pub, old_sign_pub = _pem_public(original_enc.public_key()), _pem_public(original_sign.public_key())
    new_enc_pub, new_sign_pub = _pem_public(attacker_enc.public_key()), _pem_public(attacker_sign.public_key())
    license_path = tmp_path / "license.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        f"def interact_func(challenge):\n    return open({str(license_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=old_enc_pub,
        publisher_signing_public_pem=old_sign_pub,
        artifact_id="substitution-test", device_key_name="substitution-device",
        device_policy="software_allowed", mode="offline",
        offline_nonce=b"fixed-substitution-id")
    records = {}
    original = obf_module("print('SECRET BODY')", ModuleObfOptions(
        output="text", machine_gate=gate), machine_record_out=records)
    substituted = original.replace(base64.b64encode(old_enc_pub).decode(),
                                   base64.b64encode(new_enc_pub).decode())
    substituted = substituted.replace(base64.b64encode(old_sign_pub).decode(),
                                      base64.b64encode(new_sign_pub).decode())
    assert substituted != original
    script = tmp_path / "modified.py"
    script.write_text(substituted)
    with open_device_key(gate.device_key_name, "software_allowed") as device:
        public_der = device.public_key_der()
        challenge, _ = create_challenge(
            artifact_id=gate.artifact_id,
            publisher_id_value=publisher_id(new_enc_pub, new_sign_pub),
            hardware_id=device_identity(public_der, "software_allowed"),
            device_public_key_der=public_der, mode="offline", nonce=gate.offline_nonce,
            publisher_encryption_public_pem=new_enc_pub,
            publisher_signing_public_pem=new_sign_pub)
    _, forged = solve_challenge(
        challenge, publisher_encryption_private_pem=_pem_private(attacker_enc),
        publisher_signing_private_pem=_pem_private(attacker_sign),
        artifact_keys={gate.artifact_id: b"x" * 32}, authorize=lambda _: True)
    license_path.write_bytes(forged)
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    result = subprocess.run([sys.executable, str(script)], capture_output=True,
                            text=True, env=env, timeout=30)
    assert result.returncode == 7 and "SECRET BODY" not in result.stdout


def test_online_challenge_changes_and_replayed_response_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()
    enc_pub, sign_pub = _pem_public(enc.public_key()), _pem_public(sign.public_key())
    challenge_path, response_path = tmp_path / "challenge.bin", tmp_path / "response.bin"
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        "import time\n"
        "def interact_func(challenge):\n"
        f"    open({str(challenge_path)!r}, 'wb').write(challenge)\n"
        f"    while not __import__('os').path.exists({str(response_path)!r}):\n"
        "        time.sleep(0.02)\n"
        f"    return open({str(response_path)!r}, 'rb').read()\n"
        "def on_fail():\n    print('DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=enc_pub, publisher_signing_public_pem=sign_pub,
        artifact_id="online-artifact", device_key_name="online-device",
        device_policy="software_allowed", mode="online")
    records = {}
    script = tmp_path / "online.py"
    script.write_text(obf_module("print('ONLINE REAL')", ModuleObfOptions(
        output="text", machine_gate=gate), machine_record_out=records))
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    process = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env=env)
    try:
        deadline = time.monotonic() + 15
        while not challenge_path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert challenge_path.exists(), process.communicate(timeout=5)
        first_challenge = challenge_path.read_bytes()
        request, response = solve_challenge(
            first_challenge, publisher_encryption_private_pem=_pem_private(enc),
            publisher_signing_private_pem=_pem_private(sign), artifact_keys=records,
            authorize=lambda fields: fields["mode"] == "online")
        response_path.write_bytes(response)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        assert stdout.strip() == "ONLINE REAL"
        assert len(base64.b64decode(request["challenge"])) == 32
        replay = subprocess.run([sys.executable, str(script)], capture_output=True,
                                text=True, env=env, timeout=30)
        assert replay.returncode == 7 and "ONLINE REAL" not in replay.stdout
        assert challenge_path.read_bytes() != first_challenge
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_transport_callback_exception_calls_on_fail(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign = ed25519.Ed25519PrivateKey.generate()
    entrance = tmp_path / "entrance.py"
    entrance.write_text(
        "def interact_func(challenge):\n    raise RuntimeError('network adapter failed')\n"
        "def on_fail():\n    print('DENIED')\n    raise SystemExit(7)\n")
    gate = MachineGateOptions(
        entrance=(str(entrance), "interact_func", "on_fail"),
        publisher_encryption_public_pem=_pem_public(enc.public_key()),
        publisher_signing_public_pem=_pem_public(sign.public_key()),
        artifact_id="transport-error", device_key_name="transport-device",
        device_policy="software_allowed", mode="online")
    artifact = obf_module("print('SECRET')", ModuleObfOptions(
        output="text", machine_gate=gate), machine_record_out={})
    path = tmp_path / "main.py"
    path.write_text(artifact)
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(tmp_path / "localappdata")
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    result = subprocess.run([sys.executable, str(path)], capture_output=True,
                            text=True, env=env, timeout=30)
    assert result.returncode == 7 and result.stdout.strip() == "DENIED"
