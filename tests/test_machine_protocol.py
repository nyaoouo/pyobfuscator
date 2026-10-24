"""The machine protocol must fail before producing a content key on forged inputs."""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from pyobfuscator.machine.protocol import (MachineVerificationError, create_challenge,
                                           key_id, open_challenge, publisher_id,
                                           solve_challenge, verify_response)


def _pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem_public(key):
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def keys():
    publisher_enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    publisher_sign = ed25519.Ed25519PrivateKey.generate()
    device = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return publisher_enc, publisher_sign, device, other


def _request(keys, mode="offline"):
    publisher_enc, publisher_sign, device, _ = keys
    enc_public = _pem_public(publisher_enc.public_key())
    sign_public = _pem_public(publisher_sign.public_key())
    device_public_der = device.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    challenge, request = create_challenge(
        artifact_id="artifact-1", publisher_id_value=publisher_id(enc_public, sign_public),
        hardware_id="tpm-key-identity", device_public_key_der=device_public_der,
        mode=mode, nonce=b"fixed-license-id!" if mode == "offline" else b"fresh-run-nonce!",
        publisher_encryption_public_pem=enc_public,
        publisher_signing_public_pem=sign_public)
    return challenge, request


def _unwrap(device):
    return lambda data, label: device.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label))


@pytest.mark.parametrize("mode", ["offline", "online"])
def test_solve_recovers_every_challenge_field_and_unlocks(keys, mode):
    publisher_enc, publisher_sign, device, _ = keys
    challenge, request = _request(keys, mode)
    cek = b"c" * 32
    seen = []
    recovered, response = solve_challenge(
        challenge, publisher_encryption_private_pem=_pem_private(publisher_enc),
        publisher_signing_private_pem=_pem_private(publisher_sign),
        artifact_keys={"artifact-1": cek}, authorize=lambda fields: seen.append(fields) or True)
    assert recovered == request == seen[0]
    assert open_challenge(challenge, _pem_private(publisher_enc)) == request
    assert verify_response(response, request=request,
                           publisher_signing_public_pem=_pem_public(publisher_sign.public_key()),
                           unwrap=_unwrap(device)) == cek
    assert cek not in challenge and cek not in response


def test_wrong_issuer_key_and_tampered_challenge_fail(keys):
    publisher_enc, _, _, other = keys
    challenge, _ = _request(keys)
    with pytest.raises(MachineVerificationError, match="decryption failed"):
        open_challenge(challenge, _pem_private(other))
    outer = json.loads(challenge)
    ciphertext = bytearray(base64.b64decode(outer["ciphertext"]))
    ciphertext[-1] ^= 1
    outer["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    tampered = json.dumps(outer, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(MachineVerificationError, match="decryption failed"):
        open_challenge(tampered, _pem_private(publisher_enc))


def test_key_substitution_and_wrong_device_cannot_unlock(keys):
    publisher_enc, publisher_sign, device, other = keys
    challenge, request = _request(keys)
    _, response = solve_challenge(
        challenge, publisher_encryption_private_pem=_pem_private(publisher_enc),
        publisher_signing_private_pem=_pem_private(publisher_sign),
        artifact_keys={"artifact-1": b"c" * 32}, authorize=lambda _: True)
    attacker_sign = ed25519.Ed25519PrivateKey.generate()
    forged = json.loads(response)
    forged["signature"] = base64.b64encode(
        attacker_sign.sign(json.dumps(forged["payload"], sort_keys=True,
                                 separators=(",", ":")).encode("ascii"))).decode("ascii")
    forged_bytes = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(MachineVerificationError, match="signature failed"):
        verify_response(forged_bytes, request=request,
                        publisher_signing_public_pem=_pem_public(publisher_sign.public_key()),
                        unwrap=_unwrap(device))
    with pytest.raises(MachineVerificationError, match="cannot unwrap"):
        verify_response(response, request=request,
                        publisher_signing_public_pem=_pem_public(publisher_sign.public_key()),
                        unwrap=_unwrap(other))
    assert key_id(_pem_public(device.public_key())) == request["device_key_id"]


def test_context_change_denial_and_missing_content_key_fail(keys):
    publisher_enc, publisher_sign, device, _ = keys
    challenge, request = _request(keys)
    args = dict(publisher_encryption_private_pem=_pem_private(publisher_enc),
                publisher_signing_private_pem=_pem_private(publisher_sign),
                artifact_keys={"artifact-1": b"c" * 32})
    with pytest.raises(MachineVerificationError, match="denied"):
        solve_challenge(challenge, authorize=lambda _: False, **args)
    with pytest.raises(MachineVerificationError, match="unavailable"):
        solve_challenge(challenge, authorize=lambda _: True, artifact_keys={},
                        publisher_encryption_private_pem=args["publisher_encryption_private_pem"],
                        publisher_signing_private_pem=args["publisher_signing_private_pem"])
    _, response = solve_challenge(challenge, authorize=lambda _: True, **args)
    changed = dict(request, artifact_id="other-artifact")
    with pytest.raises(MachineVerificationError, match="context mismatch"):
        verify_response(response, request=changed,
                        publisher_signing_public_pem=_pem_public(publisher_sign.public_key()),
                        unwrap=_unwrap(device))


def test_server_rejects_mismatched_publisher_key_bundle_before_authorize(keys):
    publisher_enc, publisher_sign, _, _ = keys
    challenge, _ = _request(keys)
    wrong_sign = ed25519.Ed25519PrivateKey.generate()
    called = []
    with pytest.raises(MachineVerificationError, match="bundle mismatch"):
        solve_challenge(
            challenge, publisher_encryption_private_pem=_pem_private(publisher_enc),
            publisher_signing_private_pem=_pem_private(wrong_sign),
            artifact_keys={"artifact-1": b"c" * 32},
            authorize=lambda fields: called.append(fields) or True)
    assert not called
