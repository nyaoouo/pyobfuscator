"""Versioned machine-authorization messages.

`interact_func` transports opaque bytes. The request is encrypted to the publisher; the response
is signed by the publisher and contains a content key wrapped to the enrolled device. A signature
alone is never accepted as the content key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_CHALLENGE_DOMAIN = b"pyobfuscator.machine.challenge.v1"
_CEK_DOMAIN = b"pyobfuscator.machine.cek.v1\0"
_MAX_MESSAGE = 1 << 20
_MAX_FIELD = 1 << 16


class MachineVerificationError(ValueError):
    """A malformed, unauthorized, or non-matching machine credential."""


def _encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decoded(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > _MAX_MESSAGE * 2:
        raise MachineVerificationError("invalid encoded field")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise MachineVerificationError("invalid encoded field") from exc


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MachineVerificationError("duplicate message field")
        result[key] = value
    return result


def _parse(data: bytes) -> dict:
    if not isinstance(data, bytes) or len(data) > _MAX_MESSAGE:
        raise MachineVerificationError("message size or type is invalid")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise MachineVerificationError("invalid message encoding") from exc
    if not isinstance(value, dict) or _json_bytes(value) != data:
        raise MachineVerificationError("message is not canonical")
    return value


def _public_key(raw: bytes, kind: str):
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise MachineVerificationError(f"invalid {kind} public key") from exc
    if kind == "encryption" and not isinstance(key, rsa.RSAPublicKey):
        raise MachineVerificationError("encryption public key must be RSA")
    if kind == "signing" and not isinstance(key, ed25519.Ed25519PublicKey):
        raise MachineVerificationError("signing public key must be Ed25519")
    if kind == "encryption" and key.key_size < 2048:
        raise MachineVerificationError("RSA public key is too short")
    return key


def _spki(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(public_key_pem: bytes, kind: str = "encryption") -> str:
    """Stable identifier of a canonical public key, not a secret or proof of hardware residency."""
    return hashlib.sha256(_spki(_public_key(public_key_pem, kind))).hexdigest()


def publisher_id(encryption_public_pem: bytes, signing_public_pem: bytes) -> str:
    enc = _spki(_public_key(encryption_public_pem, "encryption"))
    sign = _spki(_public_key(signing_public_pem, "signing"))
    return _publisher_id_der(enc, sign)


def _publisher_id_der(encryption_der: bytes, signing_der: bytes) -> str:
    return hashlib.sha256(b"pyobf.publisher.v1\0" + encryption_der + signing_der).hexdigest()


def _validate_request(request: dict) -> None:
    expected = {"version", "artifact_id", "publisher_id", "hardware_id", "device_public_key",
                "device_key_id", "publisher_encryption_public_key",
                "publisher_signing_public_key", "mode", "challenge"}
    if set(request) != expected or request.get("version") != 1:
        raise MachineVerificationError("unsupported challenge schema")
    for field in ("artifact_id", "publisher_id", "hardware_id", "device_key_id"):
        value = request[field]
        if not isinstance(value, str) or not value or len(value) > 256:
            raise MachineVerificationError(f"invalid {field}")
    if request["mode"] not in ("online", "offline"):
        raise MachineVerificationError("invalid challenge mode")
    challenge = _decoded(request["challenge"])
    if len(challenge) < 16 or len(challenge) > 64:
        raise MachineVerificationError("invalid challenge length")
    public = _decoded(request["device_public_key"])
    if len(public) > _MAX_FIELD:
        raise MachineVerificationError("device public key is too large")
    try:
        device = serialization.load_der_public_key(public)
    except ValueError as exc:
        raise MachineVerificationError("invalid device public key") from exc
    if not isinstance(device, rsa.RSAPublicKey) or device.key_size < 2048:
        raise MachineVerificationError("device public key must be RSA-2048 or stronger")
    if hashlib.sha256(_spki(device)).hexdigest() != request["device_key_id"]:
        raise MachineVerificationError("device key identifier mismatch")
    publisher_enc = _decoded(request["publisher_encryption_public_key"])
    publisher_sign = _decoded(request["publisher_signing_public_key"])
    if len(publisher_enc) > _MAX_FIELD or len(publisher_sign) > _MAX_FIELD:
        raise MachineVerificationError("publisher public key is too large")
    try:
        enc_key = serialization.load_der_public_key(publisher_enc)
        sign_key = serialization.load_der_public_key(publisher_sign)
    except ValueError as exc:
        raise MachineVerificationError("invalid publisher public key") from exc
    if (not isinstance(enc_key, rsa.RSAPublicKey) or enc_key.key_size < 2048
            or not isinstance(sign_key, ed25519.Ed25519PublicKey)):
        raise MachineVerificationError("invalid publisher key bundle")
    if _publisher_id_der(_spki(enc_key), _spki(sign_key)) != request["publisher_id"]:
        raise MachineVerificationError("publisher key identifier mismatch")


def create_challenge(*, artifact_id: str, publisher_id_value: str, hardware_id: str,
                     device_public_key_der: bytes, mode: str, nonce: bytes,
                     publisher_encryption_public_pem: bytes,
                     publisher_signing_public_pem: bytes) -> tuple[bytes, dict]:
    """Return an opaque encrypted challenge and the local context needed to check its response."""
    enc_public = _public_key(publisher_encryption_public_pem, "encryption")
    sign_public = _public_key(publisher_signing_public_pem, "signing")
    request = {"version": 1, "artifact_id": artifact_id,
               "publisher_id": publisher_id_value, "hardware_id": hardware_id,
               "publisher_encryption_public_key": _encoded(_spki(enc_public)),
               "publisher_signing_public_key": _encoded(_spki(sign_public)),
               "device_public_key": _encoded(device_public_key_der),
               "device_key_id": hashlib.sha256(device_public_key_der).hexdigest(),
               "mode": mode, "challenge": _encoded(nonce)}
    _validate_request(request)
    plaintext = _json_bytes(request)
    public = enc_public
    session_key = os.urandom(32)
    iv = os.urandom(12)
    wrapped = public.encrypt(session_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
        label=_CHALLENGE_DOMAIN))
    outer = {"version": 1, "wrapped": _encoded(wrapped), "iv": _encoded(iv),
             "ciphertext": _encoded(AESGCM(session_key).encrypt(iv, plaintext, _CHALLENGE_DOMAIN))}
    return _json_bytes(outer), request


def open_challenge(challenge: bytes, publisher_encryption_private_pem: bytes) -> dict:
    """Decrypt and return every request field; no plaintext side-channel input is used."""
    outer = _parse(challenge)
    if set(outer) != {"version", "wrapped", "iv", "ciphertext"} or outer["version"] != 1:
        raise MachineVerificationError("unsupported encrypted challenge")
    iv, wrapped, ciphertext = (_decoded(outer[k]) for k in ("iv", "wrapped", "ciphertext"))
    if len(iv) != 12 or len(ciphertext) > _MAX_MESSAGE:
        raise MachineVerificationError("invalid encrypted challenge")
    try:
        private = serialization.load_pem_private_key(publisher_encryption_private_pem, password=None)
        if not isinstance(private, rsa.RSAPrivateKey):
            raise MachineVerificationError("publisher encryption key must be RSA")
        session_key = private.decrypt(wrapped, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
            label=_CHALLENGE_DOMAIN))
        plaintext = AESGCM(session_key).decrypt(iv, ciphertext, _CHALLENGE_DOMAIN)
    except (ValueError, TypeError, InvalidTag) as exc:
        raise MachineVerificationError("challenge decryption failed") from exc
    request = _parse(plaintext)
    _validate_request(request)
    return request


def solve_challenge(challenge: bytes, *, publisher_encryption_private_pem: bytes,
                    publisher_signing_private_pem: bytes, artifact_keys: Mapping[str, bytes],
                    authorize: Callable[[dict], bool]) -> tuple[dict, bytes]:
    """Server operation: decrypt all fields, authorize, and return `(request, response_bytes)`."""
    request = open_challenge(challenge, publisher_encryption_private_pem)
    encryption_private = serialization.load_pem_private_key(
        publisher_encryption_private_pem, password=None)
    try:
        private = serialization.load_pem_private_key(publisher_signing_private_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise MachineVerificationError("invalid publisher signing key") from exc
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise MachineVerificationError("publisher signing key must be Ed25519")
    if publisher_id(
        encryption_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    ) != request["publisher_id"]:
        raise MachineVerificationError("publisher key bundle mismatch")
    if not authorize(request):
        raise MachineVerificationError("machine authorization denied")
    cek = artifact_keys.get(request["artifact_id"])
    if not isinstance(cek, bytes) or len(cek) != 32:
        raise MachineVerificationError("artifact content key is unavailable")
    device = serialization.load_der_public_key(_decoded(request["device_public_key"]))
    wrapped_cek = device.encrypt(cek, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
        label=_CEK_DOMAIN))
    payload = {"version": 1, "request_digest": hashlib.sha256(_json_bytes(request)).hexdigest(),
               "artifact_id": request["artifact_id"], "publisher_id": request["publisher_id"],
               "device_key_id": request["device_key_id"], "wrapped_cek": _encoded(wrapped_cek)}
    response = {"payload": payload, "signature": _encoded(private.sign(_json_bytes(payload)))}
    return request, _json_bytes(response)


def solve_challange(*args, **kwargs):
    """Compatibility spelling for the API name used in the initial design discussion."""
    return solve_challenge(*args, **kwargs)


def verify_response(response: bytes, *, request: dict, publisher_signing_public_pem: bytes,
                    unwrap: Callable[[bytes, bytes], bytes]) -> bytes:
    """Verify the grant and unwrap the CEK through the selected device provider."""
    _validate_request(request)
    envelope = _parse(response)
    if set(envelope) != {"payload", "signature"} or not isinstance(envelope["payload"], dict):
        raise MachineVerificationError("invalid response schema")
    payload = envelope["payload"]
    if set(payload) != {"version", "request_digest", "artifact_id", "publisher_id",
                        "device_key_id", "wrapped_cek"} or payload["version"] != 1:
        raise MachineVerificationError("unsupported response schema")
    public = _public_key(publisher_signing_public_pem, "signing")
    try:
        public.verify(_decoded(envelope["signature"]), _json_bytes(payload))
    except (InvalidSignature, ValueError) as exc:
        raise MachineVerificationError("response signature failed") from exc
    if (payload["request_digest"] != hashlib.sha256(_json_bytes(request)).hexdigest()
            or payload["artifact_id"] != request["artifact_id"]
            or payload["publisher_id"] != request["publisher_id"]
            or payload["device_key_id"] != request["device_key_id"]):
        raise MachineVerificationError("response context mismatch")
    try:
        cek = unwrap(_decoded(payload["wrapped_cek"]), _CEK_DOMAIN)
    except (ValueError, OSError, RuntimeError, MachineVerificationError) as exc:
        raise MachineVerificationError("device key cannot unwrap content key") from exc
    if not isinstance(cek, bytes) or len(cek) != 32:
        raise MachineVerificationError("invalid unwrapped content key")
    return cek
