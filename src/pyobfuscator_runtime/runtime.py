"""Runtime authorization boundary for a protected entrypoint."""
from __future__ import annotations

import base64
import marshal
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .device import open_device_key
from .protocol import (MachineVerificationError, create_challenge, publisher_id,
                       verify_response)


def _body_context(artifact_id: str, publisher_id_value: str) -> bytes:
    return b"pyobfuscator.machine.body.v1\0" + artifact_id.encode("utf-8") + b"\0" + bytes.fromhex(publisher_id_value)


def body_key(cek: bytes, artifact_id: str, publisher_id_value: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_body_context(artifact_id, publisher_id_value)).derive(cek)


def load_body(*, entrance_source: str, interact_name: str, on_fail_name: str,
              encryption_public_pem: bytes, signing_public_pem: bytes,
              artifact_id: str, device_key_name: str, device_policy: str,
              mode: str, offline_nonce: bytes | None, iv: bytes, ciphertext: bytes,
              body_format: str):
    """Run entrance independently; return main code only after credential and AEAD checks.

    The caller executes the returned code at module scope. This keeps the entry stack change to
    exactly one wrapper `exec` frame, including when the inner launcher is compressed.
    """
    entrance_globals = {"__name__": "__machine_entrance__", "__builtins__": __builtins__}
    exec(compile(entrance_source, "<machine-entrance>", "exec"), entrance_globals)
    interact = entrance_globals.get(interact_name)
    on_fail = entrance_globals.get(on_fail_name)
    if not callable(interact) or not callable(on_fail):
        raise MachineVerificationError("entrance functions are unavailable")

    try:
        expected_publisher = publisher_id(encryption_public_pem, signing_public_pem)
        if mode == "online":
            nonce = os.urandom(32)
        elif mode == "offline" and isinstance(offline_nonce, bytes) and len(offline_nonce) >= 16:
            nonce = offline_nonce
        else:
            raise MachineVerificationError("invalid challenge mode or offline nonce")
        with open_device_key(device_key_name, device_policy) as device:
            public_der = device.public_key_der()
            challenge, request = create_challenge(
                artifact_id=artifact_id, publisher_id_value=expected_publisher,
                hardware_id=device.hardware_id(),
                device_public_key_der=public_der, mode=mode, nonce=nonce,
                publisher_encryption_public_pem=encryption_public_pem,
                publisher_signing_public_pem=signing_public_pem)
            try:
                response = interact(challenge)
            except Exception as exc:
                raise MachineVerificationError("interaction failed") from exc
            if not isinstance(response, bytes):
                raise MachineVerificationError("interact_func must return response bytes")
            cek = verify_response(response, request=request,
                                  publisher_signing_public_pem=signing_public_pem,
                                  unwrap=device.unwrap)
        key = body_key(cek, artifact_id, expected_publisher)
        plaintext = AESGCM(key).decrypt(iv, ciphertext,
                                        _body_context(artifact_id, expected_publisher))
        if body_format == "text":
            code = compile(plaintext.decode("utf-8"), "<protected-entry>", "exec")
            return code, int(expected_publisher[:16], 16)
        if body_format == "pyc" and len(plaintext) >= 16:
            return marshal.loads(plaintext[16:]), int(expected_publisher[:16], 16)
        raise MachineVerificationError("unsupported protected body format")
    except (MachineVerificationError, InvalidTag, OSError, ValueError) as exc:
        on_fail()
        raise MachineVerificationError("machine authorization failed") from exc


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
