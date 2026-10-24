"""Build the separate entrance and authenticated main-body envelope."""
from __future__ import annotations

import base64
import os
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..cff.emit import _to_pyc
from ..options import OutputFormat
from pyobfuscator_runtime.protocol import publisher_id
from pyobfuscator_runtime.runtime import _body_context, body_key


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def wrap_machine_entry(inner, options, record_out: dict | None):
    """Encrypt the entire inner artifact; publish CEK only into an explicit build-side sink."""
    gate = options.machine_gate
    if gate is None:
        return inner
    if record_out is None:
        raise ValueError("machine gate requires machine_record_out to retain the server content key")
    if gate.artifact_id in record_out:
        raise ValueError("machine_record_out already contains artifact_id")
    if options.output not in (OutputFormat.TEXT, OutputFormat.PYC):
        raise ValueError("machine gate requires text or pyc output")
    if gate.device_policy not in ("tpm_required", "software_allowed"):
        raise ValueError("unknown device key policy")
    if gate.mode not in ("online", "offline"):
        raise ValueError("unknown machine challenge mode")
    if gate.mode == "offline" and (not isinstance(gate.offline_nonce, bytes)
                                   or len(gate.offline_nonce) < 16 or len(gate.offline_nonce) > 64):
        raise ValueError("offline mode requires a fixed 16-64 byte nonce")
    if not gate.artifact_id or len(gate.artifact_id) > 256:
        raise ValueError("invalid artifact_id")
    if not gate.device_key_name or len(gate.device_key_name) > 128 or not all(
            c.isalnum() or c in "._-" for c in gate.device_key_name):
        raise ValueError("invalid device_key_name")
    entrance_path, interact_name, on_fail_name = gate.entrance
    if not all(isinstance(v, str) and v.isidentifier() for v in (interact_name, on_fail_name)):
        raise ValueError("entrance function names must be identifiers")
    entrance_source = Path(entrance_path).read_text(encoding="utf-8")
    from .. import obf_module
    from ..pyinstaller import collect_pyinstaller_imports
    # Entrance encryption is intentionally independent of the main CEK. It must run first, and
    # its bytecode/obfuscation is not part of the main confidentiality claim.
    entrance_opts = replace(options, machine_gate=None, output=OutputFormat.TEXT,
                            protect_level="off", pack_body=True, key_from_cff=True,
                            attest=False, body_cohash=False, cohash_integrity=False,
                            compress_output=False, detect_stack=False, key_binds_env=False,
                            require_min_python=False)
    entrance_obfuscated = obf_module(entrance_source, entrance_opts)
    pid = publisher_id(gate.publisher_encryption_public_pem,
                       gate.publisher_signing_public_pem)
    cek = os.urandom(32)
    iv = os.urandom(12)
    plaintext = inner.encode("utf-8") if isinstance(inner, str) else inner
    ciphertext = AESGCM(body_key(cek, gate.artifact_id, pid)).encrypt(
        iv, plaintext, _body_context(gate.artifact_id, pid))
    entrance_imports = collect_pyinstaller_imports(entrance_path)
    dormant_imports = "def _pyx_entrance_imports():\n" + (
        "".join(f"    import {name}\n" for name in entrance_imports) or "    pass\n")
    source = (
        "from pyobfuscator_runtime.runtime import load_body as _pyx_load, b64 as _pyx_b64\n"
        + dormant_imports +
        "_pyx_code, _pyx_publisher_selector = _pyx_load(\n"
        f"    entrance_source={entrance_obfuscated!r},\n"
        f"    interact_name={interact_name!r}, on_fail_name={on_fail_name!r},\n"
        f"    encryption_public_pem=_pyx_b64({_b64(gate.publisher_encryption_public_pem)!r}),\n"
        f"    signing_public_pem=_pyx_b64({_b64(gate.publisher_signing_public_pem)!r}),\n"
        f"    artifact_id={gate.artifact_id!r}, device_key_name={gate.device_key_name!r},\n"
        f"    device_policy={gate.device_policy!r}, mode={gate.mode!r},\n"
        f"    offline_nonce={gate.offline_nonce!r}, iv=_pyx_b64({_b64(iv)!r}),\n"
        f"    ciphertext=_pyx_b64({_b64(ciphertext)!r}), body_format={options.output.value!r})\n"
        "exec(_pyx_code, globals())\n"
    )
    result = (source if options.output is OutputFormat.TEXT else
              _to_pyc(compile(source, "<machine-wrapper>", "exec"), source.encode("utf-8")))
    # Publish only after all source generation and validation has succeeded.
    record_out[gate.artifact_id] = cek
    return result
