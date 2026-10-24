# Machine-gated entrypoints

The machine gate encrypts the entire generated entry artifact with AES-256-GCM. The content key
is returned only to the build caller through `machine_record_out`; it is absent from the shipped
program. The publisher issues a signed response that wraps this key to a device public key.
The first hardware backend is the Windows TPM through the Microsoft Platform Crypto Provider.

Install `pip install pyobfuscator[machine]` in the build and target environments. The shipped
program imports the small `pyobfuscator_runtime` package and `cryptography`. Ordinary artifacts
without `machine_gate` retain their previous dependency-free runtime behavior.

## Build

```python
from pathlib import Path
from pyobfuscator import MachineGateOptions, ModuleObfOptions, obf_module

gate = MachineGateOptions(
    entrance=("entrance.py", "interact_func", "on_fail"),
    publisher_encryption_public_pem=Path("issuer-encryption.pub.pem").read_bytes(),
    publisher_signing_public_pem=Path("issuer-signing.pub.pem").read_bytes(),
    artifact_id="my-app-2026-10-24",
    device_key_name="my-app-device-key",
    device_policy="tpm_required",  # or explicit weaker "software_allowed"
    mode="online",                  # "offline" requires offline_nonce=16..64 fixed bytes
)
server_keys = {}
output = obf_module(
    Path("main.py").read_text(encoding="utf-8"),
    ModuleObfOptions(output="text", pack_body=True, key_from_cff=True,
                     detect_stack=True, key_binds_env=True, machine_gate=gate),
    machine_record_out=server_keys,
)
Path("dist").mkdir(exist_ok=True)
Path("dist/main.py").write_text(output, encoding="utf-8")
# Transfer server_keys to the publisher's protected issuer store. Never ship it with dist/.
```

The entrance file is packed separately from the main body. It must define the two named functions:

```python
# entrance.py — example transport; the server must implement the issuer operation below.
from urllib.request import Request, urlopen

def interact_func(challenge: bytes) -> bytes:
    request = Request("https://issuer.example/license", data=challenge, method="POST")
    with urlopen(request, timeout=10) as response:
        return response.read()

def on_fail() -> None:
    raise SystemExit("This machine is not licensed")
```

The complete entrance file runs before the main decrypt step, including its imports and top-level
statements. Keep its pre-gate behavior small and deliberate; it is currently treated as a
standalone file, so package-relative imports need separate handling. `interact_func` receives encrypted
challenge bytes and returns signed response bytes; it cannot override validation. Expected
credential, device-provider, and `interact_func` exceptions call `on_fail`. If `on_fail` returns,
the runtime raises an error and does not run the main body. Errors while executing the entrance
file itself occur before the callbacks are loaded and may surface directly.

## Issue a response

Keep the RSA challenge-decryption private key, Ed25519 signing private key, and per-artifact
content keys on the issuer side. `solve_challenge` decrypts and returns every challenge field, so
the authorization callback can inspect the full request before a response is issued:

```python
from pyobfuscator.machine import solve_challenge

request, response = solve_challenge(
    incoming_challenge,
    publisher_encryption_private_pem=issuer_decryption_private_pem,
    publisher_signing_private_pem=issuer_signing_private_pem,
    artifact_keys=server_keys,
    authorize=lambda fields: issuer_policy_allows(fields),
)
# Send response bytes to interact_func; log only safe request metadata.
```

The request fields are `version`, `artifact_id`, `publisher_id`,
`publisher_encryption_public_key`, `publisher_signing_public_key`, `hardware_id`,
`device_public_key`, `device_key_id`, `mode`, and `challenge`. Both publisher public keys are
canonical DER inside the encrypted request. In Windows TPM mode,
`hardware_id` is the SHA-256 fingerprint of the TPM endorsement public key, separate from the
application device key ID. In software mode it is the copyable key's fingerprint. Neither value
is independently attested in the request. The issuer must not trust a client claim of TPM
residency: enrollment must be controlled or backed by attestation before a hardware-bound
licensing claim is justified.

`mode="online"` generates a fresh 32-byte challenge on each run. The response binds that exact
request. Server-side replay state is still needed for single-use issuance or revocation.
`mode="offline"` uses the fixed `offline_nonce` and allows the same license response to be read
from a local file on every run. Copying that file to another TPM key does not unwrap the content
key. `software_allowed` uses a copyable PEM device key under the user's local app-data directory,
so copying both the key and license can also copy authorization.

## Project and PyInstaller boundaries

For `obf_project` with protected satellites, pass `machine_record_out` and use the existing
shared-runtime settings (`pack_body=True`, `key_from_cff=True`, `attest=True`) with
`import_hook=True`. Protected satellite blobs then reside in the encrypted entry registry.
The gate rejects self-contained satellite stubs and `shared_oracle_decouple=True`. Files classified
as plaintext by `obf_project` remain plaintext and are outside the gate.

For PyInstaller, build a TEXT outer entry and use `write_pyinstaller_hook` on the original source
to include imports hidden by the inner obfuscation. The generated wrapper exposes its runtime and
entrance imports to PyInstaller's static analysis without executing the entrance in a runtime
hook. Frozen onedir and onefile execution with `detect_stack=True`, plus a gated import-hook
project in onedir, are tested. PyInstaller's bootloader and
its runtime hooks run before the protected entry. A `.pyc` outer entry is directly runnable by
CPython but is not an accepted PyInstaller entry script.

## Security scope

Replacing the embedded publisher public keys changes both the CFF selector (when enabled) and
the HKDF key for the outer AEAD ciphertext. A forged credential with an attacker-generated
content key cannot authenticate the original body. The public key and its hash are visible and
patchable; the missing original content key and device private-key capability are the actual
barriers on an unauthorized machine.

An authorized machine necessarily receives the content key and executes plaintext Python code.
An attacker controlling that machine can inspect process memory or instrument execution. Online
relay, weak enrollment, virtual TPM migration, key reset/recovery, issuer key storage, and
revocation need deployment-specific policy. The protocol does not include TPM attestation or
an expiry field. Only Windows TPM is implemented; other platform providers have an extension
point but no validated backend.
