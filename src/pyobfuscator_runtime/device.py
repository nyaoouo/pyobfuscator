"""Device-bound RSA key providers for machine authorization.

The Windows provider uses a nonexportable persisted CNG key in the Microsoft Platform Crypto
Provider. Other platforms can implement the same three-method interface without changing the
challenge protocol. A file-backed provider is deliberately explicit and has weaker guarantees.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .protocol import MachineVerificationError


class DeviceKeyError(MachineVerificationError):
    """The selected device key is unavailable or cannot decrypt the credential."""


class WindowsTpmKey:
    """A named, persisted RSA key held by the Windows TPM CNG provider."""

    _PROVIDER = "Microsoft Platform Crypto Provider"
    _OAEP_FLAG = 0x00000004

    def __init__(self, name: str):
        if sys.platform != "win32":
            raise DeviceKeyError("Windows TPM provider is unavailable on this platform")
        if not name or len(name) > 128 or not all(c.isalnum() or c in "._-" for c in name):
            raise DeviceKeyError("invalid TPM key name")
        self.name = name
        self._dll = ctypes.WinDLL("ncrypt.dll")
        self._provider = ctypes.c_void_p()
        self._key = ctypes.c_void_p()
        self._open()

    def _call(self, name, *args):
        fn = getattr(self._dll, name)
        fn.restype = ctypes.c_long
        status = fn(*args)
        if status:
            raise DeviceKeyError(f"Windows TPM {name} failed (0x{status & 0xffffffff:08x})")

    def _open(self):
        self._call("NCryptOpenStorageProvider", ctypes.byref(self._provider),
                   ctypes.c_wchar_p(self._PROVIDER), 0)
        try:
            open_key = self._dll.NCryptOpenKey
            open_key.restype = ctypes.c_long
            status = open_key(self._provider, ctypes.byref(self._key),
                              ctypes.c_wchar_p(self.name), 0, 0)
            if not status:
                return
            # NTE_BAD_KEYSET: key absent. Other errors should remain visible.
            if status & 0xffffffff != 0x80090016:
                raise DeviceKeyError(f"Windows TPM NCryptOpenKey failed (0x{status & 0xffffffff:08x})")
            self._call("NCryptCreatePersistedKey", self._provider, ctypes.byref(self._key),
                       ctypes.c_wchar_p("RSA"), ctypes.c_wchar_p(self.name), 0, 0)
            bits = ctypes.c_uint32(2048)
            self._call("NCryptSetProperty", self._key, ctypes.c_wchar_p("Length"),
                       ctypes.byref(bits), ctypes.sizeof(bits), 0)
            self._call("NCryptFinalizeKey", self._key, 0)
        except BaseException:
            self.close()
            raise

    def public_key_der(self) -> bytes:
        size = ctypes.c_uint32()
        self._call("NCryptExportKey", self._key, None, ctypes.c_wchar_p("RSAPUBLICBLOB"),
                   None, None, 0, ctypes.byref(size), 0)
        data = ctypes.create_string_buffer(size.value)
        self._call("NCryptExportKey", self._key, None, ctypes.c_wchar_p("RSAPUBLICBLOB"),
                   None, data, size.value, ctypes.byref(size), 0)
        magic, bits, exponent_len, modulus_len, prime1_len, prime2_len = struct.unpack_from(
            "<6I", data.raw)
        if magic != 0x31415352 or bits < 2048 or prime1_len or prime2_len:
            raise DeviceKeyError("invalid Windows TPM RSA public blob")
        offset = 24
        exponent = int.from_bytes(data.raw[offset:offset + exponent_len], "big")
        offset += exponent_len
        modulus = int.from_bytes(data.raw[offset:offset + modulus_len], "big")
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        return key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)

    def hardware_id(self) -> str:
        """Hash the TPM endorsement public key, separate from this app's device key ID."""
        size = ctypes.c_uint32()
        self._call("NCryptGetProperty", self._provider, ctypes.c_wchar_p("PCP_EKPUB"),
                   None, 0, ctypes.byref(size), 0)
        if size.value < 24 or size.value > 65536:
            raise DeviceKeyError("invalid TPM endorsement public key size")
        data = ctypes.create_string_buffer(size.value)
        self._call("NCryptGetProperty", self._provider, ctypes.c_wchar_p("PCP_EKPUB"),
                   data, size.value, ctypes.byref(size), 0)
        return "tpm-ek:" + hashlib.sha256(data.raw[:size.value]).hexdigest()

    def unwrap(self, data: bytes, label: bytes) -> bytes:
        class OaepInfo(ctypes.Structure):
            _fields_ = [("pszAlgId", ctypes.c_wchar_p), ("pbLabel", ctypes.c_void_p),
                        ("cbLabel", ctypes.c_uint32)]

        label_buf = ctypes.create_string_buffer(label)
        info = OaepInfo("SHA256", ctypes.cast(label_buf, ctypes.c_void_p), len(label))
        input_buf = ctypes.create_string_buffer(data)
        size = ctypes.c_uint32()
        self._call("NCryptDecrypt", self._key, input_buf, len(data), ctypes.byref(info),
                   None, 0, ctypes.byref(size), self._OAEP_FLAG)
        output = ctypes.create_string_buffer(size.value)
        self._call("NCryptDecrypt", self._key, input_buf, len(data), ctypes.byref(info),
                   output, size.value, ctypes.byref(size), self._OAEP_FLAG)
        return output.raw[:size.value]

    def close(self):
        if self._key:
            self._dll.NCryptFreeObject(self._key)
            self._key = ctypes.c_void_p()
        if self._provider:
            self._dll.NCryptFreeObject(self._provider)
            self._provider = ctypes.c_void_p()

    def delete(self):
        """Permanently remove this named key; intended for explicit key retirement or tests."""
        if self._key:
            self._call("NCryptDeleteKey", self._key, 0)
            self._key = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SoftwareDeviceKey:
    """Copyable file key for deployments that explicitly accept a weaker device policy."""

    def __init__(self, name: str):
        if not name or len(name) > 128 or not all(c.isalnum() or c in "._-" for c in name):
            raise DeviceKeyError("invalid software key name")
        base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "pyobfuscator" / "device-keys"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{name}.pem"
        if not path.exists():
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = private.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            try:
                with path.open("xb") as stream:
                    stream.write(pem)
            except FileExistsError:
                pass
        self._private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(self._private, rsa.RSAPrivateKey):
            raise DeviceKeyError("invalid software device key")

    def public_key_der(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def hardware_id(self) -> str:
        return "software-key:" + hashlib.sha256(self.public_key_der()).hexdigest()

    def unwrap(self, data: bytes, label: bytes) -> bytes:
        return self._private.decrypt(data, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label))

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_device_key(name: str, policy: str):
    """Return the configured provider; TPM-required never falls back to a software key."""
    if policy == "tpm_required":
        return WindowsTpmKey(name)
    if policy == "software_allowed":
        return SoftwareDeviceKey(name)
    raise DeviceKeyError("unknown device key policy")


def device_identity(public_key_der: bytes, policy: str) -> str:
    """Software-mode identity helper; TPM identity must come from the provider's EK."""
    if policy != "software_allowed":
        raise DeviceKeyError("TPM hardware identity must be read from WindowsTpmKey.hardware_id")
    return "software-key:" + hashlib.sha256(public_key_der).hexdigest()
