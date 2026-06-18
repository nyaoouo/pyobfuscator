"""Pure-Python cipher + key-derivation primitives for the launcher/body packer.

All functions are pure Python with NO imports, so they can be emitted verbatim into the
generated launcher (see `templates.py`). The same `_ks_xor` runs at build (encrypt) and at
runtime (decrypt) — it is its own inverse.
"""
from __future__ import annotations

_MASK = (1 << 64) - 1

# Used when key_from_cff is off: a temporary, hardcoded key.
_TEMP_KEY = 0xA5A5A5A5A5A5A5A5

# Salts / spread constants for the selector + key derivation.
_SALT_SEL = 0x5E1EC700
_SALT_KEY = 0x4E12B0F5
_SALT_DECOY = 0xDEC0DEC0
_BI_MAGIC = 0x100000001B3       # FNV-ish spread for the builtin-identity fold
_D_MAGIC = 0x27D4EB2F165667C5   # spread for the detection-aggregate fold
_P_MAGIC = 0x880355F21E6D1965   # spread for the user-handler POISON fold


# NOTE: runtime copies of this algorithm are embedded in protect/_templates.py (launcher)
# and cff/passes/archive.py::_RUNTIME_TMPL (const archive). Edit all copies together.
def _kdf(s: int) -> int:
    """splitmix64-style 64-bit key derivation. Deterministic, strong diffusion."""
    s = (s + 0x9E3779B97F4A7C15) & _MASK
    z = s
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
    return (z ^ (z >> 31)) & _MASK


def _fold(seed: int, steps) -> int:
    """Multiply-add fold: acc = (acc * m + c) & MASK for each (m, c). Mirrors the launcher."""
    acc = seed & _MASK
    for m, c in steps:
        acc = (acc * m + c) & _MASK
    return acc


# NOTE: runtime copies of this algorithm are embedded in protect/_templates.py (launcher)
# and cff/passes/archive.py::_RUNTIME_TMPL (const archive). Edit all copies together.
def _ks_xor(data: bytes, key: int) -> bytes:
    """Symmetric xorshift64 keystream XOR. Its own inverse. Pure Python, no imports."""
    out = bytearray(len(data))
    x = key & 0xFFFFFFFFFFFFFFFF
    if x == 0:
        x = 0x9E3779B97F4A7C15
    for i in range(len(data)):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        out[i] = data[i] ^ (x & 0xFF)
    return bytes(out)


def _hash_bytes(b) -> int:
    """FNV-1a 64-bit over a byte string. Mirrors the launcher's `t_hashfn` template."""
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h ^ c) * 0x100000001B3) & _MASK
    return h
