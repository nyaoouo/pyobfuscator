"""Back-compat shim — the Python-layer protection moved to the `protect` subpackage.

Importers historically use `pyobfuscator.packer`; this keeps that surface working.
New code should import from `pyobfuscator.protect`.
"""
from __future__ import annotations

from .protect.core import pack_module
# Cipher primitives re-exported for callers that import them from here.
from .protect.cipher import _ks_xor, _kdf, _fold, _MASK, _TEMP_KEY

__all__ = ["pack_module"]
