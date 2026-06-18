"""Format resolution + body/decoy byte serialization for the packer.

The launcher *code* snippets live in `_templates.py` as real code and are instantiated via
`astutil` (parse → rename/substitute → splice AST). This module only holds the non-codegen
helpers and the fallback decoy source.
"""
from __future__ import annotations

import ast
import marshal
import zlib

from ..options import ObfOptions, OutputFormat

_DEFAULT_DECOY = (
    "import sys as _pyobf_s\n"
    "_pyobf_s.stderr.write('integrity check failed\\n')\n"
    "__pyobf_decoy__ = True\n"
)


def _resolve_format(options: ObfOptions) -> str:
    fmt = getattr(options, "pack_format", "auto")
    if fmt == "auto":
        return "bytecode" if options.output is OutputFormat.PYC else "source"
    if fmt in ("source", "bytecode"):
        return fmt
    raise ValueError(f"invalid pack_format: {fmt!r}")


def _body_bytes(tree: ast.AST, fmt: str, fname: str = "<pyobf>") -> bytes:
    """Serialize the body to bytes, then zlib-compress. Obfuscated body (flattened source or
    marshalled bytecode) is highly repetitive (~8x on source), so compressing BEFORE encryption
    shrinks the embedded blob dramatically. The launcher decompresses after decrypt (transparent:
    the executed body is byte-identical). Encryption must come AFTER compression — ciphertext is
    incompressible — so the packer compresses here and encrypts (_ks_xor) in core.py.

    `fname` is the inner code object's co_filename. For bytecode it is baked here (marshalled
    code carries it); for source the runtime `compile()` in the launcher tail sets it (so this
    arg is unused on the source path). Randomized per build so an attacker cannot arm an
    audit hook on a fixed `co_filename == "<pyobf>"`."""
    if fmt == "source":
        raw = ast.unparse(tree).encode("utf-8")
    else:
        raw = marshal.dumps(compile(tree, fname, "exec"))
    return zlib.compress(raw, 9)


def _decoy_bytes(decoy_src: str, fmt: str, fname: str = "<pyobf>") -> bytes:
    return _body_bytes(ast.parse(decoy_src), fmt, fname)
