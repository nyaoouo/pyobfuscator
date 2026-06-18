from __future__ import annotations

import ast
import importlib.util
import marshal
import struct

from ..options import ObfOptions, OutputFormat

# PEP 552: flags bit0 = hash-based, bit1 = check_source. 0b01 => hash-based,
# unchecked -> a sourceless .pyc the import system will load without the source.
_PYC_FLAGS = 0b01


def normalize_locations(tree: ast.AST) -> ast.AST:
    """Collapse every source location to line 1, col 0 (strip_debug, AST level)."""
    for node in ast.walk(tree):
        if hasattr(node, "lineno"):
            node.lineno = 1
            node.col_offset = 0
            if hasattr(node, "end_lineno") and node.end_lineno is not None:
                node.end_lineno = 1
            if hasattr(node, "end_col_offset") and node.end_col_offset is not None:
                node.end_col_offset = 0
    return tree


def _to_pyc(code, source_bytes: bytes) -> bytes:
    magic = importlib.util.MAGIC_NUMBER
    flags = struct.pack("<I", _PYC_FLAGS)
    source_hash = importlib.util.source_hash(source_bytes)
    return magic + flags + source_hash + marshal.dumps(code)


def emit(tree: ast.AST, options: ObfOptions, *, sourcemap_out: dict | None = None,
         layer: str = "module", source: str | None = None, artifact: str | None = None):
    # Final naming pass (runs once per emitted tree, before any format branch / unparse / compile):
    # rename the monotonic temp names Namer.fresh() handed out (_pyobf_g<n>) to uniform random
    # _pyobf_<hex>. This covers obf_func, the non-packed obf_module body, AND the launcher tree
    # returned by pack_module. The packed BODY is serialized inside pack_module before reaching here,
    # so pack_module finalizes the body tree itself (see protect/core.py) — with a DISTINCT ns_salt
    # (_BODY_NS_SALT). The launcher keeps the DEFAULT ns_salt=0 here, so the body's and the launcher's
    # _pyobf_<hex> name-spaces are disjoint (required because the body execs in the launcher's globals).
    # Determinism comes from this seeded rename, not the counter.
    #
    # Opt-in sourcemap: when emit_sourcemap is set and a sink is passed, capture finalize's temp->hex
    # out_map and assemble the map for THIS tree into sourcemap_out[layer]. out_map=None otherwise
    # keeps the call (and the output) byte-identical to the no-sourcemap path.
    # Lift every lambda to a named def FIRST (before finalize), so the output has no anonymous-lambda
    # tells and the lifted def names get finalized + recorded in the sourcemap. Behaviour-preserving.
    from .lambdalift import lift_lambdas
    lift_lambdas(tree)
    from .rename import finalize_names
    want_map = bool(getattr(options, "emit_sourcemap", False)) and sourcemap_out is not None
    om: dict | None = {} if want_map else None
    tree = finalize_names(tree, options.seed, out_map=om)
    if want_map:
        from .sourcemap import build_sourcemap
        sourcemap_out[layer] = build_sourcemap(tree, om, layer=layer, seed=options.seed,
                                               source=source, artifact=artifact)

    if options.strip_debug and options.output in (OutputFormat.AST, OutputFormat.PYC):
        tree = normalize_locations(tree)

    if options.output is OutputFormat.AST:
        return tree
    if options.output is OutputFormat.TEXT:
        return ast.unparse(tree)
    if options.output is OutputFormat.PYC:
        filename = "<obf>" if options.strip_debug else "<pyobf>"
        code = compile(tree, filename, "exec")
        return _to_pyc(code, ast.unparse(tree).encode("utf-8"))
    raise ValueError(f"unsupported output format: {options.output!r}")
