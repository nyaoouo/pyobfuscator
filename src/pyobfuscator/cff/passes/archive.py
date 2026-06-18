"""ArchivePass — pool module/function constant literals (int/float/str/bytes) into ONE
encrypted blob, replacing each literal site with a `_get(off, sz, key, cast)` accessor call.

Layered crypto (see plan): per-record `_ks_xor(serialize(v), _kdf(k))` with `k` recovered at
runtime via `pow(c, D, N)`; bulk `_ks_xor(.., BULK)` + b85 transport. The accessor + its crypto
helpers are injected AFTER the rewrite (their own literals are never re-archived).
"""
from __future__ import annotations

import ast
import struct as _struct

import random

from ..gate import SupportSet
from ..names import Namer, collect_names
from ...options import ObfOptions
from ...protect.cipher import _ks_xor as _bld_ks, _kdf as _bld_kdf
from .flatten import FLATTEN_ALLOWED
from .dataobf import _rsa_params, _collect_skip


class ArchivePass:
    name = "archive"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.const_archive:
            return tree
        skip = _collect_skip(tree)
        col = _Collector(skip)
        col.visit(tree)
        if not col.values:
            return tree

        seed = options.seed if options.seed is not None else 0
        rng = random.Random(seed ^ 0xA12C0DE)
        blob, index, E, D, N, bulk = _build_archive(col.values, rng)

        namer = Namer(seed, collect_names(tree))
        names = dict(get=namer.fresh("get"), ks=namer.fresh("ks"), kdf=namer.fresh("kdf"),
                     memo=namer.fresh("C"), rawc=namer.fresh("R"), blob=namer.fresh("B"),
                     b64=namer.fresh("b64"), st=namer.fresh("st"))
        get_name = names["get"]
        node_ids = {id(n) for n in col.nodes}

        class _Rw(ast.NodeTransformer):
            def visit_Constant(self, node):
                if id(node) not in node_ids:
                    return node
                off, sz, c, cast = index[(type(node.value), node.value)]
                call = ast.Call(func=ast.Name(id=get_name, ctx=ast.Load()),
                                args=[ast.Constant(off), ast.Constant(sz),
                                      ast.Constant(c), ast.Constant(cast)], keywords=[])
                # Mark this accessor call so the SECOND (post_vault) StackCall pass may arg-hide it
                # through the push/invoke stack (Phase 4 D). Only the `_get(...)` CALL SITES carry the
                # marker; the `_get`/`_ks`/`_kdf` helper bodies (emitted below) never do, so their
                # internal pow/range/int.from_bytes calls are never routed. The second pass also
                # restricts routing to statement-level values, so a `_get(...)` nested inside another
                # call (e.g. inside a helper's getattr) is left alone regardless of the marker.
                call._pyobf_stackroute = True
                return ast.copy_location(call, node)

        tree = _Rw().visit(tree)

        fmt = "text" if str(getattr(options.output, "value", options.output)) == "text" else "bc"
        runtime = _emit_runtime(names, blob, D, N, bulk, fmt=fmt)

        body = tree.body if isinstance(tree, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if body is not None:
            pos = 0
            while pos < len(body) and (
                (isinstance(body[pos], ast.Expr) and isinstance(body[pos].value, ast.Constant)
                 and isinstance(body[pos].value.value, str))
                or (isinstance(body[pos], ast.ImportFrom) and body[pos].module == "__future__")):
                pos += 1
            body[pos:pos] = runtime
        ast.fix_missing_locations(tree)
        return tree


def _eligible_value(v):
    t = type(v)
    if t is bool:
        return False                 # bool stays inline (and would corrupt int round-trip)
    if t is int:
        return abs(v) > 1            # tiny ints stay inline (match obf_ints convention)
    return t in (float, str, bytes)


class _Collector(ast.NodeVisitor):
    """Collect eligible Constant nodes + the unique value list (order-preserving, deduped)."""
    def __init__(self, skip):
        self.skip = skip
        self.nodes = []              # Constant nodes to replace
        self.values = []             # unique values, order-preserving
        self._seen = {}
    def visit_Constant(self, node):
        if id(node) in self.skip:
            return
        if getattr(node, "_pyobf_no_archive", False):
            return                   # e.g. name-vault dict keys: kept inline for state-keying (key_consts)
        v = node.value
        if not _eligible_value(v):
            return
        key = (type(v), v)
        if key not in self._seen:
            self._seen[key] = len(self.values)
            self.values.append(v)
        self.nodes.append(node)


# cast codes: 0=int, 1=float, 2=str, 3=bytes
def _serialize(v):
    t = type(v)
    if t is int:                       # bool is excluded by the eligibility filter
        nbytes = (v.bit_length() + 8) // 8 or 1
        return v.to_bytes(nbytes, "little", signed=True), 0
    if t is float:
        return _struct.pack("<d", v), 1
    if t is str:
        return v.encode("utf-8", "surrogatepass"), 2
    if t is bytes:
        return v, 3
    raise TypeError(f"unserializable const type {t!r}")


def _deserialize(rec: bytes, cast: int):
    if cast == 0:
        return int.from_bytes(rec, "little", signed=True)
    if cast == 1:
        return _struct.unpack("<d", rec)[0]
    if cast == 2:
        return rec.decode("utf-8", "surrogatepass")
    return rec


def _build_archive(values, rng):
    """values: list of unique python values. Returns (raw_blob_bytes, index, E, D, N, bulk_key).
    index maps (type, value) -> (offset, size, c, cast).
    PRECONDITION: `values` MUST be pre-deduplicated; a duplicate (type, value) collapses to its
    LAST occurrence in the index (earlier encrypted bytes left orphaned in the blob). `_Collector`
    enforces this upstream."""
    E, D, N = _rsa_params(rng)
    bulk_key = rng.randrange(1, 1 << 64)
    enc = bytearray()
    index = {}
    for v in values:
        rec, cast = _serialize(v)
        k = rng.randrange(1, 1 << 64)
        ct = _bld_ks(rec, _bld_kdf(k))
        off = len(enc)
        enc += ct
        index[(type(v), v)] = (off, len(rec), pow(k, E, N), cast)
    blob = _bld_ks(bytes(enc), bulk_key)   # bulk layer; b85 transport applied at emit time
    return blob, index, E, D, N, bulk_key


import base64 as _bld_b64

# The {ks}/{kdf} bodies inside _RUNTIME_TMPL below MUST stay byte-for-byte identical to
# protect/cipher.py::_ks_xor/_kdf: _build_archive() encrypts with those, this template
# decrypts with these. Any drift silently corrupts every archive. Keep all copies in sync.
#
# The {get} memo is keyed on (off, sz, cast), NOT off alone: a zero-length literal (b"" / "")
# serializes to 0 bytes and therefore shares its offset with the NEXT value in the blob. Keying
# on off alone would alias those entries (the cached empty value would be returned for the
# following literal), silently corrupting decode. The composite key disambiguates them.
_RUNTIME_TMPL = '''
import base64 as {b64}
import struct as {st}
{blob} = {blobassign}
{rawc} = [None]
{memo} = {{}}
def {ks}(data, key):
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
def {kdf}(s):
    s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = s
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF
def {get}(off, sz, c, cast):
    m = {memo}
    mk = (off, sz, cast)
    if mk in m:
        return m[mk]
    raw = {rawc}[0]
    if raw is None:
        raw = {ks}({blob}, {bulk})
        {rawc}[0] = raw
    k = pow(c, {D}, {N})
    rec = {ks}(raw[off:off + sz], {kdf}(k))
    if cast == 0:
        v = int.from_bytes(rec, "little", signed=True)
    elif cast == 1:
        v = {st}.unpack("<d", rec)[0]
    elif cast == 2:
        v = rec.decode("utf-8", "surrogatepass")
    else:
        v = rec
    m[mk] = v
    return v
'''


def _emit_runtime(names, blob, D, N, bulk, fmt):
    """Return the list of AST statements (imports, _ks/_kdf copies, blob var, memo, _get accessor)
    for the archive. For text output the blob is embedded as base64.b85decode(b'<ascii>'); for any
    other format the raw bytes literal is used. `names` provides fresh identifiers for
    get/ks/kdf/memo/rawc/blob/b64/st. The helpers are emitted here (AFTER the rewrite that creates
    _get calls) so their own literals are never themselves archived."""
    if fmt == "text":
        blobassign = "%s.b85decode(%r)" % (names["b64"], _bld_b64.b85encode(blob))
    else:
        blobassign = "%r" % (blob,)
    src = _RUNTIME_TMPL.format(blobassign=blobassign, bulk=bulk, D=D, N=N, **names)
    mod = ast.parse(src)
    # The template's helper PARAM/LOCAL names (off/sz/c/cast/data/key/s/z/raw/rec/...) are literal;
    # rename them here (at injection) to fresh obfuscator names — minted from the global counter,
    # unified by finalize_names — so the helpers carry no plaintext identifiers either.
    from .localrename import rename_simple_helper_locals
    rename_simple_helper_locals(mod)
    return mod.body
