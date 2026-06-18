"""Final distribution wrap (option `compress_output`): take the WHOLE emitted payload — the packed
launcher or the obfuscated module — and ship a tiny bootstrap that DECODES + DECOMPRESSES + execs it.
Shrinks the distributed file and adds a static-extraction speed bump.

Per layer the payload is: zlib-compressed, then encrypted with a seed-derived rolling XOR (key `k`),
then b85-transported (TEXT) or kept raw (PYC). The bootstrap reverses it:

    _c = 0;  plain = bytes((_c := b ^ _c ^ k) for b in b85decode(<blob>))   # rolling XOR, then
    exec(compile(zlib.decompress(plain), '<pyobf>', 'exec'))                 # decompress + exec

Why the rolling XOR: a naive `b85decode + zlib.decompress` no longer yields the source (it's XOR
ciphertext), so a lazy analyst is nudged toward hooking `exec` to capture the plaintext — which trips
the launcher's existing builtin-integrity (it folds `type(exec)` / `exec.__code__` into the key), so a
replaced/hooked `exec` routes the body to the decoy/honeypot. `k` is byte-sized (the chain gives
position-dependence): this is a speed bump + honeypot lure, NOT strong crypto.

Refinements:
  * `rounds` (compress_rounds): wrap N times, each with its OWN `k`. N>1 does not shrink further but
    forces peeling N layers. EACH round adds ONE persistent exec frame above the launcher, so
    detect_stack walks `rounds + 1` f_back links (see detectors.StackDetector).
  * decoy head (TEXT): a no-op layer prepended to the launcher source. It is built from the SAME
    `_layer_src` template as a real round (inline `__import__`, `_pyx_k`/`_pyx_c`, rolling XOR,
    compile+exec) so it is byte-shape-IDENTICAL to one — only its payload is EMPTY (decompresses to b'',
    `exec(compile(b''))` is a no-op, returns at once -> no lasting frame -> detect_stack unaffected). It
    therefore reads as 'just another layer' that peels to nothing, instead of a distinguishable
    one-liner. Both layer kinds use inline `__import__` (no `import zlib, base64` statement).

`k` is seed-derived (NOT os-random) so builds stay byte-reproducible. Execution runs in the bootstrap's
own module globals, so `__name__` and the payload's inner `exec(body, globals())` keep working.
"""
from __future__ import annotations

import base64
import marshal
import random
import zlib

_OUTER_FNAME = "<pyobf>"


def _xor_encrypt(p: bytes, k: int) -> bytes:
    """Encrypt so the bootstrap's `_c := b ^ _c ^ k` chain (with _c=0) recovers `p`:
    E[i] = P[i] ^ P[i-1] ^ k (P[-1]=0). All values are bytes, so no masking is needed."""
    out = bytearray(len(p))
    prev = 0
    for i in range(len(p)):
        out[i] = p[i] ^ prev ^ k
        prev = p[i]
    return bytes(out)


def _b85_literal_lines(data: bytes, width: int = 3072) -> str:
    """b85-encode `data` as adjacent `b'..'` literals, one per line (Python concatenates adjacent
    string literals at parse), so the payload never occupies a single giant line."""
    b85 = base64.b85encode(data)
    if not b85:
        return "b''"
    return "\n".join(repr(b85[i:i + width]) for i in range(0, len(b85), width))


def _layer_src(b85_lines: str, k: int, fname: str = _OUTER_FNAME) -> str:
    """The UNIFIED layer template used by BOTH a real compression round AND the decoy head, so the two
    are byte-shape-IDENTICAL (a static classifier / layer-peeler cannot tell them apart by shape):
    inline `__import__` (no `import zlib, base64` statement), the `_pyx_k`/`_pyx_c` rolling-XOR vars,
    and `exec(compile(zlib.decompress(bytes(<rolling-xor> over b85decode(<blob>))), fname, 'exec'))`.
    A real round's <blob> carries the next layer; the decoy's <blob> is empty."""
    return ("_pyx_k = %d\n_pyx_c = 0\n"
            "exec(compile(__import__('zlib').decompress(bytes((_pyx_c := _pyx_b ^ _pyx_c ^ _pyx_k) "
            "for _pyx_b in __import__('base64').b85decode(\n"
            "%s\n"
            "))), %r, 'exec'))\n" % (k, b85_lines, fname))


def decoy_head(k: int = 0) -> str:
    """A no-op layer that is byte-shape-IDENTICAL to a real compression round (same `_layer_src`
    template: inline import, `_pyx_k`/`_pyx_c`, rolling XOR, compile+exec) but whose payload is EMPTY —
    it decompresses to b'', so `exec(compile(b''))` is a no-op and returns at once (no lasting frame ->
    detect_stack unaffected). Prepended to the launcher source it now reads as 'just another layer'
    instead of a distinguishable `__import__(...).decompress(...)` one-liner. (Against a peeler that
    captures the FIRST `compile()` it also runs first -> the peeler captures the empty payload.)"""
    enc = _xor_encrypt(zlib.compress(b"", 9), k)
    return _layer_src(_b85_literal_lines(enc), k)


def outer_compress_text(src: str, k: int) -> str:
    enc = _xor_encrypt(zlib.compress(src.encode("utf-8"), 9), k)
    return _layer_src(_b85_literal_lines(enc), k)


def outer_compress_pyc(pyc_bytes: bytes, to_pyc, k: int) -> bytes:
    # A .pyc is a 16-byte header (magic 4 + flags 4 + source-hash 8) then marshal(code). Recompress +
    # XOR-encrypt the marshalled launcher code, wrap in a bootstrap .pyc.
    code = marshal.loads(bytes(pyc_bytes)[16:])
    enc = _xor_encrypt(zlib.compress(marshal.dumps(code), 9), k)
    wrapper_src = ("import marshal, zlib\n"
                   "_pyx_k = %d\n_pyx_c = 0\n"
                   "exec(marshal.loads(zlib.decompress(bytes((_pyx_c := _pyx_b ^ _pyx_c ^ _pyx_k) "
                   "for _pyx_b in %r))))\n" % (k, enc))
    return to_pyc(compile(wrapper_src, _OUTER_FNAME, "exec"), wrapper_src.encode("utf-8"))


def outer_compress(result, to_pyc, *, rounds: int = 1, decoy: bool = True, rng=None):
    """Wrap whatever emit() produced (source str = TEXT, .pyc bytes = PYC), `rounds` times, each with
    its own seed-derived XOR key. Deterministic for a given `rng`. The TEXT decoy head is added once,
    at the innermost (launcher) layer."""
    rng = rng or random.Random(0)
    rounds = max(1, int(rounds))
    if isinstance(result, str):
        if decoy:
            result = decoy_head(rng.randrange(1, 256)) + "\n" + result   # own k -> looks like a real layer
        for _ in range(rounds):
            result = outer_compress_text(result, rng.randrange(1, 256))
        return result
    if isinstance(result, (bytes, bytearray)):
        out = bytes(result)
        for _ in range(rounds):           # decoy is TEXT-only; pyc gets the rounds + XOR layering
            out = outer_compress_pyc(out, to_pyc, rng.randrange(1, 256))
        return out
    return result  # AST output etc.: nothing to wrap
