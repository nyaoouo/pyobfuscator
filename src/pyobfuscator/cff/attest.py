"""Runtime attestation helpers for the cff <-> python oracle channel.

The launcher (protect/core.py) installs an oracle O into the body's globals:
    O(s) = mix(s, S_correct, MAGIC)

cff randomly replaces a SUBSET of dispatcher gotos `state = T` with an oracle-computed
transition. The body at the top of each flattened unit binds:
    O = globals().setdefault('<oracle_name>', <FALLBACK>)

so a dumped body (no launcher-installed oracle) gets a DECOY oracle (a plausible-looking but
wrong hash; see _make_decoy_oracle_lambda) -> wrong states -> silent divergence. The oracle name
is reconstructed from char codes (name_to_charcode_expr) so it is not a greppable string literal.

This module must NOT import protect (dependency stays protect -> cff, never cff -> protect).
mix() is self-contained (no import from protect.cipher) — protect/core.py imports it from here.
"""
from __future__ import annotations

import ast
import random

_MASK = (1 << 64) - 1

# Seed-derived constants so cff and protect agree without extra params.
# These are derived from a fixed seed so they are build-deterministic.
_ATTEST_SEED = 0xA77E5710_B3A55E1D

# Minimum number of dispatcher transitions that inject_attest gates per flattened unit (or all
# of them if the unit has fewer). attest_density is the probabilistic rate; this floor guarantees
# that even a tiny program with few transitions still gets >=1 oracle-gated goto, so a dumped body
# cannot coincidentally run correctly without the oracle. Because attestation is injected before
# bogus blocks exist, every gating candidate is a real-path dispatcher block.
ATTEST_MIN_GATES = 2


def mix(s: int, k: int, m: int) -> int:
    """Self-contained splitmix64-style 64-bit mix of s ^ k ^ m.
    Returns a 64-bit value. This is the oracle function.
    """
    # XOR all three inputs together first (combining state, key, and magic)
    v = (s ^ k ^ m) & _MASK
    # splitmix64 mixing steps
    v = (v + 0x9E3779B97F4A7C15) & _MASK
    z = v
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
    return (z ^ (z >> 31)) & _MASK


def oracle_name(seed: int) -> str:
    """Return the oracle name for a given build seed. Seed-derived so cff and protect agree."""
    rng = random.Random(seed ^ _ATTEST_SEED)
    suffix = rng.randrange(0, 1 << 32)
    return f"__pyobf_oracle_{suffix:08x}__"


def MAGIC(seed: int) -> int:
    """Return the MAGIC constant for a given build seed. Seed-derived so cff and protect agree."""
    rng = random.Random(seed ^ (_ATTEST_SEED >> 1))
    return rng.randrange(1, 1 << 64)


# ---- Body self-cohash (PYC-only) ----------------------------------------------------------------
# The body computes H = FNV-1a(guard.__code__.co_code) at each gated unit and folds it into the
# oracle-gated transition (`state = O(state) ^ H ^ corr`). protect bakes the correction so the
# genuine path (H == H_build) cancels exactly; ANY tampering that recompiles the body (an AST-
# instrumentation differential, bytecode rewriting) changes the guard's co_code -> H != H_build ->
# wrong state -> divergence/decoy. This extends integrity to the BODY itself (the launcher's
# cohash_integrity only protects the launcher). PYC-ONLY: the .pyc embeds the build-compiled
# co_code, so runtime co_code == build co_code exactly; a TEXT body is recompiled by the end user's
# (possibly different-version) interpreter, so its co_code would not match H_build.
#
# Build/runtime hash agreement: cohash_build_hash(seed) compiles the SAME seeded guard def as cff
# emits, so the hashed co_code is byte-identical by construction. (co_code is independent of the
# seeded constant VALUES and of every identifier name — locals are indexed in bytecode — so finalize
# renaming the guard and nested-vs-standalone compilation both leave co_code unchanged; this is the
# invariant the launcher's _guard_cohash already relies on.)

def _fnv1a(b) -> int:
    """FNV-1a 64-bit. Build-side twin of the emitted hashfn (make_cohash_hashfn_def) AND of
    protect.cipher._hash_bytes — all three MUST stay byte-identical."""
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h ^ c) * 0x100000001B3) & _MASK
    return h


def cohash_names(seed):
    """Seed-derived (guard, hashfn) names for the body cohash. Double-underscore dunder form so
    finalize_names leaves them untouched (like the oracle/corr names) — cff (binding) and the
    wrap_module-emitted defs agree on them."""
    rng = random.Random((seed or 0) ^ 0xC0DE5A17)
    return (f"__pyobf_cog_{rng.randrange(1 << 32):08x}__",
            f"__pyobf_coh_{rng.randrange(1 << 32):08x}__")


def _guard_consts(seed):
    """Per-build (mult, shift) for the guard mixer — seed-derived so no fixed magic signature
    appears in co_consts. The values do not affect H_build (co_code is value-independent); they are
    chosen distinct from MASK so the compiler never dedups a const slot (which WOULD change co_code)."""
    rng = random.Random((seed or 0) ^ 0x9A1C0DE)
    mult = rng.randrange(1 << 62, 1 << 64) | 1   # large odd, != MASK
    shift = rng.choice((13, 17, 19, 23, 29))
    return mult, shift


# Both the emitted def and cohash_build_hash() come from these templates so their AST structure (and
# thus co_code) is identical by construction.
_GUARD_TMPL = "def {name}(v):\n    return ((v * {mult}) ^ (v >> {shift})) & {mask}\n"
_HASHFN_TMPL = (
    "def {name}(b):\n"
    "    h = 0xCBF29CE484222325\n"
    "    for c in b:\n"
    "        h = ((h ^ c) * 0x100000001B3) & {mask}\n"
    "    return h\n"
)


def make_cohash_guard_def(guard_name: str, seed) -> ast.FunctionDef:
    mult, shift = _guard_consts(seed)
    return ast.parse(_GUARD_TMPL.format(name=guard_name, mult=mult, shift=shift, mask=_MASK)).body[0]


def make_cohash_hashfn_def(hashfn_name: str) -> ast.FunctionDef:
    return ast.parse(_HASHFN_TMPL.format(name=hashfn_name, mask=_MASK)).body[0]


def cohash_build_hash(seed) -> int:
    """FNV-1a of the (standalone-compiled) guard's co_code — equals the runtime
    hashfn(guard.__code__.co_code) on the genuine PYC path. Uses the SAME seeded guard def cff emits."""
    guard = make_cohash_guard_def(cohash_names(seed)[0], seed)
    mod = ast.Module(body=[guard], type_ignores=[])
    ast.fix_missing_locations(mod)
    code = compile(mod, "<cohash>", "exec")
    gco = next(c for c in code.co_consts if hasattr(c, "co_code"))
    return _fnv1a(gco.co_code)


def make_cohash_binding(h_var: str, hashfn_name: str, guard_name: str) -> ast.Assign:
    """Emit:  H = HASHFN(GUARD.__code__.co_code)   (a plain int; no lambda/closure)."""
    co_code = ast.Attribute(
        value=ast.Attribute(value=_load(guard_name), attr="__code__", ctx=ast.Load()),
        attr="co_code", ctx=ast.Load())
    return ast.Assign(targets=[_store(h_var)],
                      value=ast.Call(func=_load(hashfn_name), args=[co_code], keywords=[]))


# ---- AST template helpers (analogous to protect/astutil.py, but for attest) ----
# These live in cff/attest.py so they are usable without importing protect.

def _load(name: str) -> ast.Name:
    return ast.Name(id=name, ctx=ast.Load())


def _store(name: str) -> ast.Name:
    return ast.Name(id=name, ctx=ast.Store())


def name_to_charcode_expr(name: str) -> ast.expr:
    """Build an AST expr that reconstructs `name` at runtime from char codes, so the oracle
    name does NOT appear as a greppable string literal in either the body or the launcher:

        ''.join([chr(c) for c in [<ord-ints>]])

    The list-comprehension target is comprehension-scoped (Python 3), so it never leaks or
    collides even when this expr appears multiple times in one scope. Both the body's setdefault
    key and the launcher's install key run the SAME `name` through this, so they agree at runtime.
    """
    codes = [ord(ch) for ch in name]
    comp = ast.ListComp(
        elt=ast.Call(func=_load("chr"), args=[_load("__pyobf_c")], keywords=[]),
        generators=[ast.comprehension(
            target=_store("__pyobf_c"),
            iter=ast.List(elts=[ast.Constant(value=c) for c in codes], ctx=ast.Load()),
            ifs=[], is_async=0)])
    return ast.Call(
        func=ast.Attribute(value=ast.Constant(value=""), attr="join", ctx=ast.Load()),
        args=[comp], keywords=[])


def _make_decoy_oracle_lambda(rng=None) -> ast.Lambda:
    """A self-contained lambda that LOOKS like a hash finalizer but is NOT the genuine oracle:

        lambda s: ((s ^ (s >> SHIFT)) * MULT) & 0xFFFFFFFFFFFFFFFF

    A dumped body (no launcher oracle) binds this via setdefault and uses it for every gated
    transition. Because it lacks the secret (s_correct, magic), its output != mix(s, s_correct,
    magic), so the gated gotos land on wrong states -> divergence (hang/crash/wrong output). The
    SHIFT/MULT vary per build (rng) so there is no fixed signature; any non-genuine function
    diverges, so the exact constants do not matter for correctness — only for stealth. This is
    strictly stealthier than `lambda v: 0`, which reads as an obvious placeholder.
    """
    if rng is None:
        shift, mult = 33, 0xFF51AFD7ED558CCD
    else:
        shift = rng.choice((29, 30, 31, 32, 33))
        mult = rng.randrange(1, 1 << 64) | 1  # force odd (invertible multiplier, mix-like)
    xor_part = ast.BinOp(
        left=_load("s"), op=ast.BitXor(),
        right=ast.BinOp(left=_load("s"), op=ast.RShift(), right=ast.Constant(value=shift)))
    body = ast.BinOp(
        left=ast.BinOp(left=xor_part, op=ast.Mult(), right=ast.Constant(value=mult)),
        op=ast.BitAnd(), right=ast.Constant(value=_MASK))
    return ast.Lambda(
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg="s")],
            vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=body)


def make_setdefault_binding(oracle_var: str, oracle_name_str: str, rng=None) -> ast.Assign:
    """Emit:  O = globals().setdefault(<charcode name>, <decoy oracle lambda>)

    This binding is placed at the top of each flattened unit. When the launcher has installed
    the real oracle in the globals before exec(), globals().setdefault() returns the existing
    (real) oracle. When a dumped body is exec'd in a fresh namespace without the oracle,
    setdefault inserts the DECOY (a wrong hash) and returns it -> wrong states -> divergence.

    The name is reconstructed from char codes (no greppable literal).
    The fallback is a plausible-looking wrong hash (no obvious `lambda v: 0` placeholder).
    """
    name_expr = name_to_charcode_expr(oracle_name_str)
    fallback = _make_decoy_oracle_lambda(rng)
    call = ast.Call(
        func=ast.Attribute(
            value=ast.Call(func=_load("globals"), args=[], keywords=[]),
            attr="setdefault", ctx=ast.Load()),
        args=[name_expr, fallback],
        keywords=[])
    return ast.Assign(targets=[_store(oracle_var)], value=call)


def _oracle_xor(state_name: str, oracle_var: str, marker_name: str, h_var: str | None) -> ast.expr:
    """Build `O(state) [^ H] ^ MARKER`. When h_var is given (body cohash enabled), the runtime
    self-hash H is folded in; protect bakes H_build into the correction so the genuine path cancels
    (H == H_build -> the term vanishes) and any co_code tamper (H != H_build) lands on a wrong state.
    h_var=None reproduces the two-term form byte-identically (XOR is left-associative; no extra node)."""
    expr = ast.Call(func=_load(oracle_var), args=[_load(state_name)], keywords=[])  # O(state)
    if h_var is not None:
        expr = ast.BinOp(left=expr, op=ast.BitXor(), right=_load(h_var))            # O(state) ^ H
    return ast.BinOp(left=expr, op=ast.BitXor(), right=_load(marker_name))          # ... ^ MARKER


def make_oracle_goto_absolute(
        state_name: str, oracle_var: str, marker_name: str, h_var: str | None = None) -> ast.Assign:
    """Emit (state_delta OFF):  state = O(state) [^ H] ^ __pyobf_corr_<id>__

    The marker Name is a placeholder that protect/core.py will replace with the computed
    CORRECTION constant. `h_var` adds the body self-cohash term; see _oracle_xor.
    """
    return ast.Assign(targets=[_store(state_name)],
                      value=_oracle_xor(state_name, oracle_var, marker_name, h_var))


def make_oracle_goto_relative(
        state_name: str, oracle_var: str, marker_name: str, h_var: str | None = None) -> ast.AugAssign:
    """Emit (state_delta ON):  state += (O(state) [^ H] ^ __pyobf_corr_<id>__)

    CORRECTION_delta = (T - s) ^ mix(s, s_correct, magic) [^ H_build]  (no masking — ints unbounded)
    At runtime: O(state) [^ H] ^ CORRECTION_delta = mix(s,...) ^ ((T-s) ^ mix(s,...)) = T - s
    So: state += (T - s)  =>  state = T  ✓   (the H terms cancel when H == H_build)

    No & MASK here: masking would corrupt the delta for state IDs where T < s (negative delta
    would become a large positive 64-bit value, making state != T).

    A gated AugAssign has a non-Constant value, so the later state_delta_transform
    (which only rewrites Assign(state, Constant)) skips it — no conflict.
    """
    # state += (O(state) [^ H] ^ MARKER)   — no & MASK, Python ints are unbounded
    return ast.AugAssign(
        target=_store(state_name),
        op=ast.Add(),
        value=_oracle_xor(state_name, oracle_var, marker_name, h_var))


def make_oracle_installer(oracle_name_str: str, oracle_var_in_launcher: str,
                          s_correct: int, magic: int) -> ast.Assign:
    """Emit the launcher-side oracle installation statement:
        <var> = (lambda k, m: lambda s: mix(s, k, m))(s_correct, magic)

    This is spliced into the launcher globals BEFORE the decrypt/exec tail.
    The oracle is a closure capturing s_correct and magic at build time,
    so it does not appear as a recognizable constant in the launched code.

    protect/core.py constructs the assignment directly using the imported mix function.
    """
    # protect/core.py has direct access to s_correct and builds the installation
    # statement using AST helpers directly.
    raise NotImplementedError(
        "protect/core.py builds the oracle installer AST directly")
