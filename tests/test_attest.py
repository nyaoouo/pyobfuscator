"""Tests for cff <-> python runtime attestation (task #40).

The oracle O(s) = mix(s, S_correct, MAGIC) is installed by the launcher into the body's
globals. cff randomly gates a subset of state transitions: state = O(state) ^ CORRECTION.
A dumped body executed without the launcher's oracle binds a DECOY oracle (a plausible-looking
but wrong hash, via globals().setdefault) and produces wrong states -> wrong results -> genuine
divergence from the real output. The oracle name is reconstructed from char codes, so it is not
a greppable string literal in either the launcher or the body.

RULE #0 (the most important rule): every test that runs the body on a WRONG/ABSENT-oracle path
MUST be TIME-BOUNDED, and MUST use a KILLABLE SUBPROCESS — never a daemon thread. A wrong-state
CFF dispatcher busy-loops forever (`while True:` with no matching branch); a daemon thread cannot
be killed, so the runaway loop would peg a CPU for the rest of the suite (this is what hung the
earlier attempts). subprocess.run(timeout=...) terminates the loop with the process. Treat
hang/timeout OR crash OR wrong-output ALL as "diverged = PASS"; only reproducing the real result
is a FAIL. See _diverges_without_oracle.
"""
from __future__ import annotations

import ast
import marshal
import sys
import threading
import types

import pytest

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0] + "/src" if "/tests/" in __file__
                else __file__.rsplit("\\tests\\", 1)[0] + "\\src")

from pyobfuscator import obf_module, ModuleObfOptions
from pyobfuscator.cff.attest import mix, oracle_name, MAGIC


# ---- helpers -----------------------------------------------------------------

def _exec_text(src: str, name: str = "m") -> dict:
    ns = {"__name__": name}
    exec(compile(src, "<t>", "exec"), ns)
    return ns


def _exec_code(code, name: str = "m") -> dict:
    ns = {"__name__": name}
    exec(code, ns)
    return ns


def _real_result(launcher_src: str, keys) -> dict:
    """Genuine path: run the launcher IN-PROCESS without replacing any builtin (so the launcher's
    builtin-integrity check passes). The launcher installs its own oracle and execs the body into
    this namespace, so the real results are read directly. No capture / no exec-spy needed."""
    ns = {"__name__": "m"}
    exec(compile(launcher_src, "<launcher>", "exec"), ns)
    return {k: ns.get(k) for k in keys}


def _capture_body_src(launcher_src: str, timeout: float = 8.0) -> str:
    """Capture the decrypted body SOURCE WITHOUT replacing any builtin.

    The launcher decompresses the body via ``zlib.decompress`` (a MODULE function, not a builtin),
    so wrapping it in a subprocess captures the body bytes without tripping the builtin-integrity
    check (which now flags a replaced ``exec``/``compile``/``pow``/...). This is the subprocess-
    based replacement for the old in-process exec-spy capture, which the integrity check correctly
    rejects. ``pack_format='source'`` => the captured bytes are utf-8 body source text."""
    import subprocess, tempfile, os, sys, base64
    probe = (
        "import sys, zlib, base64\n"
        "_real = zlib.decompress; _cap = []\n"
        "def _w(*a, **k):\n"
        "    out = _real(*a, **k); _cap.append(out); return out\n"
        "zlib.decompress = _w\n"
        "exec(compile(base64.b64decode(%r).decode('utf-8'), '<launcher>', 'exec'), {'__name__': 'm'})\n"
        "sys.stdout.write('__BODY__' + base64.b64encode(_cap[-1]).decode())\n"
        % (base64.b64encode(launcher_src.encode()).decode(),)
    )
    pf = tempfile.NamedTemporaryFile("w", suffix="_cap.py", delete=False, encoding="utf-8")
    pf.write(probe); pf.close()
    try:
        r = subprocess.run([sys.executable, pf.name], capture_output=True, text=True, timeout=timeout)
    finally:
        os.unlink(pf.name)
    assert "__BODY__" in r.stdout, ("body capture failed", r.stdout[-300:], r.stderr[-300:])
    return base64.b64decode(r.stdout.split("__BODY__", 1)[1].strip()).decode("utf-8")


def _diverges_without_oracle_src(body_src: str, real_values: dict, timeout: float = 8.0) -> bool:
    """Compile+exec the body SOURCE WITHOUT the launcher oracle in a KILLABLE SUBPROCESS (RULE #0).

    Without the oracle, ``globals().setdefault(<oracle_name>, <decoy>)`` binds the DECOY hash -> the
    gated transitions land on wrong states. A daemon thread CANNOT be killed (a wrong-state CFF
    dispatcher busy-loops in ``while True:``), so a subprocess+timeout is mandatory. Divergence
    (PASS) = timeout/hang OR crash OR wrong captured globals; only reproducing ``real_values``
    returns False (the security property FAILED)."""
    import subprocess, tempfile, os, sys, json, base64
    keys = list(real_values)
    probe = (
        "import sys, json, base64\n"
        "src = base64.b64decode(%r).decode('utf-8')\n"
        "ns = {'__name__': 'm'}\n"           # NO oracle -> globals().setdefault binds the decoy
        "exec(compile(src, '<pyobf>', 'exec'), ns)\n"
        "print('__DONE__' + json.dumps({k: ns.get(k) for k in %r}))\n"
        % (base64.b64encode(body_src.encode()).decode(), keys)
    )
    pf = tempfile.NamedTemporaryFile("w", suffix="_noora.py", delete=False, encoding="utf-8")
    pf.write(probe); pf.close()
    try:
        r = subprocess.run([sys.executable, pf.name], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return True   # hang (wrong state -> dispatcher never exits) => diverged
    finally:
        os.unlink(pf.name)
    if r.returncode != 0 or "__DONE__" not in r.stdout:
        return True   # crash => diverged
    try:
        got = json.loads(r.stdout.split("__DONE__", 1)[1].strip().splitlines()[-1])
    except Exception:
        return True
    return got != real_values   # wrong output => diverged


FULL_PACKER = dict(
    pack_body=True,
    key_from_cff=True,
    integrity_selfcheck=True,
    pack_decoy=True,
    min_blocks=1,
    output="text",
    pack_format="source",
    shuffle_states=True,
    bogus_blocks=True,
    opaque_predicates=True,
    attest=True,
    attest_density=0.5,  # gate 50% so we reliably get at least one gated transition
)

_SIMPLE_SRC = (
    "RESULT = 0\n"
    "def compute(x):\n"
    "    if x > 0:\n"
    "        return x * 2\n"
    "    return x - 1\n"
    "RESULT = compute(7)\n"
)

_COMPLEX_SRC = (
    "VALS = []\n"
    "def process(n):\n"
    "    acc = 0\n"
    "    for i in range(n):\n"
    "        acc += i * i\n"
    "    return acc\n"
    "for k in range(4):\n"
    "    VALS.append(process(k))\n"
    "TOTAL = sum(VALS)\n"
)


# ---- test: attest=False is zero-change (sanity) ----

def test_attest_false_zero_change():
    """attest=False (default) => the obfuscated output is equivalent to CPython, as before."""
    src = _SIMPLE_SRC
    opts = ModuleObfOptions(pack_body=True, key_from_cff=True, min_blocks=1,
                            output="text", seed=42, attest=False)
    out = obf_module(src, opts)
    orig = _exec_text(src, "orig")
    obf = _exec_text(out, "obf")
    assert orig["RESULT"] == obf["RESULT"] == 14
    assert orig["compute"](3) == obf["compute"](3) == 6


# ---- test: attest=True + full packer => genuine behavior equiv to CPython ----

@pytest.mark.parametrize("seed", [1, 42, 101])
def test_attest_genuine_path_equivalent(seed):
    """With attest=True and the full packer, untraced genuine execution is equiv to CPython."""
    opts = ModuleObfOptions(seed=seed, **FULL_PACKER)
    out = obf_module(_SIMPLE_SRC, opts)
    orig = _exec_text(_SIMPLE_SRC, "orig")
    obf = _exec_text(out, "obf")
    assert orig["RESULT"] == obf["RESULT"] == 14
    assert orig["compute"](5) == obf["compute"](5) == 10
    assert orig["compute"](-3) == obf["compute"](-3) == -4


@pytest.mark.parametrize("seed", [7, 99])
def test_attest_complex_src_equivalent(seed):
    """attest=True on a more complex source with loops => still equiv to CPython."""
    opts = ModuleObfOptions(seed=seed, **FULL_PACKER)
    out = obf_module(_COMPLEX_SRC, opts)
    orig = _exec_text(_COMPLEX_SRC, "orig")
    obf = _exec_text(out, "obf")
    assert orig["VALS"] == obf["VALS"]
    assert orig["TOTAL"] == obf["TOTAL"]


# ---- test: attest=True without pack_body/key_from_cff raises ----

def test_attest_without_packer_raises():
    """attest=True without pack_body+key_from_cff must raise a clear error."""
    with pytest.raises(ValueError, match="attest.*requires.*pack_body.*key_from_cff"):
        obf_module(_SIMPLE_SRC, ModuleObfOptions(attest=True, pack_body=False, min_blocks=1))


def test_attest_without_key_from_cff_raises():
    """attest=True + pack_body but without key_from_cff raises."""
    with pytest.raises(ValueError, match="attest.*requires.*pack_body.*key_from_cff"):
        obf_module(_SIMPLE_SRC, ModuleObfOptions(attest=True, pack_body=True,
                                                  key_from_cff=False, min_blocks=1))


@pytest.mark.parametrize("out", ["ast"])
def test_attest_with_non_text_pyc_output_raises(out):
    """attest=True needs the packer to patch CORRECTION markers + install the oracle, which only
    happens for output text/pyc. output='ast' would otherwise leave unpatched __pyobf_corr_*
    placeholders -> NameError at runtime; reject it up front instead."""
    with pytest.raises(ValueError, match="attest.*requires output"):
        obf_module(_SIMPLE_SRC, ModuleObfOptions(attest=True, pack_body=True, key_from_cff=True,
                                                  min_blocks=1, output=out))


# ---- test: mix() and oracle_name() / MAGIC() are deterministic and seed-derived ----

def test_mix_self_contained():
    """mix(s, k, m) is deterministic and produces different outputs for different inputs."""
    v = mix(42, 100, 200)
    assert v == mix(42, 100, 200)  # deterministic
    assert 0 <= v < (1 << 64)      # 64-bit range
    assert mix(42, 100, 200) != mix(43, 100, 200)  # s-sensitive
    assert mix(42, 100, 200) != mix(42, 101, 200)  # k-sensitive
    assert mix(42, 100, 200) != mix(42, 100, 201)  # m-sensitive


def test_oracle_name_seed_derived():
    """oracle_name(seed) is deterministic and seed-dependent."""
    assert oracle_name(0) == oracle_name(0)
    assert oracle_name(0) != oracle_name(1)
    assert oracle_name(42).startswith("__pyobf_oracle_")


def test_MAGIC_seed_derived():
    """MAGIC(seed) is deterministic and seed-dependent."""
    assert MAGIC(0) == MAGIC(0)
    assert MAGIC(0) != MAGIC(1)
    assert 0 < MAGIC(42) < (1 << 64)


# ---- DUMP-REPLAY test (the real security gate) ----

# NOTE: the former in-process `_get_body_src_and_oracle` captured the body by replacing
# `builtins.exec` with a spy. The builtin-integrity check now (correctly) flags a replaced
# `exec`/`compile`, so that capture would route to the decoy. Body capture is therefore done via
# `_capture_body_src` (a subprocess that wraps the non-builtin `zlib.decompress`); the genuine
# (with-oracle) result is obtained by simply running the launcher via `_real_result`.


@pytest.mark.parametrize("seed", [1, 42])
def test_dump_replay_diverges(seed):
    """DUMP-REPLAY security test.

    Build with attest + full packer. Capture the decrypted body AND the installed oracle
    from a genuine launcher run. Then:
      1. Exec the body WITH the oracle in a fresh namespace => real result.
      2. Exec the same body WITHOUT the oracle in a fresh namespace (TIME-BOUNDED via a KILLABLE
         subprocess) => the DECOY oracle is used => wrong state transitions => divergence.

    Divergence = hang/timeout OR wrong output OR exception — all three count as PASS.
    Only reproducing the real result counts as FAIL.

    RULE #0 compliance: the no-oracle path runs in a KILLABLE subprocess (subprocess.run with
    timeout), never a daemon thread, so an infinite-loop in the CFF dispatcher cannot hang the
    suite (see _diverges_without_oracle).
    """
    # Source with enough branching to have multiple state transitions, so gating at density=0.5
    # will almost certainly gate at least one transition.
    src = (
        "R = []\n"
        "def f(x):\n"
        "    if x > 5:\n"
        "        return x * 3\n"
        "    elif x > 0:\n"
        "        return x + 10\n"
        "    else:\n"
        "        return 0\n"
        "for i in range(5):\n"
        "    R.append(f(i))\n"
        "TOTAL = sum(R)\n"
    )

    opts = ModuleObfOptions(seed=seed, **FULL_PACKER)
    launcher_src = obf_module(src, opts)

    # 1. Genuine path: run the launcher (no builtin replacement -> integrity passes) => real result.
    ref = _exec_text(src)
    real = _real_result(launcher_src, ["R", "TOTAL"])
    assert real == {"R": ref["R"], "TOTAL": ref["TOTAL"]}, (
        f"With-oracle (genuine) run gave {real!r} != reference "
        f"{{'R': {ref['R']!r}, 'TOTAL': {ref['TOTAL']!r}}}")

    # 2. Capture the decrypted body via a subprocess that wraps zlib.decompress (NOT by replacing
    #    exec/compile, which the builtin-integrity check now flags), then exec it WITHOUT the oracle
    #    in a KILLABLE subprocess (RULE #0): the decoy oracle => wrong states => divergence.
    body_src = _capture_body_src(launcher_src)
    assert _diverges_without_oracle_src(body_src, {"R": ref["R"], "TOTAL": ref["TOTAL"]}), (
        "DUMP-REPLAY PROTECTION FAILED: the body reproduced the real result WITHOUT the launcher "
        "oracle -- no state transition was actually gated (raise attest_density or use a source "
        "with more state transitions)."
    )


# ---- test: state_delta=True + attest => genuine path still works ----

@pytest.mark.parametrize("seed", [5, 77])
def test_attest_state_delta_equivalent(seed):
    """attest=True + state_delta=True => relative-form gating; genuine path equiv to CPython."""
    opts = ModuleObfOptions(
        seed=seed,
        pack_body=True, key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
        min_blocks=1, output="text", pack_format="source",
        shuffle_states=True, bogus_blocks=True, opaque_predicates=True,
        state_delta=True,
        attest=True, attest_density=0.4,
    )
    out = obf_module(_COMPLEX_SRC, opts)
    orig = _exec_text(_COMPLEX_SRC, "orig")
    obf = _exec_text(out, "obf")
    assert orig["VALS"] == obf["VALS"]
    assert orig["TOTAL"] == obf["TOTAL"]


# ---- test: dump-replay with state_delta=True ----

@pytest.mark.parametrize("seed", [33])
def test_dump_replay_state_delta_diverges(seed):
    """Dump-replay also diverges when state_delta=True (relative AugAssign form).

    RULE #0 compliance: the no-oracle path is TIME-BOUNDED via a KILLABLE subprocess.
    A hang is the expected divergence when the wrong oracle sends state to a value
    that never matches any dispatcher branch.
    """
    src = (
        "V = 0\n"
        "def g(n):\n"
        "    s = 0\n"
        "    for i in range(n):\n"
        "        s += i\n"
        "    return s\n"
        "V = g(10)\n"
    )
    opts = ModuleObfOptions(
        seed=seed,
        pack_body=True, key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
        min_blocks=1, output="text", pack_format="source",
        shuffle_states=True, bogus_blocks=True, opaque_predicates=True,
        state_delta=True,
        attest=True, attest_density=0.5,
    )
    launcher_src = obf_module(src, opts)

    # Genuine path (no builtin replacement -> integrity passes) => real V.
    ref = _exec_text(src)
    real = _real_result(launcher_src, ["V"])
    assert real == {"V": ref["V"]} == {"V": 45}, real

    # Capture body via zlib-hook subprocess (not exec replacement), then run WITHOUT the oracle.
    body_src = _capture_body_src(launcher_src)
    assert _diverges_without_oracle_src(body_src, {"V": 45}), (
        "DUMP-REPLAY (state_delta=True) FAILED: body reproduced correct V=45 without the oracle. "
        "Relative-form gating is not actually gating any transition."
    )


# ---- minimum-count floor protects even at attest_density=0.0 ----

def test_attest_floor_protects_at_zero_density():
    """Even at attest_density=0.0, the minimum-count floor (ATTEST_MIN_GATES) forces >=1 gated
    transition, so a tiny program is still dump-replay-protected. Without the floor, density=0
    would gate nothing and the dumped body would reproduce the real result (no protection).

    RULE #0: the no-oracle path uses a KILLABLE subprocess.
    """
    src = "X = 0\nfor i in range(3):\n    X += i\n"
    opts = ModuleObfOptions(seed=3, pack_body=True, key_from_cff=True, integrity_selfcheck=True,
                            pack_decoy=True, min_blocks=1, output="text", pack_format="source",
                            attest=True, attest_density=0.0)
    launcher_src = obf_module(src, opts)
    # Genuine path (no builtin replacement -> integrity passes) => real X.
    ref = _exec_text(src)
    real = _real_result(launcher_src, ["X"])
    assert real == {"X": ref["X"]} == {"X": 3}, real

    # Dump-replay (no oracle) => diverge, thanks to the floor (density 0.0 alone would not gate).
    body_src = _capture_body_src(launcher_src)
    assert _diverges_without_oracle_src(body_src, {"X": 3}), (
        "FLOOR FAILED: density=0.0 produced no gated transition, so the dumped body ran correctly "
        "without the oracle. ATTEST_MIN_GATES must guarantee >=1 gated transition."
    )


# ---- attest_density actually controls coverage (regression) ----

_DENSITY_SRC = (
    "def big(x):\n"
    "    a = x + 1\n    b = a * 2\n    c = b - 3\n    d = c + 4\n    e = d * 5\n"
    "    g = e - 6\n    h = g + 7\n"
    "    if h > 100:\n        h = h - 50\n    else:\n        h = h + 50\n"
    "    return h + a + b + c + d + e + g\n"
    "RES = big(10)\n"
)


def _attest_gate_total(src, density, seed=1, inflate=True):
    """Build `src` with attest at `density` and return the total number of gated transitions, by
    intercepting inject_attest (it appends exactly one request per gated transition)."""
    import pyobfuscator.cff.cfg as cfg
    orig = cfg.inject_attest
    total = 0

    def wrap(rendered, names, rng, requests, attest_density, *a, **k):
        nonlocal total
        before = len(requests)
        orig(rendered, names, rng, requests, attest_density, *a, **k)
        total += len(requests) - before

    cfg.inject_attest = wrap
    try:
        obf_module(src, ModuleObfOptions(
            seed=seed, pack_body=True, key_from_cff=True, integrity_selfcheck=True,
            min_blocks=1, output="text", pack_format="source",
            attest=True, attest_density=density, attest_inflate=inflate))
    finally:
        cfg.inject_attest = orig
    return total


def test_attest_density_monotonic():
    """Regression: attest_density must control the gated-transition count -- non-decreasing in
    density and genuinely moving across the range. Before the fix (per-site Bernoulli + a per-unit
    floor over too-few sites) the count was pinned for density 0.0..~0.6, so the knob was inert."""
    counts = {d: _attest_gate_total(_DENSITY_SRC, d) for d in (0.0, 0.3, 0.6, 0.9, 1.0)}
    seq = [counts[d] for d in (0.0, 0.3, 0.6, 0.9, 1.0)]
    assert seq == sorted(seq), counts            # monotonic non-decreasing
    assert counts[1.0] > counts[0.0], counts     # density genuinely moves the count
    assert counts[0.9] > counts[0.3], counts     # resolves across the mid-high range


def test_attest_inflate_resolves_density():
    """Dead-clone inflation is what gives density room to resolve on small units: with
    inflation off, the per-unit floor pins the count; with it on, the dynamic range is wider."""
    off_lo = _attest_gate_total(_DENSITY_SRC, 0.0, inflate=False)
    off_hi = _attest_gate_total(_DENSITY_SRC, 1.0, inflate=False)
    on_lo = _attest_gate_total(_DENSITY_SRC, 0.0, inflate=True)
    on_hi = _attest_gate_total(_DENSITY_SRC, 1.0, inflate=True)
    assert on_hi > off_hi, (off_hi, on_hi)                   # inflation gives density more to gate
    assert (on_hi - on_lo) > (off_hi - off_lo), (off_lo, off_hi, on_lo, on_hi)  # wider dynamic range


# ---- oracle name is not a greppable string literal ----

@pytest.mark.parametrize("seed", [1, 42, 101])
def test_attest_oracle_name_not_literal_in_launcher(seed):
    """The oracle name is reconstructed from char codes (name_to_charcode_expr), so it must
    NOT appear as a greppable string literal in the launcher source (the plaintext an analyst
    sees first). The body's setdefault uses the same char-code form (and is encrypted besides)."""
    opts = ModuleObfOptions(seed=seed, **FULL_PACKER)
    launcher_src = obf_module(_SIMPLE_SRC, opts)
    assert oracle_name(seed) not in launcher_src, (
        f"oracle name {oracle_name(seed)!r} leaked as a literal in the launcher source"
    )
