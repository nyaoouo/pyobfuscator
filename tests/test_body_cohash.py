"""#4 body self-cohash (PYC-only): each oracle-gated transition folds H = FNV(guard.__code__.co_code),
recomputed at runtime; protect bakes H_build into the correction so the GENUINE path cancels (H ==
H_build) and any tamper that changes the body's co_code (instrumentation / recompile / bytecode
rewrite) flips H -> wrong state -> divergence. This extends integrity to the BODY (cohash_integrity
(B) only guards the launcher).

RULE #0 (from test_attest): every WRONG-co_code run MUST be in a KILLABLE SUBPROCESS with a timeout —
a wrong-state CFF dispatcher busy-loops forever. Treat hang/crash/wrong-output ALL as "diverged = PASS".
"""
from __future__ import annotations

import base64
import marshal
import subprocess
import sys

import pytest

from pyobfuscator import obf_module, ModuleObfOptions
from pyobfuscator.options import OutputFormat
from pyobfuscator.cff.attest import cohash_build_hash, _fnv1a

_SRC = (
    "import sys\n"
    "R = []\n"
    "def f(x):\n"
    "    if x > 5:\n        return x * 3\n"
    "    elif x > 0:\n        return x + 10\n"
    "    else:\n        return 0\n"
    "for i in range(6):\n    R.append(f(i))\n"
    "TOTAL = sum(R)\n"
)
_REF = {"R": [0, 11, 12, 13, 14, 15], "TOTAL": 65}   # f(i) for i in range(6); f(5)=5+10=15

_PYC_COHASH = dict(pack_body=True, key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
                   min_blocks=1, output="pyc", attest=True, attest_density=0.6, body_cohash=True)

_SRC_DIR = __file__.rsplit("\\tests\\", 1)[0] + "\\src" if "\\tests\\" in __file__ \
    else __file__.rsplit("/tests/", 1)[0] + "/src"


def _run_pyc(pyc_bytes, keys):
    code = marshal.loads(bytes(pyc_bytes)[16:])
    ns = {"__name__": "m"}
    exec(code, ns)
    return {k: ns.get(k) for k in keys}


# ---- genuine path: PYC + body_cohash is equivalent to CPython ----

@pytest.mark.parametrize("seed", [1, 42, 101])
def test_body_cohash_genuine_equivalent(seed):
    pyc = obf_module(_SRC, ModuleObfOptions(seed=seed, **_PYC_COHASH))
    assert _run_pyc(pyc, ["R", "TOTAL"]) == _REF


@pytest.mark.parametrize("seed", [7, 99])
def test_body_cohash_genuine_state_delta(seed):
    pyc = obf_module(_SRC, ModuleObfOptions(seed=seed, state_delta=True, **_PYC_COHASH))
    assert _run_pyc(pyc, ["R", "TOTAL"]) == _REF


@pytest.mark.parametrize("seed", [3, 88])
def test_body_cohash_funcs_only_module(seed):
    """Edge: a body whose MODULE level is too trivial to wrap (dispatcher is None) but whose FUNCTION
    bodies are flattened + gated. Their cohash bindings reference the guard/hashfn defs, so wrap_module
    must emit those defs even on the dispatcher-is-None early return. min_blocks=2 keeps the 1-statement
    module unwrapped; the branching function still gets >=2 blocks -> gated. The H-binding runs at CALL
    time, so without the fix calling f raises NameError(guard)."""
    src = ("def f(x):\n"
           "    if x > 0:\n        return x * 2\n"
           "    return -x\n")
    opts = dict(_PYC_COHASH); opts["min_blocks"] = 2
    pyc = obf_module(src, ModuleObfOptions(seed=seed, **opts))
    code = marshal.loads(bytes(pyc)[16:])
    ns = {"__name__": "m"}
    exec(code, ns)
    assert ns["f"](5) == 10 and ns["f"](-3) == 3


# ---- validation (fail-loud): PYC-only + requires attest ----

def test_body_cohash_text_rejected():
    opts = dict(pack_body=True, key_from_cff=True, min_blocks=1, attest=True, body_cohash=True)
    with pytest.raises(ValueError, match="body_cohash.*requires output='pyc'"):
        obf_module(_SRC, ModuleObfOptions(seed=1, output="text", **opts))


def test_body_cohash_without_attest_rejected():
    with pytest.raises(ValueError, match="body_cohash.*requires attest"):
        obf_module(_SRC, ModuleObfOptions(seed=1, output="pyc", pack_body=True, key_from_cff=True,
                                          min_blocks=1, attest=False, body_cohash=True))


# ---- the flag has effect + is deterministic ----

def test_body_cohash_deterministic_and_changes_output():
    a = bytes(obf_module(_SRC, ModuleObfOptions(seed=5, **_PYC_COHASH)))
    b = bytes(obf_module(_SRC, ModuleObfOptions(seed=5, **_PYC_COHASH)))
    assert a == b                                    # same seed+opts -> byte-identical
    off = dict(_PYC_COHASH); off["body_cohash"] = False
    c = bytes(obf_module(_SRC, ModuleObfOptions(seed=5, **off)))
    assert a != c                                    # cohash genuinely changes the artifact


# ---- security gate: tampering the body's co_code -> divergence (even WITH the genuine oracle) ----
# All in ONE killable subprocess (RULE #0): run the launcher genuinely (captures the body code via a
# zlib.decompress hook AND the installed oracle), replace the guard's co_code with a structurally
# different code object (simulating any recompile/instrumentation), then re-exec the tampered body WITH
# the genuine oracle pre-installed. Genuine H_build no longer matches H_runtime -> the gated transitions
# land on wrong states. Distinct markers separate a real divergence from a test-setup miss.

_TAMPER_PROBE = r'''
import sys, base64, marshal, json, zlib
sys.path.insert(0, {src_dir!r})
from pyobfuscator.cff.attest import cohash_build_hash, oracle_name, _fnv1a

SEED = {seed}
pyc = base64.b64decode({pyc_b64!r})

# 1. run the launcher genuinely; hook zlib.decompress to grab the (marshalled) body bytes.
_real = zlib.decompress
cap = []
def _w(*a, **k):
    out = _real(*a, **k); cap.append(out); return out
zlib.decompress = _w
lns = {{"__name__": "m"}}
exec(marshal.loads(pyc[16:]), lns)
zlib.decompress = _real

oname = oracle_name(SEED)
oracle = lns.get(oname)
if oracle is None or not cap:
    print("__SETUP__no oracle/body captured"); sys.exit(0)
body = marshal.loads(cap[-1])

# 2. find the guard code object by its FNV (== build hash) and swap in a different-co_code variant.
th = cohash_build_hash(SEED)
consts = list(body.co_consts)
gi = next((i for i, c in enumerate(consts)
           if hasattr(c, "co_code") and _fnv1a(c.co_code) == th), None)
if gi is None:
    print("__SETUP__guard const not found"); sys.exit(0)
MASK = (1 << 64) - 1
tamp = compile("def _g(v):\n e = v + 1\n return ((v * 3) ^ (v >> 5)) & " + str(MASK) + "\n", "<t>", "exec")
tg = next(c for c in tamp.co_consts if hasattr(c, "co_code"))
assert _fnv1a(tg.co_code) != th, "tamper produced identical co_code"
consts[gi] = tg
body2 = body.replace(co_consts=tuple(consts))

# 3. re-exec the tampered body WITH the genuine oracle pre-installed (setdefault finds it).
ns2 = {{"__name__": "m", oname: oracle}}
exec(body2, ns2)
print("__DONE__" + json.dumps({{"R": ns2.get("R"), "TOTAL": ns2.get("TOTAL")}}))
'''


@pytest.mark.parametrize("seed", [1, 42])
def test_body_cohash_tamper_diverges(seed):
    pyc = obf_module(_SRC, ModuleObfOptions(seed=seed, **_PYC_COHASH))
    probe = _TAMPER_PROBE.format(src_dir=_SRC_DIR, seed=seed,
                                 pyc_b64=base64.b64encode(bytes(pyc)).decode())
    try:
        r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return  # hang (wrong state -> dispatcher never exits) => diverged => PASS
    out = r.stdout
    assert "__SETUP__" not in out, ("test setup failed (not a security result): " + out + r.stderr[-300:])
    if r.returncode != 0 or "__DONE__" not in out:
        return  # crash => diverged => PASS
    import json
    got = json.loads(out.split("__DONE__", 1)[1].strip().splitlines()[-1])
    assert got != _REF, ("BODY-COHASH FAILED: tampered body (changed guard co_code) reproduced the "
                         "real result WITH the genuine oracle -> the self-hash did not gate.")
