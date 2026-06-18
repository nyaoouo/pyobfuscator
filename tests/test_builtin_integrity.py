"""Configurable + absolute + randomized builtin-integrity.

The generic attack that broke the CTF demo replaced `builtins.compile` / `pow` with a Python
function to dump the decrypted body / decoded strings. With those builtins folded into the launcher
integrity term, such a replacement (a Python def: wrong type AND has `__code__`) lowers the integrity
value -> wrong key selector -> branchless decoy / divergence. The ABSOLUTE "is X a Python-defined
function?" spot-check additionally catches UNIFORM replacement of every checked builtin (the blind
spot of the relative-only `type(X) is type(''.join)` check).

RULE #0: every tamper run is a KILLABLE subprocess (a wrong-key body can busy-loop forever).
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0] + "/src" if "/tests/" in __file__
                else __file__.rsplit("\\tests\\", 1)[0] + "\\src")

from pyobfuscator import obf_module, ModuleObfOptions

# Real body => OK == 3; any tamper must NOT reproduce 3 (decoy / crash / hang).
_SRC = "OK = 0\nfor _i in range(3):\n    OK += 1\n"


def _build(**over):
    opts = dict(seed=11, pack_body=True, key_from_cff=True, integrity_selfcheck=True,
                pack_decoy=True, min_blocks=1, output="text", pack_format="source")
    opts.update(over)
    return obf_module(_SRC, ModuleObfOptions(**opts))


def _run(launcher_src, replace_names, timeout=8.0):
    """Run the launcher in a KILLABLE subprocess after replacing the named builtins with
    Python-typed *delegating* wrappers (same behaviour, but `type` is `function` and they have
    `__code__`, exactly like a dump hook). The launcher is compiled with the genuine `compile`
    BEFORE tampering, so the only effect is the runtime identity mismatch the integrity check sees.
    Returns the body's `OK` value, or 'HANG'/'CRASH'."""
    probe = (
        "import sys, json, base64, builtins\n"
        "code = compile(base64.b64decode(%r).decode('utf-8'), '<launcher>', 'exec')\n"
        "for nm in %r:\n"
        "    _o = getattr(builtins, nm)\n"
        "    setattr(builtins, nm, (lambda f: (lambda *a, **k: f(*a, **k)))(_o))\n"
        "ns = {'__name__': 'm'}\n"
        "exec(code, ns)\n"
        "sys.stdout.write('__R__' + json.dumps(ns.get('OK')))\n"
        % (base64.b64encode(launcher_src.encode()).decode(), list(replace_names))
    )
    pf = tempfile.NamedTemporaryFile("w", suffix="_bi.py", delete=False, encoding="utf-8")
    pf.write(probe); pf.close()
    try:
        r = subprocess.run([sys.executable, pf.name], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "HANG"
    finally:
        os.unlink(pf.name)
    if r.returncode != 0 or "__R__" not in r.stdout:
        return "CRASH"
    return json.loads(r.stdout.split("__R__", 1)[1].strip().splitlines()[-1])


def test_bi_clean_runs_real():
    """No tampering -> genuine body runs."""
    assert _run(_build(), []) == 3


@pytest.mark.parametrize("name", ["compile", "exec", "pow"])
def test_bi_detects_single_builtin_hook(name):
    """Replacing a single checked builtin with a Python wrapper (the dump-hook pattern) is detected
    -> not the real result (decoy / crash / hang)."""
    out = _run(_build(), [name])
    assert out != 3, f"builtin-integrity did NOT detect a {name} hook (got {out!r})"


def test_bi_detects_uniform_replacement():
    """Replacing EVERY checked builtin at once is still detected."""
    out = _run(_build(), ["compile", "exec", "pow", "sum", "open", "len"])
    assert out != 3, f"uniform builtin replacement evaded detection (got {out!r})"


def test_bi_configurable_set_is_honoured():
    """A builtin NOT in `builtin_checks` is not folded into integrity, so hooking it alone does not
    flip to the decoy (clean result), while a builtin that IS in the set does -> proves the set is
    actually consulted (configurable)."""
    launcher = _build(builtin_checks=("pow",), builtin_spot_count=1)
    assert _run(launcher, ["len"]) == 3, "len was checked despite not being in builtin_checks"
    assert _run(launcher, ["pow"]) != 3, "pow (the configured check) was not enforced"


def test_bi_spot_check_varies_per_build():
    """The random absolute spot-check subset is build-seed-derived and unpredictable: it is
    deterministic per seed but varies across seeds."""
    from pyobfuscator.protect.core import _choose_bi
    # deterministic per seed
    assert _choose_bi(ModuleObfOptions(seed=5))[1] == _choose_bi(ModuleObfOptions(seed=5))[1]
    # varies across builds
    subsets = {tuple(_choose_bi(ModuleObfOptions(seed=s))[1]) for s in range(8)}
    assert len(subsets) > 1, subsets
