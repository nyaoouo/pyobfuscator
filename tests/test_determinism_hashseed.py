"""Build determinism across PYTHONHASHSEED.

Regression guard for the attest oracle-var bug: `flatten.py` derived the oracle var name from the
builtin `hash()` of a string, which is process-randomized, so the same (seed, flags, source) produced
different output across runs — the var appears in every gated goto, so the whole body source, the
packed blob, and the launcher's offsets all varied. The obfuscator must be byte-deterministic given a
fixed seed regardless of PYTHONHASHSEED. RULE #0: builds run in killable subprocesses with a timeout.
"""
import os
import subprocess
import sys

import pyobfuscator

_SRCROOT = os.path.dirname(os.path.dirname(os.path.abspath(pyobfuscator.__file__)))

_BUILD = '''
import sys
sys.path.insert(0, %r)
from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, OutputFormat
SRC = ("def f(x):\\n"
       "    y = 0\\n"
       "    for i in range(x):\\n"
       "        if i %% 2 == 0:\\n"
       "            y += i\\n"
       "        else:\\n"
       "            y -= i\\n"
       "    return y\\n")
opts = ModuleObfOptions(output=OutputFormat.TEXT, seed=3, pack_body=True, key_from_cff=True,
                        attest=True, attest_density=0.5, dispatch_tree=True, bogus_blocks=True,
                        junk_code=True, shuffle_states=True, opaque_predicates=True,
                        name_vault=True, const_archive=True)
sys.stdout.write(obf_module(SRC, opts))
''' % _SRCROOT


def _build(hashseed: int) -> str:
    env = dict(os.environ, PYTHONHASHSEED=str(hashseed))
    r = subprocess.run([sys.executable, "-c", _BUILD], capture_output=True, text=True,
                       timeout=180, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_packed_attest_build_deterministic_across_hashseed():
    a = _build(1)
    b = _build(2)
    c = _build(13)
    assert a, "build produced output"
    assert a == b == c, "packed+attest build must be byte-identical across PYTHONHASHSEED"
