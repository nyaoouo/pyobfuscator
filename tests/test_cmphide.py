"""A — hide_compares: `expr == CONST` -> `_h(expr) == <baked>` (splitmix64∘zigzag). Equivalence
preserved; CONST not plaintext; PORTABLE across Python versions (pure int math) — verified by building
on the test Python and running on every installed `py -3.x` (TEXT cross-version compatibility)."""
import ast
import shutil
import subprocess
import textwrap

import pytest

from pyobfuscator import obf_func, obf_module
from pyobfuscator.options import ObfOptions, ModuleObfOptions, OutputFormat
from pyobfuscator.cff.passes.cmphide import _mix_zz


def test_mix_zz_injective_over_realistic_range():
    inputs = set(range(-2000, 2000)) | {2 ** 31, -2 ** 31, 2 ** 40, 27588, 2 ** 62, -(2 ** 62)}
    seen = {}
    for n in sorted(inputs):
        h = _mix_zz(n)
        assert h not in seen, ("collision", n, seen.get(h))
        seen[h] = n
    assert len(seen) == len(inputs)


def _exec(code):
    ns = {}
    exec(compile(ast.parse(code), "<t>", "exec"), ns)
    return ns


def test_equivalence_eq_and_neq():
    src = textwrap.dedent('''
        def f(x):
            if x == 308:
                return "a"
            if x != 5:
                return "b"
            return "c"
    ''')
    out = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=2, min_blocks=1, hide_compares=True))
    g, ref = _exec(out)["f"], _exec(src)["f"]
    for x in (308, 5, 0, -7, 999, 27588):
        assert g(x) == ref(x), x


def test_const_left_and_chained_and_sideeffect():
    src = textwrap.dedent('''
        log = []
        def bump():
            log.append(1)
            return 7
        def f():
            return (308 == 308, 1 < 2 < 3, bump() == 7)
    ''')
    out = obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=2, min_blocks=1,
                                           hide_compares=True))
    ns = _exec(out)
    assert ns["f"]() == (True, True, True)
    assert ns["log"] == [1]   # bump() evaluated exactly once (no double-eval from the wrap)


def test_const_not_plaintext():
    src = "def f(x):\n    return x == 31337\n"
    out = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=1, min_blocks=1,
                                   hide_compares=True, obf_ints=False, obf_strings=False))
    assert "31337" not in out


def test_off_is_noop_vs_on_changes():
    src = "def f(x):\n    return x == 4242\n"
    base = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=1, min_blocks=1, obf_ints=False))
    on = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=1, min_blocks=1, obf_ints=False,
                                  hide_compares=True))
    assert "4242" in base and "4242" not in on


# ---- cross-version portability (TEXT): build here, run on every installed py -3.x ----

def _installed_pys():
    if not shutil.which("py"):
        return []
    try:
        out = subprocess.run(["py", "--list"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return []
    vers = []
    for tok in out.replace("-V:", " ").split():
        if tok[:1].isdigit() and "." in tok:
            v = tok.split("[")[0].split("-")[0]
            if v.count(".") == 1:
                vers.append(v)
    return sorted(set(vers))


def test_cmphide_text_cross_version(tmp_path):
    pys = _installed_pys()
    if len(pys) < 2:
        pytest.skip("need >=2 `py -3.x` versions for a cross-version check; found %r" % pys)
    src = ("import sys\n"
           "def f(x):\n    return 'OK' if x == 308 else 'NO'\n"
           "print(f(int(sys.argv[1])))\n")
    out = obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, min_blocks=1,
                                           hide_compares=True))
    p = tmp_path / "o.py"
    p.write_text(out, encoding="utf-8")
    for v in pys:
        ok = subprocess.run(["py", "-" + v, str(p), "308"], capture_output=True, text=True, timeout=60)
        assert ok.returncode == 0 and ok.stdout.strip() == "OK", (v, ok.stdout, ok.stderr)
        no = subprocess.run(["py", "-" + v, str(p), "999"], capture_output=True, text=True, timeout=60)
        assert no.stdout.strip() == "NO", (v, no.stdout, no.stderr)
