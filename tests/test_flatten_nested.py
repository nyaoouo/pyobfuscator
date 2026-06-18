import ast, sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


def _mk(src, name, seed=0):
    nso = {}; exec(compile(src, "<o>", "exec"), nso)
    out = obf_func(src, ObfOptions(output="text", seed=seed))
    nsf = {}; exec(compile(out, "<f>", "exec"), nsf)
    return nso[name], nsf[name]


def test_returned_closure():
    src = ("def make_adder(n):\n"
           "    def adder(x):\n"
           "        return x + n\n"
           "    return adder\n")
    o, f = _mk(src, "make_adder")
    assert o(5)(10) == f(5)(10) == 15


def test_counter_via_mutable_box():
    src = ("def make_counter():\n"
           "    box = [0]\n"
           "    def inc():\n"
           "        box[0] += 1\n"
           "        return box[0]\n"
           "    return inc\n")
    o, f = _mk(src, "make_counter")
    oc, fc = o(), f()
    assert [oc(), oc(), oc()] == [fc(), fc(), fc()] == [1, 2, 3]


def test_deeply_nested():
    src = ("def a(x):\n"
           "    def b(y):\n"
           "        def c(z):\n"
           "            return x + y + z\n"
           "        return c\n"
           "    return b\n")
    o, f = _mk(src, "a")
    assert o(1)(2)(3) == f(1)(2)(3) == 6


def test_nested_used_in_loop():
    src = ("def f(xs, k):\n"
           "    def scaled(v):\n"
           "        return v * k\n"
           "    out = []\n"
           "    for x in xs:\n"
           "        out.append(scaled(x))\n"
           "    return out\n")
    o, f = _mk(src, "f")
    assert o([1, 2, 3], 10) == f([1, 2, 3], 10) == [10, 20, 30]


@pytest.mark.parametrize("bad,needle", [
    ("def f():\n    n = 0\n    def g():\n        nonlocal n\n        n += 1\n    return g\n", "Nonlocal"),
    ("def f():\n    def g():\n        global G\n        G = 1\n    return g\n", "Global"),
    ("def f():\n    async def g():\n        return 1\n    return g\n", "AsyncFunctionDef"),
])
def test_still_rejects(bad, needle):
    with pytest.raises(UnsupportedConstructError) as ei:
        obf_func(bad)
    assert any(d.node_type == needle for d in ei.value.diagnostics)
