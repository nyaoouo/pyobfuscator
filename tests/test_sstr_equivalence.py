import sys, os, io, contextlib, marshal
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions
from equivalence import assert_func_equivalent

FUNCS = [
    ("def f(n):\n    total = 0\n    for i in range(n):\n        if i % 2:\n            continue\n        total += i\n    return total\n",
     "f", [((6,), {}), ((0,), {})]),
    ("def f(a, b):\n    try:\n        return a // b\n    except ZeroDivisionError:\n        return 'inf'\n    finally:\n        pass\n",
     "f", [((6, 2), {}), ((6, 0), {})]),
    ("def f(x):\n    out = []\n    i = 0\n    while i < x:\n        i += 1\n        if i == 3:\n            break\n        out.append(i)\n    return out\n",
     "f", [((5,), {}), ((1,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", FUNCS)
@pytest.mark.parametrize("seed", [0, 1, 13, 41])
def test_func_equivalent_with_shuffle(src, name, batteries, seed):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        ns = {}
        exec(compile(out, "<s>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


CLS = (
    "class Stack:\n"
    "    def __init__(self):\n        self.items = []\n"
    "    def push(self, x):\n        self.items.append(x)\n        return len(self.items)\n"
    "    def pop_or(self, default):\n        if not self.items:\n            return default\n        return self.items.pop()\n"
)


@pytest.mark.parametrize("seed", [0, 3, 19])
def test_class_equivalent_with_shuffle(seed):
    ns_o = {}
    exec(compile(CLS, "<o>", "exec"), ns_o)
    out = obf_func(CLS, ObfOptions(output="text", seed=seed, min_blocks=1))
    ns_t = {}
    exec(compile(out, "<t>", "exec"), ns_t)
    def probe(ns):
        s = ns["Stack"]()
        return (s.push(1), s.push(2), s.pop_or("e"), s.pop_or("e"), s.pop_or("empty"))
    assert probe(ns_o) == probe(ns_t)


MOD = (
    "BASE = 10\n"
    "acc = []\n"
    "for i in range(3):\n    acc.append(BASE + i)\n"
    "def total():\n    return sum(acc)\n"
)


@pytest.mark.parametrize("seed", [0, 7, 23])
def test_module_equivalent_with_shuffle(seed):
    ns_o = {"__name__": "m"}
    exec(compile(MOD, "<o>", "exec"), ns_o)
    out = obf_module(MOD, ModuleObfOptions(output="text", seed=seed, min_blocks=1))
    ns_t = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns_t)
    assert ns_o["acc"] == ns_t["acc"] and ns_o["total"]() == ns_t["total"]()


def test_pyc_with_shuffle():
    src = "def f(x):\n    if x > 0:\n        return x * 2\n    return -x\n"
    def factory():
        out = obf_func(src, ObfOptions(output="pyc", seed=4, min_blocks=1))
        code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((5,), {}), ((-3,), {})])
