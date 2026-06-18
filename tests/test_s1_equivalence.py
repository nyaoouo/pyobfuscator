import ast
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from pyobfuscator import obf_func, ObfOptions
from equivalence import assert_func_equivalent

CORPUS = [
    # (src, name, batteries)
    ("def f(a, b):\n    return a + b\n", "f", [((2, 3), {}), ((-1, 1), {})]),
    ("def f(x):\n    if x > 0:\n        return 'pos'\n    elif x < 0:\n        return 'neg'\n    return 'zero'\n",
     "f", [((5,), {}), ((-5,), {}), ((0,), {})]),
    ("def f(n):\n    t = 0\n    for i in range(n):\n        if i % 2 == 0:\n            continue\n        t += i\n    return t\n",
     "f", [((0,), {}), ((10,), {})]),
    ("def f(n):\n    i, t = 0, 0\n    while True:\n        if i >= n:\n            break\n        t += i\n        i += 1\n    return t\n",
     "f", [((0,), {}), ((6,), {})]),
    ("def f(xs):\n    for x in xs:\n        if x < 0:\n            return x\n    else:\n        return 0\n",
     "f", [(([1, 2, 3],), {}), (([1, -2, 3],), {}), (([],), {})]),
    ("def f(n):\n    out = []\n    for i in range(n):\n        for j in range(i):\n            out.append((i, j))\n    return out\n",
     "f", [((0,), {}), ((4,), {})]),
    ("def f(d, k):\n    if k in d:\n        return d[k]\n    return None\n",
     "f", [(({'a': 1}, 'a'), {}), (({'a': 1}, 'b'), {})]),
    ("def f(x):\n    y = x * 2 if x else -1\n    return y\n", "f", [((3,), {}), ((0,), {})]),
    ("def f(a):\n    total = 0\n    i = 0\n    while i < len(a):\n        total += a[i]\n        i += 1\n    return total\n",
     "f", [(([1, 2, 3, 4],), {}), (([],), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 1, 7, 42])
def test_corpus_equivalent_across_seeds(src, name, batteries, seed):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed))
        ns = {}
        exec(compile(out, "<s1>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


def test_exception_propagates_identically():
    # division by zero inside the flattened body must raise the same as original
    src = "def f(a, b):\n    c = a + b\n    return c // (a - b)\n"

    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=3))
        ns = {}
        exec(compile(out, "<s1>", "exec"), ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((4, 2), {}), ((3, 3), {})])  # 3,3 -> ZeroDivisionError both


def test_pyc_path_equivalent():
    import marshal
    src = "def f(n):\n    t = 1\n    for i in range(1, n + 1):\n        t *= i\n    return t\n"

    def factory():
        out = obf_func(src, ObfOptions(output="pyc", seed=9))
        code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((5,), {}), ((0,), {}), ((1,), {})])
