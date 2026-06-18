import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from equivalence import assert_func_equivalent

CORPUS = [
    ("def f():\n    try:\n        print('t')\n    finally:\n        print('f')\n    return 1\n",
     "f", [((), {})]),
    ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n    finally:\n        print('f')\n",
     "f", [((2,), {}), ((0,), {})]),
    ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n"
     "    except ZeroDivisionError:\n        print('h')\n        return -1\n    finally:\n        print('f')\n",
     "f", [((2,), {}), ((0,), {})]),
    ("def f(x):\n    try:\n        y = 10 // x\n    except ZeroDivisionError:\n        return 'z'\n"
     "    else:\n        return y\n    finally:\n        print('f')\n",
     "f", [((5,), {}), ((0,), {})]),
    ("def f():\n    try:\n        return 'a'\n    finally:\n        return 'b'\n",
     "f", [((), {})]),
    ("def f():\n    try:\n        return 'a'\n    finally:\n        raise ValueError('boom')\n",
     "f", [((), {})]),
    ("def f(x):\n    try:\n        try:\n            print('it')\n            return 10 // x\n"
     "        finally:\n            print('if')\n    finally:\n        print('of')\n",
     "f", [((2,), {}), ((0,), {})]),
    ("def f(n):\n    out = []\n    try:\n        for i in range(n):\n            if i == 2:\n"
     "                break\n            out.append(i)\n    finally:\n        out.append('f')\n    return out\n",
     "f", [((5,), {}), ((1,), {})]),
    ("def f(x):\n    r = 0\n    try:\n        r = 10 // x\n    except ZeroDivisionError:\n        r = -1\n"
     "    finally:\n        print('f')\n    if r < 0:\n        return 'neg'\n    return r\n",
     "f", [((5,), {}), ((0,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 1, 11, 41])
def test_finally_corpus_equivalent(src, name, batteries, seed):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        ns = {}
        exec(compile(out, "<s2b>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


def test_pyc_path_finally_equivalent():
    import marshal
    src = ("def f(x):\n    try:\n        return 10 // x\n    finally:\n        print('f')\n")
    def factory():
        out = obf_func(src, ObfOptions(output="pyc", seed=3, min_blocks=1))
        code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((6,), {}), ((0,), {})])
