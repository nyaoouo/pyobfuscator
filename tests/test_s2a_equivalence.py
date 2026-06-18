import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from equivalence import assert_func_equivalent

CORPUS = [
    ("def f(a, b):\n    try:\n        return a // b\n    except ZeroDivisionError:\n        return -1\n",
     "f", [((6, 2), {}), ((6, 0), {})]),
    ("def f(x):\n    try:\n        return int(x) + 1\n    except (ValueError, TypeError) as e:\n        return 'err:' + type(e).__name__\n",
     "f", [(("4",), {}), (("z",), {}), ((None,), {})]),
    ("def f(seq):\n    out = []\n    for x in seq:\n        try:\n            out.append(100 // x)\n        except ZeroDivisionError:\n            out.append(-1)\n            continue\n    return out\n",
     "f", [(([1, 0, 2, 0, 5],), {}), (([],), {})]),
    ("def f(d, k):\n    try:\n        return d[k]\n    except KeyError:\n        try:\n            return d['default']\n        except KeyError:\n            return None\n",
     "f", [(({'a': 1}, 'a'), {}), (({'a': 1}, 'b'), {}), (({'default': 9}, 'z'), {})]),
    ("def f(x):\n    try:\n        if x < 0:\n            raise ValueError('neg')\n        return x\n    except ValueError:\n        return 0\n",
     "f", [((5,), {}), ((-5,), {})]),
    ("def f(x):\n    try:\n        raise RuntimeError('boom')\n    except RuntimeError:\n        if x:\n            raise\n        return 'ok'\n",
     "f", [((0,), {}), ((1,), {})]),
    ("def f(x):\n    try:\n        y = 10 // x\n    except ZeroDivisionError:\n        return 'zero'\n    else:\n        return y\n",
     "f", [((2,), {}), ((0,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 1, 11, 41])
def test_exception_corpus_equivalent(src, name, batteries, seed):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed))
        ns = {}
        exec(compile(out, "<s2a>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


def test_pyc_path_exception_equivalent():
    import marshal
    src = ("def f(a, b):\n    try:\n        return a // b\n"
           "    except ZeroDivisionError:\n        return 'inf'\n")
    def factory():
        out = obf_func(src, ObfOptions(output="pyc", seed=3))
        code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((6, 3), {}), ((6, 0), {})])
