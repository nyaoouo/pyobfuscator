import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from equivalence import assert_func_equivalent

CORPUS = [
    ("def f(name):\n    greeting = 'Hello, '\n    return greeting + name + '!'\n",
     "f", [(("World",), {}), (("",), {})]),
    ("def f(items):\n    out = []\n    for it in items:\n        out.append('item:' + str(it))\n    return out\n",
     "f", [(([1, 2, 3],), {}), (([],), {})]),
    ("def f(x):\n    table = {'a': 1, 'b': 2, 'c': 3}\n    if x in table:\n        return table[x]\n    return -1\n",
     "f", [(("b",), {}), (("z",), {})]),
    ("def f(x):\n    try:\n        return {'ok': True, 'msg': 'fine'}[x]\n    except KeyError:\n        return 'missing:' + x\n",
     "f", [(("ok",), {}), (("nope",), {})]),
    ("def f(s):\n    return 'éèê' + s + '\U0001f600'\n",
     "f", [(("x",), {})]),
    ("def f(n):\n    total = 0\n    for i in range(n):\n        total += i * 100 + 7\n    return total\n",
     "f", [((5,), {}), ((0,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 1, 13, 41])
@pytest.mark.parametrize("obf_ints", [False, True])
def test_data_corpus_equivalent(src, name, batteries, seed, obf_ints):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, obf_ints=obf_ints))
        ns = {}
        exec(compile(out, "<s3>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


def test_pyc_path_data_obf():
    import marshal
    src = "def f(name):\n    return 'id=' + name + '#' + str(len(name))\n"
    def factory():
        out = obf_func(src, ObfOptions(output="pyc", seed=3, min_blocks=1, obf_ints=True))
        code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [(("abc",), {}), (("",), {})])
