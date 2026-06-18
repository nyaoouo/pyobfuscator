import sys, os, io, contextlib, ast, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _obs(fn, a):
    b = io.StringIO(); r = e = None
    with contextlib.redirect_stdout(b):
        try: r = fn(*a)
        except BaseException as x: e = (type(x).__name__, str(x))
    return (repr(r), e, b.getvalue())


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


SRCS = [
    ("def f(x):\n    t = 0\n    for i in range(x):\n        if i % 2:\n            t += i\n        else:\n            t -= 1\n    return t\n", "f", [(0,), (5,), (10,)]),
    ("def f(a, b):\n    try:\n        return a // b\n    except ZeroDivisionError:\n        return -1\n", "f", [(6, 2), (6, 0)]),
    ("def f(n):\n    s = ''\n    i = 0\n    while i < n:\n        s += str(i)\n        i += 1\n    return s\n", "f", [(0,), (4,)]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(junk_code=True),
    dict(junk_code=True, shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False),
    dict(junk_code=True, obf_ints=True, obf_strings=True, dispatch_tree=True, state_delta=True, dedup=True, return_var=True),
    dict(junk_code=True, safe_mode=False),
])
@pytest.mark.parametrize("seed", [0, 1, 9])
def test_junk_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_junk_adds_reachable_states():
    # Must have branches so the lowerer produces Goto edges (junk splices onto those).
    # A purely sequential function collapses to a single Ret-terminated block: no Goto edges.
    src = ("def f(x):\n    if x > 0:\n        a = x + 1\n    else:\n        a = x - 1\n"
           "    b = a * 2\n    c = b - 3\n    d = c % 5\n    return a + b + c + d\n")
    base = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                    shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    junk = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, junk_code=True,
                                    shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    assert n(junk) > n(base)  # more guard states than without junk


def test_off_by_default():
    src = ("def f(x):\n    a = x + 1\n    return a * 2\n")
    base = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                    shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    junk = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, junk_code=True,
                                    shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    assert n(junk) >= n(base)  # junk_code never removes states; default-off path unaffected


def test_module_level_junk_equivalent():
    src = ("RESULT = []\n"
           "def step(x):\n    return x * x\n"
           "for i in range(4):\n    RESULT.append(step(i))\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=0, min_blocks=1, junk_code=True))
    o = {}; exec(compile(src, "<o>", "exec"), o)
    t = {}; exec(compile(out, "<t>", "exec"), t)
    assert t["RESULT"] == o["RESULT"]
