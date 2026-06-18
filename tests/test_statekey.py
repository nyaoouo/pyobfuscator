import sys, os, io, contextlib, ast, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


def _obs(fn, a):
    b = io.StringIO(); r = e = None
    with contextlib.redirect_stdout(b):
        try: r = fn(*a)
        except BaseException as x: e = (type(x).__name__, str(x))
    return (repr(r), e, b.getvalue())


SRCS = [
    ("def f(x):\n    a = x * 1000 + 27\n    b = a - 54321\n    return a + b * 7\n", "f", [(3,), (-5,), (0,)]),
    # constant inside an EAGER comprehension (state == K) -> keyed, still correct
    ("def f(n):\n    return [i * 100 + 7 for i in range(n)]\n", "f", [(4,), (0,)]),
    # constant inside a LAMBDA (deferred) -> must NOT be state-keyed (would be wrong when called later)
    ("def f(x):\n    g = lambda: x + 999999\n    y = x * 2222\n    return g() + y\n", "f", [(5,), (-3,)]),
    # constant inside a GENERATOR (lazy) consumed later
    ("def f(n):\n    gen = (i + 888 for i in range(n))\n    total = 0 + 0\n    for v in gen:\n        total += v\n    return total\n", "f", [(5,), (0,)]),
    # nested function with its own constants (keyed by its own state)
    ("def f(x):\n    def inner(k):\n        return k * 1234 + 99\n    return inner(x) + inner(x + 1)\n", "f", [(2,)]),
    # exception path + constants
    ("def f(a, b):\n    try:\n        return a * 31337 // b\n    except ZeroDivisionError:\n        return -424242\n", "f", [(6, 2), (6, 0)]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(obf_ints=True),
    dict(obf_ints=True, shuffle_states=True, dispatch_tree=True, state_delta=True),
    dict(obf_ints=True, dispatch_tree=True, state_delta=True, dedup=True, junk_code=True,
         bogus_blocks=True, opaque_predicates=True, slot_vars=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_statekey_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_literal_int_not_present_and_no_separate_key_var():
    out = obf_func("def f():\n    return 31337\n",
                   ObfOptions(output="text", seed=1, min_blocks=1, obf_ints=True))
    code = compile(out, "<t>", "exec")

    def consts(c, acc):
        for k in c.co_consts:
            if isinstance(k, int):
                acc.add(k)
            if hasattr(k, "co_consts"):
                consts(k, acc)
        return acc

    assert 31337 not in consts(code, set())          # not folded / not present verbatim
    assert "_pyobf_ik" not in out and "_ik" not in out  # no separate key var (closure-free)
    assert _ns(out, "f")() == 31337


def test_module_level_constants_keyed():
    src = "VALUE = 7 * 11111\ndef get():\n    return VALUE + 222\n"
    out = obf_module(src, ModuleObfOptions(output="text", seed=0, min_blocks=1, obf_ints=True))
    o = {}; exec(compile(src, "<o>", "exec"), o)
    t = {}; exec(compile(out, "<t>", "exec"), t)
    assert t["get"]() == o["get"]() and t["VALUE"] == o["VALUE"]
