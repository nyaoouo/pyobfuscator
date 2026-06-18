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
    # nested helper called several ways
    ("def f(n):\n    def _g(a, b):\n        return a * b + 1\n    return _g(n, 2) + _g(n, n)\n", "f", [(5,), (0,)]),
    # RECURSIVE nested function (key must not be clobbered)
    ("def f(n):\n    def _fac(k):\n        if k < 2:\n            return 1\n        return k * _fac(k - 1)\n    return _fac(n)\n", "f", [(0,), (6,)]),
    # MUTUAL recursion
    ("def f(n):\n    def _ev(k):\n        return True if k == 0 else _od(k - 1)\n    def _od(k):\n        return False if k == 0 else _ev(k - 1)\n    return _ev(n)\n", "f", [(0,), (7,), (10,)]),
    # RE-ENTRANT: outer calls inner which calls outer (closure freshness)
    ("def f(n, d=0):\n    def _h(x):\n        if x <= 0:\n            return d\n        return f(x - 1, d + 1) + _h(x - 1)\n    return _h(n)\n", "f", [(0,), (3,)]),
    # function passed as a VALUE (not just called)
    ("def f(xs):\n    def _sq(x):\n        return x * x\n    return list(map(_sq, xs)) + [_sq(3)]\n", "f", [([1, 2, 3],), ([],)]),
    # private module-level functions (obf_module)
    ("def _a(x):\n    return x + 1\n\ndef _b(x):\n    return _a(x) * 2\n\ndef pub(x):\n    return _b(x) + _a(x)\n", "pub", [(5,)]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(dict_indirect=True),
    dict(dict_indirect=True, obf_ints=True),  # keys get state-encrypted
    dict(dict_indirect=True, obf_ints=True, dispatch_tree=True, state_delta=True, dedup=True,
         stack_calls=True, hide_external_args=True, slot_vars=True, junk_code=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_dictindirect_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_internal_call_goes_through_dict():
    src = "def f(n):\n    def _g(a):\n        return a + 1\n    return _g(n)\n"
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, dict_indirect=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    # the call `_g(n)` no longer appears as a bare-name call; it's a subscript call
    assert any(isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load)
               for n in ast.walk(ast.parse(out)))
    assert _ns(out, "f")(5) == 6


def test_off_by_default():
    src = "def f(n):\n    def _g(a):\n        return a + 1\n    return _g(n)\n"
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert _ns(out, "f")(5) == 6


def test_module_private_funcs_indirected_public_preserved():
    src = ("def _helper(x):\n    return x * 3\n\ndef api(x):\n    return _helper(x) + 1\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=0, min_blocks=1, dict_indirect=True))
    assert "def api" in out  # public name preserved
    o = {}; exec(compile(src, "<o>", "exec"), o)
    t = {}; exec(compile(out, "<t>", "exec"), t)
    assert t["api"](7) == o["api"](7)
