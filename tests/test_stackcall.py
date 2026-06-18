import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions


def _obs(fn, a):
    buf = io.StringIO(); rv = exc = None
    with contextlib.redirect_stdout(buf):
        try: rv = fn(*a)
        except BaseException as e: exc = (type(e).__name__, str(e))
    return (repr(rv), exc, buf.getvalue())


def _check(src, name, args, seeds=(0, 1, 7)):
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0); orig = ns0[name]
    for seed in seeds:
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, stack_calls=True))
        ns = {}; exec(compile(out, "<t>", "exec"), ns)
        for a in args:
            assert _obs(orig, a) == _obs(ns[name], a), f"seed={seed} args={a}\n{out}"
    return out


def test_nested_helper_stackcall():
    src = ("def f(n):\n    def _add(a, b):\n        return a + b\n"
           "    def _mul(a, b):\n        return a * b\n"
           "    return _add(_mul(n, 2), 3)\n")
    out = _check(src, "f", [(5,), (0,), (-2,)])
    assert "threading" in out and ".append(" in out and ".pop(" in out


def test_kwargs_in_order():
    src = ("def f(n):\n    def _g(a, b, c):\n        return a - b + c\n"
           "    return _g(n, 2, c=10)\n")
    _check(src, "f", [(5,), (100,)])


def test_recursion_via_stack():
    src = ("def f(n):\n    def _fib(k):\n        if k < 2:\n            return k\n"
           "        return _fib(k - 1) + _fib(k - 2)\n    return _fib(n)\n")
    _check(src, "f", [(0,), (1,), (8,), (10,)])


def test_eval_order_preserved():
    src = ("def f():\n    log = []\n    def _rec(x):\n        log.append(('rec', x))\n        return x\n"
           "    def _h(a, b, c):\n        return (a, b, c)\n"
           "    r = _h(_rec(1), _rec(2), _rec(3))\n    return (r, log)\n")
    _check(src, "f", [()])


def test_public_module_func_not_transformed():
    # `pub` is public module-level (no underscore) -> NOT transformed; `_priv` -> transformed.
    src = ("def _priv(a, b):\n    return a * b\n"
           "def pub(n):\n    return _priv(n, 3) + 1\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True))
    ns = {}; exec(compile(out, "<t>", "exec"), ns)
    assert ns["pub"](4) == 13
    # pub must keep its normal signature (1 positional param) for external callers:
    import inspect
    assert len(inspect.signature(ns["pub"]).parameters) == 1


def test_name_used_as_value_not_transformed():
    src = ("def f(n):\n    def _g(a):\n        return a + 1\n"
           "    h = _g\n    return h(n) + _g(n)\n")
    # _g is used as a value (h = _g) -> ineligible -> normal calls -> still correct
    _check(src, "f", [(5,)])


def test_off_by_default_is_noop():
    src = ("def f(n):\n    def _g(a, b):\n        return a + b\n    return _g(n, 1)\n")
    out = obf_func(src, ObfOptions(output="text", min_blocks=1))  # stack_calls default False
    assert "_stk" not in out
    ns = {}; exec(compile(out, "<t>", "exec"), ns)
    assert ns["f"](4) == 5


def test_stackcall_with_full_strength():
    src = ("def f(items):\n    def _score(x, w):\n        if x < 0:\n            return 0\n        return x * w\n"
           "    total = 0\n    for it in items:\n        total += _score(it, 2)\n    return total\n")
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0)
    for seed in (0, 3, 9):
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1,
                                       stack_calls=True, obf_ints=True, slot_vars=True))
        ns = {}; exec(compile(out, "<t>", "exec"), ns)
        for a in ([1, -2, 3],), ([],):
            assert _obs(ns0["f"], a) == _obs(ns["f"], a)


def test_class_methods_not_stack_routed():
    # REGRESSION: methods/properties are invoked via the descriptor protocol (obj.m(), property
    # get), never via a bare `m(...)` call. stack_calls must NOT strip their params, or the
    # descriptor call breaks ("takes 0 positional arguments but 1 was given").
    src = ("def f(x):\n"
           "    class C:\n"
           "        def __init__(self, v):\n"
           "            self.v = v\n"
           "        def scaled(self, k):\n"
           "            return self.v * k\n"
           "        @property\n"
           "        def doubled(self):\n"
           "            return self.v * 2\n"
           "    c = C(x)\n"
           "    return c.scaled(3) + c.doubled\n")
    _check(src, "f", [(5,), (0,), (-4,)])


def test_method_and_eligible_nested_func_coexist():
    # a class method `helper` and a private module-level `_helper` with different bodies: the
    # method must be left alone; the standalone may be routed. Behavior must be preserved.
    src = ("def _twice(n):\n    return n * 2\n"
           "def f(x):\n"
           "    class C:\n"
           "        def helper(self, a):\n"
           "            return a + 1\n"
           "    return C().helper(x) + _twice(x)\n")
    _check(src, "f", [(3,), (10,)])
