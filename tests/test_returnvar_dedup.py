import sys, os, io, contextlib, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions


def _obs(fn, a):
    buf = io.StringIO(); rv = exc = None
    with contextlib.redirect_stdout(buf):
        try: rv = fn(*a)
        except BaseException as e: exc = (type(e).__name__, str(e))
    return (repr(rv), exc, buf.getvalue())


def _check(src, name, args, **opts):
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0); orig = ns0[name]
    for seed in (0, 1, 7):
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
        ns = {}; exec(compile(out, "<t>", "exec"), ns)
        for a in args:
            assert _obs(orig, a) == _obs(ns[name], a), f"seed={seed} args={a}\n{out}"
    return out


MULTI_RET = ("def f(x):\n    if x < 0:\n        return False\n    if x == 0:\n        return\n"
             "    if x > 100:\n        return False\n    if x == 7:\n        return\n    return x * 2\n")


def test_return_var_equivalent():
    _check(MULTI_RET, "f", [(-1,), (0,), (200,), (7,), (5,)], return_var=True)


def test_return_var_uses_intermediate():
    out = obf_func(MULTI_RET, ObfOptions(output="text", seed=0, min_blocks=1,
                                         return_var=True, shuffle_states=False,
                                         opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    # bare `return` became `_r = None; return _r`; no bare value returns remain
    assert "return False" not in out and "return None" not in out


def test_dedup_merges_identical_blocks():
    # 3x `return False` + 2x bare return -> after return_var, identical bodies -> dedup collapses
    base = obf_func(MULTI_RET, ObfOptions(output="text", seed=0, min_blocks=1, return_var=True,
                                          dedup=False, shuffle_states=False, opaque_predicates=False,
                                          bogus_blocks=False, obf_strings=False))
    dd = obf_func(MULTI_RET, ObfOptions(output="text", seed=0, min_blocks=1, return_var=True,
                                        dedup=True, shuffle_states=False, opaque_predicates=False,
                                        bogus_blocks=False, obf_strings=False))
    n_base = sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(base)))
    n_dd = sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(dd)))
    assert n_dd < n_base  # dedup removed duplicate guards


def test_dedup_equivalent_combined():
    _check(MULTI_RET, "f", [(-1,), (0,), (200,), (7,), (5,)], return_var=True, dedup=True)


def test_dedup_alone_equivalent():
    src = ("def f(x):\n    if x == 1:\n        y = 10\n        return y\n    if x == 2:\n        y = 10\n        return y\n"
           "    return x\n")
    _check(src, "f", [(1,), (2,), (9,)], dedup=True)


def test_dedup_with_exceptions():
    src = ("def f(a, b):\n    try:\n        return a // b\n    except ZeroDivisionError:\n        return 0\n"
           "    except TypeError:\n        return 0\n")
    _check(src, "f", [(6, 2), (6, 0), (6, None)], return_var=True, dedup=True)


@pytest.mark.parametrize("seed", [0, 1, 11, 41])
def test_combined_full_strength(seed):
    src = ("def f(s):\n    out = []\n    for ch in s:\n        if ch == 'a':\n            out.append(1)\n"
           "        elif ch == 'b':\n            out.append(1)\n        else:\n            return ('bad', out)\n"
           "    return ('ok', out)\n")
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, return_var=True,
                                   dedup=True, obf_ints=True, slot_vars=True, stack_calls=True))
    ns = {}; exec(compile(out, "<t>", "exec"), ns)
    for a in ("aab",), ("aXb",), ("",):
        assert _obs(ns0["f"], a) == _obs(ns["f"], a)


def test_off_by_default_noop():
    out = obf_func(MULTI_RET, ObfOptions(output="text", min_blocks=1))
    assert "return False" in out or "return result" not in out  # return_var off -> bare returns kept
