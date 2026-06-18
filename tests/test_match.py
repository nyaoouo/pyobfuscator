import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


def _obs(fn, a):
    buf = io.StringIO(); rv = exc = None
    with contextlib.redirect_stdout(buf):
        try: rv = fn(*a)
        except BaseException as e: exc = (type(e).__name__, str(e))
    return (repr(rv), exc, buf.getvalue())


def _check(src, name, args, seeds=(0, 1, 7)):
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0); orig = ns0[name]
    for seed in seeds:
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        assert "match " not in out  # desugared away
        ns = {}; exec(compile(out, "<t>", "exec"), ns)
        for a in args:
            assert _obs(orig, a) == _obs(ns[name], a), f"seed={seed} args={a}"


def test_value_and_wildcard():
    src = ("def f(x):\n    match x:\n        case 1:\n            return 'one'\n"
           "        case 2:\n            return 'two'\n        case _:\n            return 'other'\n")
    _check(src, "f", [(1,), (2,), (3,), (0,)])


def test_singleton():
    src = ("def f(x):\n    match x:\n        case None:\n            return 'none'\n"
           "        case True:\n            return 'T'\n        case False:\n            return 'F'\n"
           "        case _:\n            return 'val'\n")
    _check(src, "f", [(None,), (True,), (False,), (5,), (0,)])


def test_capture_and_guard():
    src = ("def f(x):\n    match x:\n        case n if n < 0:\n            return ('neg', n)\n"
           "        case 0:\n            return 'zero'\n        case n:\n            return ('pos', n)\n")
    _check(src, "f", [(-5,), (0,), (7,)])


def test_or_pattern():
    src = ("def f(x):\n    match x:\n        case 1 | 2 | 3:\n            return 'low'\n"
           "        case 4 | 5:\n            return 'mid'\n        case _:\n            return 'high'\n")
    _check(src, "f", [(1,), (3,), (5,), (9,)])


def test_as_pattern_with_guard():
    src = ("def f(x):\n    match x:\n        case 42 as v:\n            return ('found', v)\n"
           "        case v if v > 100:\n            return ('big', v)\n        case _:\n            return 'meh'\n")
    _check(src, "f", [(42,), (200,), (50,)])


def test_string_subject():
    src = ("def f(s):\n    match s:\n        case 'go':\n            return 1\n"
           "        case 'stop' | 'halt':\n            return 0\n        case other:\n            return ('?', other)\n")
    _check(src, "f", [("go",), ("stop",), ("halt",), ("x",)])


def test_match_in_loop_with_flatten():
    src = ("def f(items):\n    out = []\n    for it in items:\n        match it:\n"
           "            case 0:\n                continue\n            case n if n > 10:\n                break\n"
           "            case n:\n                out.append(n)\n    return out\n")
    _check(src, "f", [([1, 0, 2, 11, 3],), ([],)])


@pytest.mark.parametrize("bad", [
    "def f(x):\n    match x:\n        case [a, b]:\n            return a + b\n",
    "def f(x):\n    match x:\n        case {'k': v}:\n            return v\n",
    "def f(x):\n    match x:\n        case complex(real=r):\n            return r\n",
])
def test_structural_patterns_rejected(bad):
    with pytest.raises(UnsupportedConstructError):
        obf_func(bad, ObfOptions(min_blocks=1))
