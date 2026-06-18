import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions

SRC = "def f(x):\n    if x:\n        y = x + 1\n        return y\n    return 0\n"


def _run(out):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return ns["f"]


def _opts(**kw):
    base = dict(output="text", min_blocks=1, obf_strings=False,
                shuffle_states=False, opaque_predicates=False, bogus_blocks=False)
    base.update(kw)
    return ObfOptions(**base)


def _count(out, nodetype):
    return sum(isinstance(n, nodetype) for n in ast.walk(ast.parse(out)))


def test_all_strength_off_is_plain_and_correct():
    out = obf_func(SRC, _opts())
    assert "== 0" in out  # sequential ids, no opaque/bogus
    f = _run(out)
    assert f(3) == 4 and f(0) == 0


def test_opaque_adds_ternaries_and_preserves():
    plain = obf_func(SRC, _opts())
    opq = obf_func(SRC, _opts(opaque_predicates=True))
    assert _count(opq, ast.IfExp) > _count(plain, ast.IfExp)
    f = _run(opq)
    assert f(3) == 4 and f(0) == 0


def test_bogus_adds_guards_and_preserves():
    plain = obf_func(SRC, _opts())
    bog = obf_func(SRC, _opts(bogus_blocks=True))
    assert _count(bog, ast.If) > _count(plain, ast.If)
    f = _run(bog)
    assert f(3) == 4 and f(0) == 0


def test_flags_independent_and_default_on():
    # default ObfOptions has opaque + bogus + shuffle all on
    out = obf_func(SRC, ObfOptions(output="text", min_blocks=1))
    f = _run(out)
    assert f(3) == 4 and f(0) == 0


@pytest.mark.parametrize("seed", [0, 1, 7, 23])
def test_full_strength_exception_equivalence(seed):
    src = ("def f(a, b):\n    try:\n        return a // b\n"
           "    except ZeroDivisionError:\n        return -1\n    finally:\n        pass\n")
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))  # all strength on
    f = _run(out)
    assert f(6, 2) == 3 and f(6, 0) == -1


def test_bogus_states_are_unreachable():
    # run many seeds; if a bogus block were reachable, junk/var errors or wrong results appear
    src = ("def f(n):\n    total = 0\n    for i in range(n):\n        if i % 2:\n"
           "            total += i\n        else:\n            total -= 1\n    return total\n")
    for seed in range(8):
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        ns = {}
        exec(compile(out, "<t>", "exec"), ns)
        for n in (0, 1, 5, 10):
            expected = sum(i if i % 2 else -1 for i in range(n))
            assert ns["f"](n) == expected
