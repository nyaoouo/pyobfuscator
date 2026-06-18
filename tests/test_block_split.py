import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions

# entry block has 6 straight-line assignments before the branch
SRC = ("def f(x):\n"
       "    a = x + 1\n    b = a * 2\n    c = b - 3\n    d = c + 4\n    e = d * 5\n    g = e - 6\n"
       "    if g > 0:\n        return g\n    return -g\n")


def _run(out):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return ns["f"]


def _opts(**kw):
    base = dict(output="text", seed=0, min_blocks=1, obf_strings=False,
                shuffle_states=False, opaque_predicates=False, bogus_blocks=False)
    base.update(kw)
    return ObfOptions(**base)


def _count_guards(out):
    return sum(isinstance(n, ast.If) for n in ast.walk(ast.parse(out)))


def test_split_increases_block_count_and_preserves_behavior():
    base = obf_func(SRC, _opts(max_block_stmts=None))
    split = obf_func(SRC, _opts(max_block_stmts=2))
    assert _count_guards(split) > _count_guards(base)
    for out in (base, split):
        f = _run(out)
        assert f(2) == 29 and f(-100) == abs((((((-100 + 1) * 2) - 3) + 4) * 5) - 6)


def test_split_none_is_noop():
    a = obf_func(SRC, _opts(max_block_stmts=None))
    b = obf_func(SRC, _opts())  # default max_block_stmts is None
    assert a == b


@pytest.mark.parametrize("seed", [0, 1, 7, 23])
@pytest.mark.parametrize("mbs", [1, 2, 3])
def test_split_equivalent_full_strength(seed, mbs):
    src = ("def f(n):\n    out = []\n    acc = 0\n    acc = acc + n\n    acc = acc * 2\n"
           "    acc = acc - 1\n    for i in range(n):\n        acc = acc + i\n"
           "        out.append(acc)\n    return (acc, out)\n")
    ns_o = {}
    exec(compile(src, "<o>", "exec"), ns_o)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, max_block_stmts=mbs))
    ns_t = {}
    exec(compile(out, "<t>", "exec"), ns_t)
    for n in (0, 1, 5):
        assert ns_o["f"](n) == ns_t["f"](n)


def test_split_with_exceptions():
    src = ("def f(a, b):\n    x = a + 1\n    y = x + 1\n    z = y + 1\n    w = z + 1\n"
           "    try:\n        return w // b\n    except ZeroDivisionError:\n        return w\n")
    ns_o = {}
    exec(compile(src, "<o>", "exec"), ns_o)
    for seed in (0, 3, 9):
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, max_block_stmts=1))
        ns_t = {}
        exec(compile(out, "<t>", "exec"), ns_t)
        assert ns_o["f"](6, 2) == ns_t["f"](6, 2)
        assert ns_o["f"](6, 0) == ns_t["f"](6, 0)
