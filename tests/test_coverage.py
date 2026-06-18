import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from equivalence import assert_func_equivalent

CORPUS = [
    ("def f(n):\n    if n < 0:\n        return []\n    return [x * x for x in range(n)]\n",
     "f", [((4,), {}), ((-1,), {}), ((0,), {})]),
    ("def f(n):\n    if n == 0:\n        return {}\n    return {x: x * 2 for x in range(n)}\n",
     "f", [((3,), {}), ((0,), {})]),
    ("def f(n):\n    s = {x % 3 for x in range(n)}\n    if not s:\n        return 'empty'\n    return sorted(s)\n",
     "f", [((5,), {}), ((0,), {})]),
    ("def f(n):\n    g = (x + 1 for x in range(n))\n    total = 0\n    for v in g:\n        total += v\n    return total\n",
     "f", [((4,), {}), ((0,), {})]),
    ("def f(n):\n    add = lambda a, b: a + b\n    if n > 0:\n        return add(n, 10)\n    return add(0, 0)\n",
     "f", [((5,), {}), ((-1,), {})]),
    ("def f(items):\n    key = lambda p: p[1]\n    if not items:\n        return []\n    return sorted(items, key=key)\n",
     "f", [(([('a', 3), ('b', 1), ('c', 2)],), {}), (([],), {})]),
    ("def f(n):\n    factor = n + 1\n    mul = lambda x: x * factor\n    if n < 0:\n        return 0\n    return mul(n)\n",
     "f", [((5,), {}), ((-1,), {})]),
    ("def f(n):\n    base = n * 100\n    if n < 0:\n        return []\n    return [base + i for i in range(n)]\n",
     "f", [((3,), {}), ((-1,), {})]),
    ("def f(n):\n    if n <= 0:\n        return []\n    return [[i * j for j in range(n)] for i in range(n)]\n",
     "f", [((3,), {}), ((0,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 7])
def test_coverage_equivalent(src, name, batteries, seed):
    def factory():
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        ns = {}
        exec(compile(out, "<c>", "exec"), ns)
        return ns[name]
    assert_func_equivalent(src, factory, name, batteries)


# ---- walrus (:=) — opaque expression coverage (added when ctf_test.py needed it) ----
def _walrus_run(src, name, opts):
    out = obf_func(src, opts)
    ns = {}
    exec(compile(out, "<w>", "exec"), ns)
    return out, ns[name]


def test_walrus_in_if_test():
    src = ("def f(x):\n    if (y := x * 2) > 10:\n        return ('big', y)\n    return ('small', y)\n")
    for seed in (0, 3, 9):
        _, f = _walrus_run(src, "f", ObfOptions(output="text", seed=seed, min_blocks=1))
        assert f(6) == ('big', 12) and f(2) == ('small', 4)


def test_walrus_reassign_like_ctf_q2():
    # mirrors ctf_test.check_q2's `(n := n/73)` shape
    src = ("def f(s):\n    try:\n        n = int(s)\n    except ValueError:\n        return False\n"
           "    n = 8 * -n + 1\n    if (n := n / 73) != 73:\n        return False\n    return True\n")
    out, f = _walrus_run(src, "f", ObfOptions(output="text", seed=1, min_blocks=1))
    assert f("-666") is True and f("5") is False and f("abc") is False


def test_walrus_safe_under_slot_vars():
    # walrus target must NOT be slotted (`_slots[i] := ...` is invalid syntax)
    src = ("def f(x):\n    total = 0\n    if (total := x + 1) > 0:\n        total = total * 2\n    return total\n")
    out, f = _walrus_run(src, "f", ObfOptions(output="text", seed=0, min_blocks=1, slot_vars=True))
    assert f(5) == 12 and f(-5) == -4


def test_walrus_in_comprehension():
    src = ("def f(items):\n    out = [y := v + 1 for v in items]\n    return (out, y if items else None)\n")
    out, f = _walrus_run(src, "f", ObfOptions(output="text", seed=2, min_blocks=1))
    assert f([1, 2, 3]) == ([2, 3, 4], 4)


# ---- assert — carried as-is (opaque statement) ----
def test_assert_pass_and_fail():
    src = ("def f(x):\n    assert x > 0, 'must be positive'\n    return x * 2\n")
    for seed in (0, 4):
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
        ns = {}
        exec(compile(out, "<a>", "exec"), ns)
        assert ns["f"](5) == 10
        import pytest as _pt
        with _pt.raises(AssertionError):
            ns["f"](-1)


def test_assert_inside_try():
    src = ("def f(x):\n    try:\n        assert x != 0\n        return 10 // x\n"
           "    except AssertionError:\n        return 'asserted'\n")
    out = obf_func(src, ObfOptions(output="text", seed=1, min_blocks=1))
    ns = {}
    exec(compile(out, "<a>", "exec"), ns)
    assert ns["f"](2) == 5 and ns["f"](0) == 'asserted'
