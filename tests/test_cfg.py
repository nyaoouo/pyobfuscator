import ast
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))  # for equivalence import

from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names
from equivalence import assert_func_equivalent


def _flatten_src(src, seed=0):
    tree = ast.parse(src)
    fn = tree.body[0]
    namer = Namer(seed, collect_names(fn))
    flatten_function(fn, namer)
    ast.fix_missing_locations(tree)
    return tree, fn.name


def _check(src, name, batteries, seed=0):
    tree, fname = _flatten_src(src, seed)
    def factory():
        ns = {}
        exec(compile(tree, "<cfg>", "exec"), ns)
        return ns[fname]
    assert fname == name
    assert_func_equivalent(src, factory, name, batteries)


def test_straight_line():
    _check("def f(a, b):\n    c = a + b\n    d = c * 2\n    return d\n",
           "f", [((1, 2), {}), ((0, 0), {})])


def test_if_else():
    _check("def f(x):\n    if x > 0:\n        r = 1\n    else:\n        r = -1\n    return r\n",
           "f", [((5,), {}), ((-5,), {}), ((0,), {})])


def test_if_no_else_fallthrough():
    _check("def f(x):\n    r = 0\n    if x:\n        r = 1\n    return r\n",
           "f", [((1,), {}), ((0,), {})])


def test_while_with_break_continue():
    src = ("def f(n):\n"
           "    t = 0\n"
           "    i = 0\n"
           "    while i < n:\n"
           "        i = i + 1\n"
           "        if i == 3:\n"
           "            continue\n"
           "        if i == 7:\n"
           "            break\n"
           "        t = t + i\n"
           "    return t\n")
    _check(src, "f", [((0,), {}), ((5,), {}), ((10,), {})])


def test_while_else():
    src = ("def f(n):\n"
           "    i = 0\n"
           "    while i < n:\n"
           "        i = i + 1\n"
           "    else:\n"
           "        i = i + 100\n"
           "    return i\n")
    _check(src, "f", [((0,), {}), ((3,), {})])


def test_for_sum():
    _check("def f(n):\n    t = 0\n    for i in range(n):\n        t += i\n    return t\n",
           "f", [((0,), {}), ((5,), {}), ((1,), {})])


def test_for_else_and_break():
    src = ("def f(seq, target):\n"
           "    found = -1\n"
           "    for i in seq:\n"
           "        if i == target:\n"
           "            found = i\n"
           "            break\n"
           "    else:\n"
           "        found = -999\n"
           "    return found\n")
    _check(src, "f", [(([1, 2, 3], 2), {}), (([1, 2, 3], 9), {}), (([], 0), {})])


def test_early_return_in_loop():
    src = ("def f(n):\n"
           "    for i in range(n):\n"
           "        if i == 4:\n"
           "            return i\n"
           "    return -1\n")
    _check(src, "f", [((10,), {}), ((2,), {})])


def test_implicit_return_none():
    _check("def f(x):\n    y = x + 1\n", "f", [((1,), {})])


def test_nested_loops():
    src = ("def f(n):\n"
           "    t = 0\n"
           "    for i in range(n):\n"
           "        for j in range(i):\n"
           "            t += j\n"
           "    return t\n")
    _check(src, "f", [((0,), {}), ((4,), {})])
