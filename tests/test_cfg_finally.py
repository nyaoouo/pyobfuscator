import ast, sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names
from pyobfuscator.cff.diagnostics import UnsupportedConstructError
from equivalence import assert_func_equivalent


def _flat(src, seed=0):
    tree = ast.parse(src)
    fn = tree.body[0]
    flatten_function(fn, Namer(seed, collect_names(fn)), safe_mode=True)
    ast.fix_missing_locations(tree)
    return tree, fn.name


def _check(src, name, batteries, seed=0):
    tree, fname = _flat(src, seed)
    def factory():
        ns = {}
        exec(compile(tree, "<fin>", "exec"), ns)
        return ns[fname]
    assert_func_equivalent(src, factory, name, batteries)


def test_hybrid_keeps_real_finally_and_flattens():
    src = ("def f():\n    try:\n        x = 1\n    finally:\n        print('fin')\n    return x\n")
    tree, _ = _flat(src)
    out = ast.unparse(tree)
    assert "while True" in out      # the bodies were flattened into dispatchers
    assert "finally:" in out         # ...but a REAL finally was kept (hybrid)


def test_finally_runs_on_normal_path():
    src = ("def f():\n    try:\n        print('t')\n    finally:\n        print('f')\n    return 1\n")
    _check(src, "f", [((), {})])


def test_finally_runs_on_exception_propagation():
    src = ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n    finally:\n        print('f')\n")
    _check(src, "f", [((2,), {}), ((0,), {})])  # x=0 -> ZeroDivisionError after t,f


def test_try_except_finally():
    src = ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n"
           "    except ZeroDivisionError:\n        print('h')\n        return -1\n"
           "    finally:\n        print('f')\n")
    _check(src, "f", [((2,), {}), ((0,), {})])


def test_try_except_else_finally():
    src = ("def f(x):\n    try:\n        print('t')\n        y = 10 // x\n"
           "    except ZeroDivisionError:\n        print('h')\n        return -1\n"
           "    else:\n        print('e')\n        return y\n"
           "    finally:\n        print('f')\n")
    _check(src, "f", [((5,), {}), ((0,), {})])


def test_return_in_protected_still_runs_finally():
    src = ("def f():\n    try:\n        print('t')\n        return 'a'\n    finally:\n        print('f')\n")
    _check(src, "f", [((), {})])


def test_return_in_finally_overrides():
    src = ("def f():\n    try:\n        print('t')\n        return 'a'\n"
           "    finally:\n        print('f')\n        return 'b'\n")
    _check(src, "f", [((), {})])  # must return 'b'


def test_raise_in_finally_overrides():
    src = ("def f():\n    try:\n        return 'a'\n    finally:\n        raise ValueError('boom')\n")
    _check(src, "f", [((), {})])  # must raise ValueError, not return 'a'


def test_uncaught_through_finally():
    src = ("def f():\n    try:\n        raise KeyError('k')\n    finally:\n        print('f')\n")
    _check(src, "f", [((), {})])  # KeyError propagates; 'f' printed


def test_nested_try_finally_order():
    src = ("def f(x):\n    try:\n        try:\n            print('it')\n            return 10 // x\n"
           "        finally:\n            print('if')\n    finally:\n        print('of')\n")
    _check(src, "f", [((2,), {}), ((0,), {})])  # order it, if, of


def test_finally_with_internal_control_flow():
    src = ("def f(x):\n    try:\n        return x\n    finally:\n        if x > 0:\n"
           "            print('pos')\n        else:\n            print('nonpos')\n")
    _check(src, "f", [((5,), {}), ((-1,), {})])


def test_break_inside_protected_targets_in_region_loop_ok():
    src = ("def f(n):\n    out = []\n    try:\n        for i in range(n):\n            if i == 2:\n"
           "                break\n            out.append(i)\n    finally:\n        out.append('f')\n    return out\n")
    _check(src, "f", [((5,), {}), ((1,), {})])


def test_continue_inside_protected_targets_in_region_loop_ok():
    src = ("def f(n):\n    out = []\n    try:\n        for i in range(n):\n            if i % 2:\n"
           "                continue\n            out.append(i)\n    finally:\n        out.append('f')\n    return out\n")
    _check(src, "f", [((6,), {})])


def test_loop_inside_finally_ok():
    src = ("def f(n):\n    try:\n        return n\n    finally:\n        for i in range(n):\n            print(i)\n")
    _check(src, "f", [((3,), {})])


@pytest.mark.parametrize("src", [
    # break in protected targeting an OUTER loop (crosses finally) -> reject
    ("def f(n):\n    for i in range(n):\n        try:\n            if i == 2:\n                break\n"
     "            print(i)\n        finally:\n            print('f')\n    return 'done'\n"),
    # continue in protected targeting an OUTER loop -> reject
    ("def f(n):\n    for i in range(n):\n        try:\n            if i == 2:\n                continue\n"
     "            print(i)\n        finally:\n            print('f')\n    return 'done'\n"),
    # break in the finally body targeting an OUTER loop -> reject
    ("def f(n):\n    for i in range(n):\n        try:\n            print(i)\n        finally:\n"
     "            if i == 2:\n                break\n    return 'done'\n"),
])
def test_break_continue_across_finally_rejected(src):
    with pytest.raises(UnsupportedConstructError):
        _flat(src)
