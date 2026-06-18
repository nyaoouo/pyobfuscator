"""Backlog E: the flattened `return` terminator is cut into its OWN dispatcher block.

When `split_markers` is on (driven by split_calls / stack_calls / hide_external_args),
the SIMPLE return path computes the value into a fresh `ret` var in the current block
and `Goto`s a new block whose only terminator is `return <name>`. The value/logic that
produced the result therefore lives in a different state from the `return`, so an analyst
who locates the `return` block sees only `return _r`.

The unwind path (safe_mode=False with active exception frames) is UNTOUCHED and keeps its
own `retval`/finally-continuation machinery.
"""
import ast
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))  # for equivalence import

import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names
from equivalence import assert_func_equivalent, observe


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _flatten_low(src, *, split_markers, safe_mode=True, seed=0):
    """Low-level flatten (no shuffle/bogus/opaque) for clean structural inspection."""
    tree = ast.parse(src)
    fn = tree.body[0]
    namer = Namer(seed, collect_names(fn))
    flatten_function(fn, namer, min_blocks=1, safe_mode=safe_mode,
                     split_markers=split_markers)
    ast.fix_missing_locations(tree)
    return tree, fn


def _guard_bodies(fn):
    """The body list of each `if <state> == K:` dispatcher guard in a flattened fn."""
    while_node = next(s for s in fn.body if isinstance(s, ast.While))
    body = while_node.body
    # needs_exc wraps the guards in a Try; unwrap it
    if len(body) == 1 and isinstance(body[0], ast.Try):
        body = body[0].body
    return [g.body for g in body if isinstance(g, ast.If)]


def _return_nodes(fn):
    return [n for n in ast.walk(fn) if isinstance(n, ast.Return)]


def _factory(tree, name):
    def f():
        ns = {}
        exec(compile(tree, "<rc>", "exec"), ns)
        return ns[name]
    return f


# --------------------------------------------------------------------------- #
# 1. return terminator isolated (structural)
# --------------------------------------------------------------------------- #
def test_return_terminator_isolated_simple():
    """logic-then-return: the block holding `return` is ONLY `return <Name>`; the
    value computation lives in a different (predecessor) block."""
    src = "def f(x):\n    y = x + 1\n    z = y * 2\n    return z + 100\n"
    tree, fn = _flatten_low(src, split_markers=True)

    rets = _return_nodes(fn)
    assert len(rets) == 1
    # the return value is a bare Name (the relayed ret var), not the original expr
    assert isinstance(rets[0].value, ast.Name)

    # the guard block that contains the Return contains NOTHING else
    ret_bodies = [b for b in _guard_bodies(fn) if any(isinstance(s, ast.Return) for s in b)]
    assert len(ret_bodies) == 1
    assert len(ret_bodies[0]) == 1  # just the `return <Name>`
    assert isinstance(ret_bodies[0][0], ast.Return)

    # and the original computation `z + 100` is NOT in the return block — it is in a
    # block that ends in a Goto (state assign + continue), not a Return.
    src_text = ast.unparse(tree)
    assert "+ 100" in src_text  # the computation survives
    # equivalence
    assert_func_equivalent(src, _factory(tree, "f"), "f", [((5,), {}), ((0,), {}), ((-3,), {})])


def test_return_value_is_bare_name_multiple_returns():
    """Every simple return becomes `return <bare Name>` under split_markers."""
    src = ("def f(x):\n"
           "    if x < 0:\n        return x - 1\n"
           "    if x == 0:\n        return\n"
           "    return x * x\n")
    tree, fn = _flatten_low(src, split_markers=True)
    rets = _return_nodes(fn)
    assert len(rets) == 3
    assert all(isinstance(r.value, ast.Name) for r in rets), ast.unparse(tree)
    # each return lives alone in its guard
    for b in _guard_bodies(fn):
        if any(isinstance(s, ast.Return) for s in b):
            assert len(b) == 1
    assert_func_equivalent(src, _factory(tree, "f"), "f",
                           [((-2,), {}), ((0,), {}), ((4,), {})])


# --------------------------------------------------------------------------- #
# 3. off path unchanged
# --------------------------------------------------------------------------- #
def test_off_path_return_not_cut():
    """split_markers OFF: the value goes straight into the `return`; NO extra cut block."""
    src = "def f(x):\n    y = x + 1\n    return y * 2\n"
    tree, fn = _flatten_low(src, split_markers=False)
    rets = _return_nodes(fn)
    assert len(rets) == 1
    # the return value is the ORIGINAL expression (a BinOp `y * 2`), not a bare Name
    assert isinstance(rets[0].value, ast.BinOp)
    # the return shares its block with the computation `y = x + 1`
    ret_bodies = [b for b in _guard_bodies(fn) if any(isinstance(s, ast.Return) for s in b)]
    assert len(ret_bodies) == 1
    assert len(ret_bodies[0]) > 1  # computation + return together
    assert_func_equivalent(src, _factory(tree, "f"), "f", [((1,), {}), ((9,), {})])


def test_off_path_via_obf_func_returns_kept():
    """With no split_calls/stack_calls/hide_external_args, the bare return value is kept."""
    src = "def f(x):\n    return x + 41\n"
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                   obf_strings=False, obf_ints=False,
                                   shuffle_states=False, opaque_predicates=False,
                                   bogus_blocks=False))
    tree = ast.parse(out)
    rets = [n for n in ast.walk(tree) if isinstance(n, ast.Return)]
    # at least one return whose value is the original BinOp (not relayed through a name)
    assert any(isinstance(r.value, ast.BinOp) for r in rets), out


# --------------------------------------------------------------------------- #
# bare return / return None correctness
# --------------------------------------------------------------------------- #
def test_bare_return_and_return_none_cut_correctly():
    src = ("def f(x):\n"
           "    if x:\n        return\n"
           "    y = 5\n"
           "    return None\n")
    tree, fn = _flatten_low(src, split_markers=True)
    rets = _return_nodes(fn)
    # bare `return`, `return None`, and the implicit fall-off all relay a name
    assert all(isinstance(r.value, ast.Name) for r in rets), ast.unparse(tree)
    assert_func_equivalent(src, _factory(tree, "f"), "f", [((1,), {}), ((0,), {})])


# --------------------------------------------------------------------------- #
# 2. equivalence across return contexts (the hard gate)
# --------------------------------------------------------------------------- #
_CASES = {
    "plain": ("def f(a, b):\n    c = a + b\n    return c * 2\n",
              [((1, 2), {}), ((0, 0), {}), ((-3, 5), {})]),
    "if_elif_else": (
        "def f(x):\n"
        "    if x < 0:\n        return 'neg'\n"
        "    elif x == 0:\n        return 'zero'\n"
        "    else:\n        return 'pos'\n",
        [((-1,), {}), ((0,), {}), ((9,), {})]),
    "for_loop": (
        "def f(n):\n"
        "    t = 0\n"
        "    for i in range(n):\n"
        "        if i == 4:\n            return ('early', i)\n"
        "        t += i\n"
        "    return ('end', t)\n",
        [((2,), {}), ((10,), {}), ((0,), {})]),
    "while_loop": (
        "def f(n):\n"
        "    i = 0\n"
        "    while True:\n"
        "        if i >= n:\n            return i\n"
        "        i += 1\n",
        [((0,), {}), ((5,), {})]),
    "multiple_returns": (
        "def f(x):\n"
        "    if x < 0:\n        return False\n"
        "    if x == 0:\n        return\n"
        "    if x > 100:\n        return False\n"
        "    return x * 2\n",
        [((-1,), {}), ((0,), {}), ((200,), {}), ((5,), {})]),
    "bare_return": (
        "def f(x):\n"
        "    if x:\n        print('hit')\n        return\n"
        "    print('miss')\n",
        [((1,), {}), ((0,), {})]),
    "return_none": ("def f(x):\n    y = x\n    return None\n", [((7,), {})]),
    "nested_func": (
        "def f(n):\n"
        "    def g(z):\n        if z > 0:\n            return z * 10\n        return -1\n"
        "    return g(n) + 1\n",
        [((3,), {}), ((-2,), {})]),
    "try_except": (
        "def f(a, b):\n"
        "    try:\n        return a // b\n"
        "    except ZeroDivisionError:\n        return 'zde'\n"
        "    except TypeError:\n        return 'te'\n",
        [((6, 2), {}), ((6, 0), {}), ((6, None), {})]),
    "try_finally": (
        "def f(x):\n"
        "    try:\n"
        "        if x > 0:\n            return x + 1\n"
        "        return -1\n"
        "    finally:\n        print('F')\n",
        [((5,), {}), ((-5,), {})]),
    "try_except_finally": (
        "def f(a, b):\n"
        "    try:\n        r = a // b\n        return r\n"
        "    except ZeroDivisionError:\n        return -1\n"
        "    finally:\n        print('done')\n",
        [((10, 2), {}), ((10, 0), {})]),
    "raises": (
        "def f(x):\n"
        "    if x < 0:\n        raise ValueError('neg ' + str(x))\n"
        "    return x * 3\n",
        [((-4,), {}), ((4,), {})]),
    "arg_mutation": (
        "def f(lst):\n"
        "    lst.append(99)\n"
        "    if len(lst) > 3:\n        return 'big'\n"
        "    return 'small'\n",
        [(([1, 2],), {}), (([1, 2, 3, 4],), {})]),
}


def _matrix():
    out = []
    for name, (src, batt) in _CASES.items():
        for safe_mode in (True, False):
            for trigger in ("split_calls", "stack_calls"):
                for return_var in (False, True):
                    for extra in ({}, {"dispatch_tree": True}):
                        for seed in (0, 3):
                            out.append((name, src, batt, safe_mode, trigger,
                                        return_var, extra, seed))
    return out


@pytest.mark.parametrize(
    "name,src,batt,safe_mode,trigger,return_var,extra,seed",
    _matrix(),
    ids=lambda v: v if isinstance(v, str) else "")
def test_equivalence_matrix(name, src, batt, safe_mode, trigger, return_var, extra, seed):
    """Behaviour (return value / exception type+msg / stdout / arg mutation) is identical
    to the original across the full option matrix that turns split_markers on."""
    opts = dict(output="text", seed=seed, min_blocks=1, safe_mode=safe_mode,
                return_var=return_var, **{trigger: True}, **extra)
    out = obf_func(src, ObfOptions(**opts))

    def factory():
        ns = {}
        exec(compile(out, "<rcm>", "exec"), ns)
        return ns["f"]

    # use fresh-arg observation so list-mutation cases compare correctly
    orig_ns = {}
    exec(compile(src, "<rco>", "exec"), orig_ns)

    def orig_factory():
        ns = {}
        exec(compile(src, "<rco2>", "exec"), ns)
        return ns["f"]

    for args, kwargs in batt:
        import copy
        o = observe(orig_factory, copy.deepcopy(args), copy.deepcopy(kwargs))
        t = observe(factory, copy.deepcopy(args), copy.deepcopy(kwargs))
        assert o == t, f"{name} safe={safe_mode} {trigger} rv={return_var} {extra} seed={seed}\nargs={args}\n{o}\n!=\n{t}\n{out}"


# --------------------------------------------------------------------------- #
# 4. exception / finally still correct (unwind path untouched)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("safe_mode", [True, False])
def test_finally_runs_on_return_and_raise(safe_mode):
    src = ("def f(x):\n"
           "    out = []\n"
           "    try:\n"
           "        if x == 1:\n            return 'one'\n"
           "        if x == 2:\n            raise ValueError('two')\n"
           "        out.append('body')\n"
           "    finally:\n        out.append('fin')\n"
           "    return out\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                   safe_mode=safe_mode, split_calls=True))

    def factory():
        ns = {}
        exec(compile(out, "<rcf>", "exec"), ns)
        return ns["f"]

    assert_func_equivalent(src, factory, "f", [((1,), {}), ((2,), {}), ((3,), {})])


def test_unwind_path_untouched_full_mode_finally_continuation():
    """safe_mode=False return inside try/finally uses the finally-continuation unwind,
    not the simple cut — finally still runs and the value is returned afterwards."""
    src = ("def f(x):\n"
           "    try:\n"
           "        return x + 1\n"
           "    finally:\n"
           "        print('cleanup')\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                   safe_mode=False, stack_calls=True))

    def factory():
        ns = {}
        exec(compile(out, "<rcu>", "exec"), ns)
        return ns["f"]

    assert_func_equivalent(src, factory, "f", [((10,), {}), ((0,), {})])
