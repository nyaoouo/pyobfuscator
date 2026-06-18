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


SRCS = [
    ("def f(x):\n    if x < 0:\n        return 'neg'\n    total = 0\n    for i in range(x):\n        total += i\n    return total\n",
     "f", [(-1,), (0,), (5,)]),
    ("def f(a, b):\n    try:\n        return a // b\n    except ZeroDivisionError:\n        return 'inf'\n",
     "f", [(6, 2), (6, 0)]),
    ("def f(n):\n    out = []\n    i = 0\n    while i < n:\n        i += 1\n        if i % 2:\n            continue\n        out.append(i)\n    return out\n",
     "f", [(6,), (0,)]),
    # full-flatten finally (needs_k) — delta/tree must still be safe there
    ("def f(x):\n    try:\n        if x == 0:\n            return 'z'\n        return 10 // x\n    finally:\n        pass\n",
     "f", [(0,), (2,)]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(state_delta=True),
    dict(dispatch_tree=True),
    dict(state_delta=True, dispatch_tree=True),
    dict(state_delta=True, dispatch_tree=True, obf_ints=True, slot_vars=True),
    dict(state_delta=True, dispatch_tree=True, safe_mode=False),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_equivalent(src, name, args, opts, seed):
    ns0 = {}; exec(compile(src, "<o>", "exec"), ns0); orig = ns0[name]
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    ns = {}; exec(compile(out, "<t>", "exec"), ns)
    for a in args:
        assert _obs(orig, a) == _obs(ns[name], a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_delta_emits_augassign():
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, state_delta=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert any(isinstance(n, ast.AugAssign) for n in ast.walk(ast.parse(out)))


def test_tree_emits_gte_dispatch():
    src = ("def f(x):\n    if x == 1:\n        return 'a'\n    if x == 2:\n        return 'b'\n"
           "    if x == 3:\n        return 'c'\n    return 'd'\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, dispatch_tree=True,
                                   obf_strings=False))
    assert any(isinstance(n, ast.GtE) for n in ast.walk(ast.parse(out)))


def test_tree_has_no_state_equality_leaf():
    # The whole point: a fragment's concrete state value must NOT appear as `state == k`
    # (the BST alone locates the block by range). The state var is a `_pyobf_<hex>` name; with
    # dispatch_tree there must be ZERO `state == <int>` comparisons (state equality is the only
    # thing that would produce them — opaque predicates compare a BinOp, not a bare Name).
    #
    # NOTE: LocalRenamePass now renames the user param too (`x` -> `_pyobf_<hex>`), so the user's
    # own `if x == N` checks also become `_pyobf_<hex> == int` and would confound a bare
    # `_pyobf_* == int` filter. The synthetic dispatch state var is never a function PARAMETER, so
    # exclude param names from the leak set — this isolates the state var precisely and still fails
    # loudly if flatten ever emits a real `state == k` leaf.
    src = ("def f(x):\n    if x == 1:\n        return 'a'\n    if x == 2:\n        return 'b'\n"
           "    if x == 3:\n        return 'c'\n    if x == 4:\n        return 'e'\n    return 'd'\n")
    out = obf_func(src, ObfOptions(output="text", seed=3, min_blocks=1, dispatch_tree=True,
                                   shuffle_states=True, bogus_blocks=True, obf_strings=False))
    tree = ast.parse(out)
    param_names = {a.arg for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs}
    eqs = [n for n in ast.walk(tree)
           if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
           and n.left.id.startswith("_pyobf_") and n.left.id not in param_names
           and any(isinstance(o, ast.Eq) for o in n.ops)
           and len(n.comparators) == 1 and isinstance(n.comparators[0], ast.Constant)
           and type(n.comparators[0].value) is int]
    assert eqs == [], f"{len(eqs)} `state == int` comparisons leaked the fragment state values"


def test_off_by_default():
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert not any(isinstance(n, ast.AugAssign) for n in ast.walk(ast.parse(out)))  # no delta
    assert not any(isinstance(n, ast.GtE) for n in ast.walk(ast.parse(out)))         # no tree
