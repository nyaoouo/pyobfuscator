import sys, os, io, contextlib, ast, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions


def _obs(fn, a):
    b = io.StringIO(); r = e = None
    with contextlib.redirect_stdout(b):
        try: r = fn(*a)
        except BaseException as x: e = (type(x).__name__, str(x))
    return (repr(r), e, b.getvalue())


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


SRCS = [
    # internal eligible, multi-param, called as bare statement + assignment + return
    ("def f(x):\n    def _g(a, b, c):\n        return a * 100 + b * 10 + c\n"
     "    r = _g(x, x + 1, x + 2)\n    return _g(r, 0, 1)\n", "f", [(3,), (0,)]),
    # external multi-arg in assignment / return / statement
    ("def f(a, b):\n    m = max(a, b)\n    print(a, b, m)\n    return min(a, b) + m\n", "f", [(7, 2), (1, 9)]),
    # multi-arg call in a condition (NOT splittable) must still work
    ("def f(s):\n    if max(len(s), 3) > 2:\n        return len(s)\n    return 0\n", "f", [("ab",), ("abcde",)]),
    # nested multi-arg calls
    ("def f(x):\n    def _add(a, b):\n        return a + b\n    return _add(_add(x, 1), _add(2, 3))\n", "f", [(5,)]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(split_calls=True, stack_calls=True),
    dict(split_calls=True, hide_external_args=True),
    dict(split_calls=True, stack_calls=True, hide_external_args=True),
    dict(split_calls=True, stack_calls=True, hide_external_args=True, obf_ints=True,
         obf_strings=True, dispatch_tree=True, state_delta=True, dedup=True, return_var=True),
])
@pytest.mark.parametrize("seed", [0, 1, 9])
def test_split_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_split_actually_separates_blocks():
    # with split_calls, a 3-arg internal call must yield more dispatcher states than without
    src = ("def f(x):\n    def _g(a, b, c):\n        return a + b + c\n    return _g(x, x, x)\n")
    base = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True,
                                    shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    split = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True, split_calls=True,
                                     shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    assert n(split) > n(base)  # more guard states => split across more blocks
    assert "..." not in split  # the Ellipsis markers were consumed by the flattener, not emitted


def test_split_by_default_when_callhiding(seed=0):
    # backlog C: with stack_calls on, call-site splitting is the DEFAULT (no split_calls flag).
    # A 3-arg internal call scatters into push/marker/call => more dispatcher states than a
    # non-routed min-blocks flatten of the same body. (split_calls additionally interleaves the
    # CALLEE-side pops, so it yields >= the default; we assert default already splits the call.)
    src = ("def f(x):\n    def _g(a, b, c):\n        return a + b + c\n    return _g(x, x, x)\n")
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    baseline = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1,
                                        shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    default = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True,
                                       shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    explicit = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True, split_calls=True,
                                        shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert n(default) > n(baseline)      # default now splits the call across blocks
    assert n(explicit) >= n(default)     # explicit adds callee-side pop splitting on top
    assert "..." not in default          # markers consumed by the flattener
    assert not _has_bundled_call_subscript(default)


def _has_bundled_call_subscript(code):
    """Detect a bundled `(push, ..., call)[-1]` Subscript-of-Tuple.

    The bundled hidden-call form is `(push(...), ..., call)[-1]`: a Subscript whose value is a
    Tuple ending in a Call. (Note: the `-1` index parses as UnaryOp(USub, Constant(1)), not a
    Constant, so we don't match on the slice — the Tuple-ending-in-Call shape is sufficient and
    is exactly what the rewriter emits.)"""
    for node in ast.walk(ast.parse(code)):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Tuple)
                and node.value.elts and isinstance(node.value.elts[-1], ast.Call)):
            return True
    return False


def test_single_arg_internal_splits_by_default():
    # backlog C intent 1: a hidden SINGLE-arg internal call splits by default (no split_calls).
    # push and call scatter into different dispatcher blocks => more states than min-blocks flatten,
    # and NO bundled (...)[-1] tuple survives for the call.
    src = ("def f(x):\n    def _g(a):\n        return a + 1\n    return _g(x)\n")
    flat_opts = dict(output="text", seed=0, min_blocks=1,
                     shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False)
    # baseline: same body but no stack_calls => one block for the (push,call) statement
    baseline = obf_func("def f(x):\n    def _g(a):\n        return a + 1\n    return _g(x)\n",
                        ObfOptions(**flat_opts))
    routed = obf_func(src, ObfOptions(stack_calls=True, **flat_opts))
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    assert n(routed) > n(baseline), f"single-arg call did not scatter:\n{routed}"
    assert "..." not in routed
    assert not _has_bundled_call_subscript(routed), f"call stayed bundled:\n{routed}"
    # equivalence
    orig = _ns(src, "f"); obf = _ns(routed, "f")
    for a in [(0,), (5,), (-3,)]:
        assert _obs(orig, a) == _obs(obf, a)


def test_single_arg_external_splits_by_default():
    # backlog C intent 1 (external variant): a hidden single-arg external call f(x) splits
    # by default under hide_external_args.
    src = ("def f(s):\n    return len(s)\n")
    flat_opts = dict(output="text", seed=0, min_blocks=1,
                     shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False)
    baseline = obf_func(src, ObfOptions(**flat_opts))
    routed = obf_func(src, ObfOptions(hide_external_args=True, **flat_opts))
    n = lambda o: sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(o)))
    assert n(routed) > n(baseline), f"single-arg external call did not scatter:\n{routed}"
    assert "..." not in routed
    assert not _has_bundled_call_subscript(routed), f"external call stayed bundled:\n{routed}"
    orig = _ns(src, "f"); obf = _ns(routed, "f")
    for a in [("abc",), ("",), ("xyz",)]:
        assert _obs(orig, a) == _obs(obf, a)


def test_multi_arg_splits_by_default():
    # backlog C intent 2: multi-arg (was the split_calls behavior) now scatters by default.
    src = ("def f(x):\n    def _g(a, b, c):\n        return a + b + c\n    return _g(x, x + 1, x + 2)\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert "..." not in out
    assert not _has_bundled_call_subscript(out), f"multi-arg call stayed bundled:\n{out}"
    orig = _ns(src, "f"); obf = _ns(out, "f")
    for a in [(0,), (3,)]:
        assert _obs(orig, a) == _obs(obf, a)


def test_nested_in_condition_stays_bundled():
    # backlog C intent 3 (safe fallback): a hidden call inside an `if <call>:` test is NOT split
    # (stays the bundled tuple form) and still works.
    src = ("def f(s):\n    if len(s) > 1:\n        return len(s)\n    return 0\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, hide_external_args=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    # the call inside the if-test cannot be split => bundled subscript form must survive
    assert _has_bundled_call_subscript(out), f"condition call should stay bundled:\n{out}"
    assert "..." not in out  # no leaked markers
    orig = _ns(src, "f"); obf = _ns(out, "f")
    for a in [("a",), ("abc",), ("",)]:
        assert _obs(orig, a) == _obs(obf, a)


def test_nested_in_expression_stays_bundled():
    # backlog C intent 3 (variant): a hidden call nested inside a larger expression
    # (binop operand) is NOT a top-level Expr/Assign-Name/Return => stays bundled.
    src = ("def f(s):\n    return len(s) + 100\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, hide_external_args=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert _has_bundled_call_subscript(out), f"nested-expr call should stay bundled:\n{out}"
    orig = _ns(src, "f"); obf = _ns(out, "f")
    for a in [("a",), ("abc",)]:
        assert _obs(orig, a) == _obs(obf, a)


# backlog C intent 4: equivalence matrix over routing x split_calls x dispatch x seeds.
MATRIX_SRCS = [
    ("def f(x):\n    def _g(a):\n        return a * 2\n    return _g(x) + _g(x + 1)\n", "f", [(3,), (0,), (-5,)]),
    ("def f(x):\n    def _g(a, b, c):\n        return a - b + c\n    r = _g(x, 1, 2)\n    return _g(r, 0, 9)\n", "f", [(5,), (0,)]),
    ("def f(s):\n    return len(s) + len(s)\n", "f", [("abc",), ("",)]),
    ("def f(a, b):\n    print(a, b)\n    m = max(a, b)\n    return min(a, b) + m\n", "f", [(7, 2), (1, 9)]),
    # exception path
    ("def f(x):\n    def _g(a):\n        return 10 // a\n    return _g(x)\n", "f", [(2,), (0,)]),
    # arg mutation / side-effect order
    ("def f():\n    log = []\n    def _rec(x):\n        log.append(x)\n        return x\n"
     "    r = _rec(1) + _rec(2)\n    return (r, log)\n", "f", [()]),
]


@pytest.mark.parametrize("src,name,args", MATRIX_SRCS)
@pytest.mark.parametrize("opts", [
    dict(stack_calls=True),
    dict(hide_external_args=True),
    dict(stack_calls=True, hide_external_args=True),
    dict(stack_calls=True, split_calls=True),                 # back-compat: flag still works
    dict(hide_external_args=True, split_calls=True),
    dict(stack_calls=True, hide_external_args=True, dispatch_tree=True),
    dict(stack_calls=True, hide_external_args=True, shuffle_states=True, state_delta=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_default_split_equivalence_matrix(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_split_calls_flag_still_works_backcompat():
    # intent 5: split_calls=True explicitly still works (back-compat) and stays equivalent.
    src = ("def f(x):\n    def _g(a, b, c):\n        return a + b + c\n    return _g(x, x, x)\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True, split_calls=True,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert "..." not in out
    assert not _has_bundled_call_subscript(out)
    orig = _ns(src, "f"); obf = _ns(out, "f")
    for a in [(3,), (0,)]:
        assert _obs(orig, a) == _obs(obf, a)
