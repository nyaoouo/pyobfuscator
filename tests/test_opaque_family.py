import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions

SRC = "def f(x):\n    if x > 0:\n        y = x + 1\n        return y\n    return 0\n"


def _run(out):
    ns = {}; exec(compile(out, "<t>", "exec"), ns); return ns["f"]


def _opq(seed, **kw):
    base = dict(output="text", seed=seed, min_blocks=1, obf_strings=False,
                shuffle_states=True, opaque_predicates=True, bogus_blocks=False)
    base.update(kw)
    return obf_func(SRC, ObfOptions(**base))


def test_not_a_single_fixed_identity():
    # The old single form (opq*opq + opq) % 2 == 0 must no longer be the ONLY predicate shape:
    # collect the set of Mod right-operands / comparator constants across seeds; expect variety.
    shapes = set()
    for s in range(12):
        for n in ast.walk(ast.parse(_opq(s))):
            if isinstance(n, ast.IfExp) and isinstance(n.test, ast.Compare):
                shapes.add(ast.dump(n.test))
    assert len(shapes) >= 4, f"opaque predicates not diverse enough: {len(shapes)} shapes"


def test_polarity_is_randomized_real_in_both_sides():
    # Across seeds, the REAL state ids (large ints) must appear in BOTH IfExp.body and IfExp.orelse.
    body_has_big = orelse_has_big = False
    for s in range(12):
        for n in ast.walk(ast.parse(_opq(s))):
            if isinstance(n, ast.IfExp):
                if isinstance(n.body, ast.Constant) and isinstance(n.body.value, int) and n.body.value >= 1000:
                    body_has_big = True
                if isinstance(n.orelse, ast.Constant) and isinstance(n.orelse.value, int) and n.orelse.value >= 1000:
                    orelse_has_big = True
    assert body_has_big and orelse_has_big, "real label never appears on one side -> polarity not randomized"


def test_state_var_is_fed_into_predicates():
    # at least some predicates reference the dispatcher state var (not only the fixed opq)
    out = _opq(0)
    tree = ast.parse(out)
    # the state var is the Name compared `== <big int>` in the guards
    state_names = {n.left.id for n in ast.walk(tree)
                   if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
                   and len(n.comparators) == 1 and isinstance(n.comparators[0], ast.Constant)
                   and isinstance(n.comparators[0].value, int) and n.comparators[0].value >= 1000}
    found = False
    for s in range(12):
        for n in ast.walk(ast.parse(_opq(s))):
            if isinstance(n, ast.IfExp):
                for sub in ast.walk(n.test):
                    if isinstance(sub, ast.Name) and sub.id in state_names:
                        found = True
    assert found, "state var never fed into an opaque predicate"


@pytest.mark.parametrize("seed", range(10))
@pytest.mark.parametrize("opts", [
    dict(opaque_predicates=True, bogus_blocks=False),
    dict(opaque_predicates=True, bogus_blocks=True, state_delta=True, dispatch_tree=True),
    dict(opaque_predicates=True, bogus_blocks=True, state_delta=True, dispatch_tree=True,
         dedup=True, junk_code=True),
])
def test_opaque_equivalence(seed, opts):
    base = dict(output="text", seed=seed, min_blocks=1)
    base.update(opts)
    f = _run(obf_func(SRC, ObfOptions(**base)))
    assert f(5) == 6 and f(-3) == 0 and f(0) == 0


def _bog(seed, **kw):
    base = dict(output="text", seed=seed, min_blocks=1, obf_strings=False,
                shuffle_states=True, opaque_predicates=False, bogus_blocks=True)
    base.update(kw)
    return obf_func(SRC, ObfOptions(**base))


def test_bogus_labels_are_referenced_as_transition_targets():
    # A bogus label is a guard `state == bl` whose bl must now ALSO appear as an IfExp branch
    # value somewhere (a never-taken target) for at least some seeds -> reachable-looking.
    ref_seen = False
    for s in range(12):
        tree = ast.parse(_bog(s))
        guard_labels = {n.comparators[0].value for n in ast.walk(tree)
                        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
                        and len(n.comparators) == 1 and isinstance(n.comparators[0], ast.Constant)
                        and isinstance(n.comparators[0].value, int)}
        ifexp_vals = {c.value for n in ast.walk(tree) if isinstance(n, ast.IfExp)
                      for c in (n.body, n.orelse)
                      if isinstance(c, ast.Constant) and isinstance(c.value, int)}
        if guard_labels & ifexp_vals:
            ref_seen = True
    assert ref_seen, "no bogus label is referenced as a transition target -> still trivially unreachable"


def test_bogus_still_never_executes():
    # behavior unchanged across seeds + flag combos (bogus body would corrupt junk var / results)
    src = ("def f(n):\n    total = 0\n    for i in range(n):\n        if i % 2:\n"
           "            total += i\n        else:\n            total -= 1\n    return total\n")
    for s in range(8):
        ns = {}
        exec(compile(obf_func(src, ObfOptions(output="text", seed=s, min_blocks=1)), "<t>", "exec"), ns)
        for n in (0, 1, 5, 10):
            assert ns["f"](n) == sum(i if i % 2 else -1 for i in range(n))
