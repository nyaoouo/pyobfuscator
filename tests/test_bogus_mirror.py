"""Bogus blocks MIRROR real branches on fresh random variables, never the old obvious
single-`junk = N * M` product."""
import ast
import random

from pyobfuscator import obf_func
from pyobfuscator.options import ObfOptions, OutputFormat
from pyobfuscator.cff.names import Namer
from pyobfuscator.cff.cfg import _build_bogus_body_synth, _mutate_clone


def test_synth_uses_distinct_fresh_vars():
    body = _build_bogus_body_synth(random.Random(1), Namer())
    lhs = [s.targets[0].id for s in body if isinstance(s, ast.Assign)]
    assert len(lhs) >= 2
    assert len(set(lhs)) == len(lhs), "synth body must use distinct vars, not one repeated junk var"
    assert all(n.startswith("_pyobf_g") for n in lhs)


def test_mutate_clone_renames_all_names_to_fresh():
    stmts = ast.parse("acc = n + 1\nx = acc * total\n").body
    out = _mutate_clone(stmts, random.Random(2), Namer())
    names = {n.id for s in out for n in ast.walk(s) if isinstance(n, ast.Name)}
    assert names and all(nm.startswith("_pyobf_g") for nm in names)
    for orig in ("acc", "n", "x", "total"):
        assert orig not in names, f"original {orig!r} leaked into the mirror clone"


def test_mutate_clone_is_consistent():
    # 2 distinct originals (a, b) -> exactly 2 distinct fresh names (a written+read keeps one name).
    stmts = ast.parse("a = 5\nb = a + a\n").body
    out = _mutate_clone(stmts, random.Random(3), Namer())
    fresh = {n.id for s in out for n in ast.walk(s) if isinstance(n, ast.Name)}
    assert len(fresh) == 2


def test_bogus_equivalence_and_determinism():
    src = "def f(x):\n    y = 0\n    if x > 1:\n        y = x * 2\n    else:\n        y = -x\n    return y\n"
    opt = dict(output=OutputFormat.TEXT, seed=7, min_blocks=1, bogus_blocks=True,
               shuffle_states=True, opaque_predicates=True)
    a = obf_func(src, ObfOptions(**opt))
    b = obf_func(src, ObfOptions(**opt))
    assert a == b, "deterministic"
    ns = {}
    exec(compile(ast.parse(a), "<t>", "exec"), ns)
    assert ns["f"](5) == 10 and ns["f"](-3) == 3


def test_no_repeated_single_junk_product_signature():
    # The old tell was many bogus blocks each = `<one var> = C * C`. Assert the output is not dominated
    # by a single repeated junk LHS doing a bare product (mirror bodies use varied fresh vars).
    src = ("def f(x):\n    a = x + 1\n    b = a * 3\n    if a > b:\n        return a\n    return b\n")
    out = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=4, min_blocks=1, bogus_blocks=True))
    tree = ast.parse(out)
    # count Assign whose value is a bare `Const * Const`
    bare_prod = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                 and isinstance(n.value, ast.BinOp) and isinstance(n.value.op, ast.Mult)
                 and isinstance(n.value.left, ast.Constant) and isinstance(n.value.right, ast.Constant)]
    assert not bare_prod, f"{len(bare_prod)} bare `C*C` junk assignments leaked (old bogus tell)"
