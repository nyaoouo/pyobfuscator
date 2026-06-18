import ast
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from pyobfuscator import obf_func
from pyobfuscator.cff.passes.flatten import FlattenPass
from pyobfuscator.cff.passes.base import Pipeline
from pyobfuscator.options import ObfOptions, UnsupportedPolicy
from pyobfuscator.cff.diagnostics import UnsupportedConstructError
from equivalence import assert_func_equivalent


def _run(src, seed=0):
    tree = ast.parse(src)
    Pipeline([FlattenPass()]).run(tree, ObfOptions(seed=seed))
    return tree


def test_flatten_changes_body_but_preserves_behavior():
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    tree = _run(src)
    # body is now a state machine: first statement assigns the state var
    fn = tree.body[0]
    assert isinstance(fn.body[0], ast.Assign)
    assert isinstance(fn.body[-1], ast.While)

    def factory():
        ns = {}
        exec(compile(tree, "<f>", "exec"), ns)
        return ns["f"]
    assert_func_equivalent(src, factory, "f", [((1,), {}), ((0,), {})])


@pytest.mark.parametrize("bad,needle", [
    ("def f():\n    yield 1\n", "Yield"),
    ("def f():\n    async def g():\n        pass\n", "AsyncFunctionDef"),
    ("def f(x):\n    match x:\n        case 1:\n            return 1\n", "Match"),
])
def test_gate_rejects_unsupported(bad, needle):
    with pytest.raises(UnsupportedConstructError) as ei:
        _run(bad)
    assert any(needle == d.node_type for d in ei.value.diagnostics)


def test_nested_def_now_supported():
    src = "def f():\n    def g():\n        return 1\n    return g()\n"
    out = obf_func(src, ObfOptions(output="text"))
    ns = {}
    exec(compile(out, "<n>", "exec"), ns)
    assert ns["f"]() == 1
