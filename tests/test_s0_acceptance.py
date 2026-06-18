import ast
import marshal
import pytest

from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.gate import SupportSet, enforce
from pyobfuscator.options import UnsupportedPolicy
from pyobfuscator.cff.diagnostics import UnsupportedConstructError
from equivalence import observe, assert_func_equivalent

CORPUS = [
    ("def a(x):\n    return x + 1\n", "a", [((1,), {}), ((-3,), {})]),
    ("def b(x, y):\n    if x > y:\n        return x\n    return y\n", "b",
     [((1, 2), {}), ((5, 0), {})]),
    ("def c(n):\n    t = 0\n    for i in range(n):\n        t += i\n    return t\n",
     "c", [((0,), {}), ((5,), {})]),
    ("def d(n):\n    while n > 0:\n        n -= 1\n    return n\n", "d",
     [((3,), {}), ((0,), {})]),
]


@pytest.mark.parametrize("src,name,batteries", CORPUS)
@pytest.mark.parametrize("fmt", ["text", "ast", "pyc"])
def test_corpus_roundtrips_equivalently(src, name, batteries, fmt):
    out = obf_func(src, ObfOptions(output=fmt))

    def factory():
        if fmt == "text":
            code = compile(out, "<acc>", "exec")
        elif fmt == "ast":
            code = compile(out, "<acc>", "exec")
        else:  # pyc
            code = marshal.loads(out[16:])
        ns = {}
        exec(code, ns)
        return ns[name]

    assert_func_equivalent(src, factory, name, batteries)


def test_gate_rejects_curated_unsupported_with_all_diagnostics():
    # Allowlist deliberately excludes yield/async/lambda.
    support = SupportSet(allowed=frozenset({
        ast.FunctionDef, ast.Return, ast.Constant, ast.Name, ast.BinOp,
        ast.arguments, ast.arg,
    }))
    src = "def f():\n    yield 1\n    x = (lambda: 2)\n    yield 3\n"
    with pytest.raises(UnsupportedConstructError) as ei:
        enforce(ast.parse(src), support, UnsupportedPolicy.STRICT)
    node_types = {d.node_type for d in ei.value.diagnostics}
    assert {"Yield", "Lambda"} <= node_types
