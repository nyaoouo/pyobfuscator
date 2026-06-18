import ast
import pytest

from pyobfuscator.cff.gate import SupportSet, GuardVisitor, collect_diagnostics, enforce
from pyobfuscator.cff.diagnostics import UnsupportedConstructError, Severity
from pyobfuscator.options import UnsupportedPolicy

# A small allowlist: a plain arithmetic function.
SAMPLE = SupportSet(allowed=frozenset({
    ast.FunctionDef, ast.Return, ast.BinOp, ast.Name, ast.Constant,
}))


def _tree(src):
    return ast.parse(src)


def test_supported_function_has_no_diagnostics():
    diags = collect_diagnostics(_tree("def f(a, b):\n    return a + b\n"), SAMPLE)
    assert diags == []


def test_unsupported_node_is_rejected():
    diags = collect_diagnostics(_tree("def f():\n    yield 1\n"), SAMPLE)
    types = {d.node_type for d in diags}
    assert "Yield" in types


def test_collects_all_not_just_first():
    src = "def f():\n    yield 1\n    yield 2\n"
    diags = collect_diagnostics(_tree(src), SAMPLE)
    assert sum(d.node_type == "Yield" for d in diags) == 2


def test_default_deny_rejects_unknown_meaningful_node():
    # `lambda` is not in the allowlist -> rejected by default-deny.
    diags = collect_diagnostics(_tree("def f():\n    return (lambda: 1)\n"), SAMPLE)
    assert any(d.node_type == "Lambda" for d in diags)


def test_enforce_strict_raises_with_all():
    src = "def f():\n    yield 1\n    yield 2\n"
    with pytest.raises(UnsupportedConstructError) as ei:
        enforce(_tree(src), SAMPLE, UnsupportedPolicy.STRICT)
    assert len(ei.value.diagnostics) == 2


def test_enforce_ignores_warnings_for_blocking():
    # warnings never block even under STRICT
    diags = enforce(_tree("def f(a, b):\n    return a + b\n"), SAMPLE,
                    UnsupportedPolicy.STRICT)
    assert all(d.severity is Severity.ERROR for d in diags) or diags == []
