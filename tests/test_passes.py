import ast
import pytest

from pyobfuscator.cff.passes.base import Pass, Pipeline, register, get, all_passes
from pyobfuscator.cff.gate import SupportSet
from pyobfuscator.options import ObfOptions, UnsupportedPolicy
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


class TagPass:
    """A no-op pass that records that it ran."""
    name = "tag"

    def __init__(self):
        self.ran = False

    def supports(self):
        return SupportSet(allowed=frozenset({
            ast.FunctionDef, ast.Return, ast.Constant,
        }))

    def transform(self, tree, options):
        self.ran = True
        return tree


def test_empty_pipeline_is_passthrough():
    tree = ast.parse("def f():\n    return 1\n")
    out = Pipeline(()).run(tree, ObfOptions())
    assert out is tree


def test_pipeline_runs_pass():
    p = TagPass()
    tree = ast.parse("def f():\n    return 1\n")
    Pipeline([p]).run(tree, ObfOptions())
    assert p.ran is True


def test_pipeline_enforces_support_before_transform():
    p = TagPass()  # does not support Yield
    tree = ast.parse("def f():\n    yield 1\n")
    with pytest.raises(UnsupportedConstructError):
        Pipeline([p]).run(tree, ObfOptions())
    assert p.ran is False


def test_registry_roundtrip():
    p = TagPass()
    register(p)
    assert get("tag") is p
    assert "tag" in all_passes()
