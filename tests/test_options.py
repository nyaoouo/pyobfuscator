import pytest
from pyobfuscator.options import (
    OutputFormat, UnsupportedPolicy, ObfOptions, ModuleObfOptions,
)


def test_defaults():
    o = ObfOptions()
    assert o.output is OutputFormat.PYC
    assert o.strip_debug is False
    assert o.on_unsupported is UnsupportedPolicy.STRICT
    assert o.seed is None
    assert o.max_block_stmts is None


def test_output_accepts_string():
    o = ObfOptions(output="text")
    assert o.output is OutputFormat.TEXT


def test_module_options_extends_base():
    m = ModuleObfOptions(output="ast")
    assert m.output is OutputFormat.AST
    assert m.emit_pyi is False
    assert m.single_file_interface is False
    assert m.exports == []
    assert m.exports_from_all is True
    # subclass still carries base fields
    assert m.on_unsupported is UnsupportedPolicy.STRICT


def test_exports_is_independent_per_instance():
    a = ModuleObfOptions()
    b = ModuleObfOptions()
    a.exports.append("foo")
    assert b.exports == []
