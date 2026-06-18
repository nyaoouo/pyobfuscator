import ast
import pytest

from pyobfuscator.cff.emit import emit, normalize_locations
from pyobfuscator.options import ObfOptions, OutputFormat

SRC = "def f(a, b):\n    return a + b\n"


def test_emit_text_roundtrips_executably():
    text = emit(ast.parse(SRC), ObfOptions(output="text"))
    assert isinstance(text, str)
    ns = {}
    exec(compile(text, "<t>", "exec"), ns)
    assert ns["f"](2, 3) == 5


def test_emit_ast_returns_module():
    tree = ast.parse(SRC)
    out = emit(tree, ObfOptions(output="ast"))
    assert isinstance(out, ast.Module)


def test_strip_debug_normalizes_locations_for_ast():
    tree = ast.parse(SRC)
    out = emit(tree, ObfOptions(output="ast", strip_debug=True))
    linenos = {getattr(n, "lineno", 1) for n in ast.walk(out) if hasattr(n, "lineno")}
    assert linenos == {1}


def test_normalize_locations_is_compilable():
    tree = normalize_locations(ast.parse(SRC))
    code = compile(tree, "<n>", "exec")
    ns = {}
    exec(code, ns)
    assert ns["f"](1, 1) == 2


import marshal
import importlib.util


def _load_func_from_pyc(pyc: bytes, name: str):
    # Header is 16 bytes: 4 magic + 4 flags + 8 source-hash.
    code = marshal.loads(pyc[16:])
    ns = {}
    exec(code, ns)
    return ns[name]


def test_emit_pyc_has_valid_header_and_executes():
    pyc = emit(ast.parse(SRC), ObfOptions(output="pyc"))
    assert isinstance(pyc, (bytes, bytearray))
    assert pyc[:4] == importlib.util.MAGIC_NUMBER
    f = _load_func_from_pyc(pyc, "f")
    assert f(4, 5) == 9


def test_emit_pyc_flags_are_hash_based_unchecked():
    import struct
    pyc = emit(ast.parse(SRC), ObfOptions(output="pyc"))
    (flags,) = struct.unpack("<I", pyc[4:8])
    assert flags == 0b01  # hash-based, check_source unset


def test_emit_pyc_strip_debug_sets_obf_filename():
    pyc = emit(ast.parse(SRC), ObfOptions(output="pyc", strip_debug=True))
    code = marshal.loads(pyc[16:])
    assert code.co_filename == "<obf>"
