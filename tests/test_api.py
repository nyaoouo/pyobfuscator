import ast
import marshal
import os
import subprocess
import sys
import pytest

from pyobfuscator import (obf_func, obf_module, ObfOptions, ModuleObfOptions,
                          cache_tag, sourceless_pyc_name)

FUNC = "def add(a, b):\n    return a + b\n"
MOD = "X = 10\n\ndef get():\n    return X\n"


def test_obf_func_text_default_passthrough():
    out = obf_func(FUNC, ObfOptions(output="text"))
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["add"](2, 2) == 4


def test_obf_func_ast():
    out = obf_func(FUNC, ObfOptions(output="ast"))
    assert isinstance(out, ast.Module)


def test_obf_func_pyc():
    out = obf_func(FUNC, ObfOptions(output="pyc"))
    code = marshal.loads(out[16:])
    ns = {}
    exec(code, ns)
    assert ns["add"](7, 8) == 15


def test_obf_func_accepts_ast_input():
    tree = ast.parse(FUNC)
    out = obf_func(tree, ObfOptions(output="text"))
    # flattened, so the literal body is gone — verify behavior instead
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["add"](2, 3) == 5


def test_obf_module_text_passthrough():
    out = obf_module(MOD, ModuleObfOptions(output="text"))
    ns = {}
    exec(compile(out, "<m>", "exec"), ns)
    assert ns["get"]() == 10


def test_obf_func_defaults_to_pyc_bytes():
    out = obf_func(FUNC)
    assert isinstance(out, (bytes, bytearray))


def test_trivial_straightline_not_flattened_by_default():
    # 1 block (no control flow) -> left unobfuscated under default min_blocks=2
    src = "def f(x):\n    y = x + 1\n    return y\n"
    out = obf_func(src, ObfOptions(output="text"))
    assert "while True" not in out
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["f"](4) == 5


def test_min_blocks_one_forces_flattening_of_straightline():
    src = "def f(x):\n    y = x + 1\n    return y\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1))
    assert "while True" in out
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["f"](4) == 5


def test_control_flow_is_flattened_by_default():
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"  # >= 3 blocks
    out = obf_func(src, ObfOptions(output="text"))
    assert "while True" in out


# ---- sourceless pyc naming helpers (Part 1a) ----

def test_cache_tag_matches_interpreter():
    assert cache_tag() == sys.implementation.cache_tag
    assert cache_tag().startswith("cpython-")


def test_sourceless_pyc_name():
    assert sourceless_pyc_name("ctf_test_obf") == "ctf_test_obf.pyc"          # bare = importable
    assert sourceless_pyc_name("m", tagged=True) == "m.%s.pyc" % cache_tag()  # cache-style


def test_bare_pyc_imports_and_runs(tmp_path):
    """The output='pyc' bytes, written to sourceless_pyc_name(module), are BOTH importable as a bare
    sourceless module AND runnable via `python <module>.pyc`."""
    src = "VALUE = 41 + 1\ndef hello():\n    return 'hi'\nimport sys\nif __name__=='__main__':\n    print(hello())\n"
    pyc = obf_module(src, ModuleObfOptions(output="pyc", seed=1, min_blocks=1))
    name = "modX"
    p = tmp_path / sourceless_pyc_name(name)
    p.write_bytes(bytes(pyc))
    # (1) bare import
    r = subprocess.run([sys.executable, "-c",
                        "import sys; sys.path.insert(0, %r); import %s as m; print(m.VALUE, m.hello())"
                        % (str(tmp_path), name)], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "42 hi", (r.stdout, r.stderr)
    # (2) python <module>.pyc
    r2 = subprocess.run([sys.executable, str(p)], capture_output=True, text=True)
    assert r2.returncode == 0 and r2.stdout.strip() == "hi", (r2.stdout, r2.stderr)
