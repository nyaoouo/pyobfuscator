import sys, os, ast, marshal
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions


def _exec(code, name="modtest"):
    ns = {"__name__": name}
    exec(code, ns)
    return ns


def _toplevel_has_while(out):
    return any(isinstance(n, ast.While) for n in ast.parse(out).body)


MOD_CF = (
    "import sys\n"
    "RESULTS = []\n"
    "for i in range(3):\n"
    "    if i % 2 == 0:\n        RESULTS.append(('even', i))\n"
    "    else:\n        RESULTS.append(('odd', i))\n"
    "def get():\n    return list(RESULTS)\n"
    "CONFIG = {'count': len(RESULTS)}\n"
)


@pytest.mark.parametrize("seed", [0, 3, 19])
def test_module_body_wrapped_and_equivalent(seed):
    out = obf_module(MOD_CF, ModuleObfOptions(output="text", seed=seed, min_blocks=1))
    assert _toplevel_has_while(out)  # the module body itself became a dispatcher
    orig = _exec(compile(MOD_CF, "<o>", "exec"))
    obf = _exec(compile(out, "<t>", "exec"))
    assert orig["RESULTS"] == obf["RESULTS"]
    assert orig["get"]() == obf["get"]()
    assert orig["CONFIG"] == obf["CONFIG"]


def test_future_import_and_docstring_preserved():
    src = (
        "'''module doc'''\n"
        "from __future__ import annotations\n"
        "VALUE = 0\n"
        "for i in range(5):\n    VALUE += i\n"
        "def total():\n    return VALUE\n"
    )
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    parsed = ast.parse(out)
    assert ast.get_docstring(parsed) == "module doc"
    assert any(isinstance(n, ast.ImportFrom) and n.module == "__future__"
               for n in parsed.body[:2])
    ns = _exec(compile(out, "<t>", "exec"))
    assert ns["VALUE"] == 10 and ns["total"]() == 10


@pytest.mark.parametrize("modname,called", [("__main__", True), ("imported", False)])
def test_name_guard(modname, called):
    src = (
        "LOG = []\n"
        "def main():\n    LOG.append('ran')\n    return 'done'\n"
        "if __name__ == '__main__':\n    main()\n"
    )
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    orig = _exec(compile(src, "<o>", "exec"), name=modname)
    obf = _exec(compile(out, "<t>", "exec"), name=modname)
    assert orig["LOG"] == obf["LOG"]
    assert obf["LOG"] == (["ran"] if called else [])


def test_optional_import_pattern():
    src = (
        "try:\n    import ujson_missing_xyz as J\n    BACKEND = 'ujson'\n"
        "except ImportError:\n    import json as J\n    BACKEND = 'json'\n"
        "def dumps(obj):\n    return J.dumps(obj)\n"
    )
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    ns = _exec(compile(out, "<t>", "exec"))
    assert ns["BACKEND"] == "json" and ns["dumps"]({"a": 1}) == '{"a": 1}'


def test_module_wrap_pyc_equivalent():
    blob = obf_module(MOD_CF, ModuleObfOptions(output="pyc", seed=4, min_blocks=1))
    code = marshal.loads(blob[16:])
    orig = _exec(compile(MOD_CF, "<o>", "exec"))
    obf = _exec(code)
    assert orig["RESULTS"] == obf["RESULTS"] and orig["CONFIG"] == obf["CONFIG"]
