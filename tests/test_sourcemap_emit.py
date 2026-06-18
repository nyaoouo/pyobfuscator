"""emit_sourcemap flag + emit/obf_module hook.

Flag OFF => no map even if a sink is passed, output byte-identical. Flag ON => sink populated with
the layer map, output STILL byte-identical (the map is a pure side channel).
"""
import re

from pyobfuscator import obf_module, obf_func
from pyobfuscator.options import ModuleObfOptions, ObfOptions, OutputFormat

SRC = (
    "def f(x):\n"
    "    y = 0\n"
    "    for i in range(x):\n"
    "        if i % 2 == 0:\n"
    "            y += i * 3\n"
    "        else:\n"
    "            y -= i\n"
    "    return y\n"
    "\n"
    "def g(a, b):\n"
    "    return f(a) + b\n"
    "\n"
    "total = 0\n"                      # top-level control flow -> module body gets a dispatcher
    "for k in range(3):\n"
    "    total = g(k, 1)\n"
    "if total > 0:\n"
    "    total = -total\n"
)

_HEX = re.compile(r"(?<![\w])_pyobf_[0-9a-f]+(?![\w])")


def _opts(**kw):
    return ModuleObfOptions(output=OutputFormat.TEXT, seed=5, **kw)


def test_flag_off_no_map_even_with_sink():
    a = obf_module(SRC, _opts())
    sink: dict = {}
    b = obf_module(SRC, _opts(), sourcemap_out=sink)
    assert a == b
    assert sink == {}            # flag off -> sink untouched


def test_flag_on_preserves_output_and_populates_sink():
    a = obf_module(SRC, _opts())                       # baseline, no map
    sink: dict = {}
    b = obf_module(SRC, _opts(emit_sourcemap=True), sourcemap_out=sink)
    assert a == b                                       # the map must NOT perturb the output
    assert "module" in sink
    m = sink["module"]
    assert m["format"] == "pyobfuscator-sourcemap/1"
    assert m["layer"] == "module"
    assert m["names"] and m["scopes"]


def test_emit_map_name_completeness():
    sink: dict = {}
    out = obf_module(SRC, _opts(emit_sourcemap=True), sourcemap_out=sink)
    used = set(_HEX.findall(out))
    assert used, "output has generated names"
    assert used <= set(sink["module"]["names"]), "every output hex name is mapped"


def test_scopes_cover_functions_and_module():
    sink: dict = {}
    obf_module(SRC, _opts(emit_sourcemap=True), sourcemap_out=sink)
    scopes = sink["module"]["scopes"]
    assert "<module>" in scopes                         # module body dispatcher
    # at least one function scope besides the module
    assert any(k != "<module>" for k in scopes)


def test_obf_func_layer():
    sink: dict = {}
    obf_func("def f(x):\n    y = x + 1\n    if y > 2:\n        return y\n    return -y\n",
             ObfOptions(output=OutputFormat.TEXT, seed=5, emit_sourcemap=True), sourcemap_out=sink)
    assert "function" in sink
    assert sink["function"]["layer"] == "function"
