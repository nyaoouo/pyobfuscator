import sys, os, ast, marshal
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

MOD = (
    "import math\n"
    "from collections import OrderedDict\n"
    "PI = 3.14\n"
    "def area(r):\n"
    "    if r < 0:\n        raise ValueError('neg')\n"
    "    return PI * r * r\n"
    "class Circle:\n"
    "    def __init__(self, r):\n        self.r = r\n"
    "    def area(self):\n        total = 0.0\n        for _ in range(1):\n            total += PI * self.r * self.r\n        return total\n"
)


def _exec(code, name="modtest"):
    ns = {"__name__": name}
    exec(code, ns)
    return ns


def _probe(ns):
    return (round(ns["area"](2.0), 4), round(ns["Circle"](3.0).area(), 4),
            ns["PI"], "OrderedDict" in ns, "math" in ns)


@pytest.mark.parametrize("seed", [0, 5])
def test_module_funcs_classes_flattened_and_behavior_preserved(seed):
    out = obf_module(MOD, ModuleObfOptions(output="text", seed=seed, min_blocks=1))
    assert "while True" in out  # methods/funcs flattened
    orig = _exec(compile(MOD, "<o>", "exec"))
    obf = _exec(compile(out, "<t>", "exec"))
    assert _probe(orig) == _probe(obf)


def test_module_interface_preserved():
    out = obf_module(MOD, ModuleObfOptions(output="text", min_blocks=1))
    ns = _exec(compile(out, "<t>", "exec"))
    assert callable(ns["area"]) and isinstance(ns["Circle"], type)
    assert ns["area"](2.0) == pytest.approx(3.14 * 4)


def test_module_pyc_path():
    blob = obf_module(MOD, ModuleObfOptions(output="pyc", seed=2, min_blocks=1))
    code = marshal.loads(blob[16:])
    ns = _exec(code)
    assert ns["Circle"](2.0).area() == pytest.approx(3.14 * 4)


def test_module_mutual_recursion_top_level():
    src = (
        "def is_even(n):\n    if n == 0:\n        return True\n    return is_odd(n - 1)\n"
        "def is_odd(n):\n    if n == 0:\n        return False\n    return is_even(n - 1)\n"
    )
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    ns = _exec(compile(out, "<t>", "exec"))
    assert ns["is_even"](10) is True and ns["is_even"](7) is False


def test_module_import_error_propagates():
    src = "import this_module_does_not_exist_xyz\nVALUE = 1\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    with pytest.raises(ModuleNotFoundError):
        _exec(compile(out, "<t>", "exec"))
