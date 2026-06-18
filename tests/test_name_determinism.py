"""Gate 2 + gate 3 for the global-counter + final-seeded-rename naming fix.

DETERMINISM (validates the no-reset design): the global monotonic counter that Namer.fresh() draws
from is NEVER reset between builds, so the two calls below see DIFFERENT absolute counter values.
Determinism must therefore come ENTIRELY from the final seeded rename (cff/rename.finalize_names:
ast.walk first-appearance order + seed). So obf_module(src, ...same seed...) called twice in ONE
process must produce BYTE-IDENTICAL output despite the counter advancing in between.

NO TEMP LEAK: the final text output must contain no _pyobf_g<digits> monotonic temp names — every
one must have been renamed to a uniform _pyobf_<hex>.
"""
import re

import pytest

from pyobfuscator import obf_module, obf_func
from pyobfuscator.options import ModuleObfOptions, ObfOptions


_SRC = (
    "import json\n"
    "def acc(xs):\n"
    "    s = 0\n"
    "    for x in xs:\n"
    "        s += x * 2\n"
    "    return s\n"
    "def main():\n"
    "    total = acc([1, 2, 3])\n"
    "    print(json.dumps({\"t\": total, \"msg\": \"done\"}, sort_keys=True))\n"
    "main()\n"
)


_COMBOS = [
    dict(),
    dict(obf_strings=True, obf_ints=True, shuffle_states=True, opaque_predicates=True,
         bogus_blocks=True),
    dict(const_archive=True, name_vault=True, name_vault_attrs=True),
    dict(const_archive=True, name_vault=True, obf_strings=True, obf_ints=True,
         shuffle_states=True, bogus_blocks=True, opaque_predicates=True),
]


@pytest.mark.parametrize("extra", _COMBOS)
def test_obf_module_byte_identical_across_two_calls_same_process(extra):
    """Two builds with the same seed in one process are byte-identical even though the global
    counter advanced between them (proves determinism is from the rename, not the counter)."""
    opts1 = ModuleObfOptions(output="text", seed=7, min_blocks=1, **extra)
    out1 = obf_module(_SRC, opts1)
    # A second, intervening build with a DIFFERENT seed advances the global counter further, so the
    # third build below cannot accidentally reuse the same absolute counter values as the first.
    obf_module(_SRC, ModuleObfOptions(output="text", seed=999, min_blocks=1, **extra))
    opts2 = ModuleObfOptions(output="text", seed=7, min_blocks=1, **extra)
    out2 = obf_module(_SRC, opts2)
    assert out1 == out2


@pytest.mark.parametrize("extra", _COMBOS)
def test_no_temp_name_leak_in_output(extra):
    """Gate 3: no _pyobf_g<digits> temp name survives into the final text."""
    out = obf_module(_SRC, ModuleObfOptions(output="text", seed=7, min_blocks=1, **extra))
    leaks = re.findall(r"_pyobf_g\d+", out)
    assert not leaks, f"temp names leaked: {sorted(set(leaks))[:10]}"


def test_obf_func_byte_identical_and_no_leak():
    """obf_func path (no packer) is also deterministic + leak-free under the rename."""
    src = (
        "def f(a, b):\n"
        "    c = a + b\n"
        "    for i in range(b):\n"
        "        c += i\n"
        "    return c\n"
    )
    o1 = obf_func(src, ObfOptions(output="text", seed=3, min_blocks=1, obf_ints=True,
                                  bogus_blocks=True))
    obf_func(src, ObfOptions(output="text", seed=55, min_blocks=1, obf_ints=True,
                             bogus_blocks=True))
    o2 = obf_func(src, ObfOptions(output="text", seed=3, min_blocks=1, obf_ints=True,
                                  bogus_blocks=True))
    assert o1 == o2
    assert not re.findall(r"_pyobf_g\d+", o1)
