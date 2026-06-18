import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _run(out, name="f"):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return ns[name]


def _opts(**kw):
    base = dict(output="text", min_blocks=1, slot_vars=True, obf_strings=False,
                shuffle_states=False, opaque_predicates=False, bogus_blocks=False)
    base.update(kw)
    return ObfOptions(**base)


def test_simple_locals_slotted_and_correct():
    src = "def f(n):\n    acc = 0\n    step = 2\n    acc = acc + n * step\n    return acc\n"
    out = obf_func(src, _opts())
    import re
    assert re.search(r"_pyobf_[0-9a-f]+\[0\]", out)  # locals mapped to a `_pyobf_<hex>[i]` slot list
    assert "acc" not in out and "step" not in out  # names hidden (params/keywords aside)
    f = _run(out)
    assert f(5) == 10 and f(0) == 0


def test_slot_off_by_default():
    src = "def f(n):\n    acc = n + 1\n    return acc\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, obf_strings=False,
                                   shuffle_states=False, opaque_predicates=False, bogus_blocks=False))
    # default slot_vars=False -> the local is NOT mapped to a `_slots[i]` subscript. (LocalRenamePass
    # still renames the local identifier away unconditionally, so we can't assert the plaintext name
    # survives; instead assert the slot SUBSCRIPT form is absent — the precise thing slot_vars adds.)
    import re
    assert not re.search(r"_pyobf_[0-9a-f]+\[\d+\]", out)


def test_closure_captured_local_not_slotted():
    # `base` is captured by `inner` -> rule 4 excludes it -> closure preserved
    src = ("def f(x):\n    base = x * 10\n"
           "    def inner(y):\n        return base + y\n"
           "    return inner(5)\n")
    out = obf_func(src, _opts())
    f = _run(out)
    assert f(2) == 25


def test_comprehension_local_not_slotted():
    # `factor` used inside a comprehension -> excluded; behavior preserved
    src = ("def f(items):\n    factor = 3\n    total = 0\n    total = sum(v * factor for v in items)\n    return total\n")
    out = obf_func(src, _opts())
    f = _run(out)
    assert f([1, 2, 3]) == 18


def test_for_with_except_targets_not_slotted():
    src = ("def f(seq):\n    out = []\n    for i in seq:\n        try:\n            out.append(10 // i)\n"
           "        except ZeroDivisionError as e:\n            out.append(str(e.__class__.__name__))\n    return out\n")
    out = obf_func(src, _opts())
    f = _run(out)
    assert f([2, 0, 5]) == [5, "ZeroDivisionError", 2]


def test_recursion_and_params():
    src = "def f(n):\n    acc = 1\n    if n <= 1:\n        return acc\n    return n * f(n - 1)\n"
    out = obf_func(src, _opts())
    f = _run(out)
    assert f(5) == 120 and f(1) == 1


def test_method_locals_slotted_module_names_not():
    src = ("BASE = 100\n"
           "class C:\n    def calc(self, x):\n        local = x + 1\n        local = local * 2\n        return local + BASE\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, slot_vars=True,
                                           obf_strings=False, shuffle_states=False,
                                           opaque_predicates=False, bogus_blocks=False))
    assert "BASE" in out  # module-level name preserved (interface)
    ns = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["C"]().calc(4) == 110 and ns["BASE"] == 100


@pytest.mark.parametrize("seed", [0, 1, 7, 23])
def test_slotvar_full_strength_equivalence(seed):
    src = ("def f(n):\n    total = 0\n    scratch = n\n    for i in range(n):\n        scratch = scratch + i\n"
           "        total = total + scratch\n    try:\n        return total // n\n"
           "    except ZeroDivisionError:\n        return total\n")
    ns_o = {}
    exec(compile(src, "<o>", "exec"), ns_o)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, slot_vars=True, obf_ints=True))
    ns_t = {}
    exec(compile(out, "<t>", "exec"), ns_t)
    for n in (0, 1, 5):
        assert ns_o["f"](n) == ns_t["f"](n)


def test_slotvar_del_local():
    src = "def f():\n    tmp = 5\n    val = tmp * 2\n    del tmp\n    return val\n"
    out = obf_func(src, _opts())
    f = _run(out)
    assert f() == 10
