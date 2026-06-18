import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_func, ObfOptions

# no string/int literals -> the only `== <int>` and state assignments are dispatcher states
SRC = "def f(x):\n    if x:\n        y = x + x\n        return y\n    return x\n"


def _run(out):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return ns["f"]


def test_shuffle_off_is_sequential():
    # isolate the shuffle feature: disable opaque/bogus so `== N` reflects only state ids
    off = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=False,
                                   opaque_predicates=False, bogus_blocks=False, obf_strings=False))
    assert "== 0" in off  # sequential ids when shuffling is off
    f = _run(off)
    assert f(3) == 6 and f(0) == 0


def test_shuffle_on_randomizes_and_preserves_behavior():
    # isolate shuffle (opaque predicates inject `% 2 == 0`, which would otherwise add `== 0`)
    on = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=True,
                                  opaque_predicates=False, bogus_blocks=False,
                                  obf_strings=False, seed=0))
    assert "== 0" not in on  # state ids remapped to large ints
    labels = [int(m) for m in re.findall(r"== (\d+)", on)]
    assert labels and min(labels) >= 1000
    f = _run(on)
    assert f(3) == 6 and f(0) == 0


def test_shuffle_changes_output_and_is_deterministic():
    a = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=True, seed=5))
    b = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=True, seed=5))
    c = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=True, seed=6))
    off = obf_func(SRC, ObfOptions(output="text", min_blocks=1, shuffle_states=False))
    assert a == b           # same seed -> identical (reproducible)
    assert a != c           # different seed -> different labels/order
    assert a != off         # shuffling changes the output


def test_exception_routing_survives_shuffle():
    src = ("def f(a, b):\n    try:\n        return a // b\n"
           "    except ZeroDivisionError:\n        return -1\n")
    for seed in (0, 1, 2, 7):
        out = obf_func(src, ObfOptions(output="text", min_blocks=1, seed=seed))
        f = _run(out)
        assert f(6, 2) == 3 and f(6, 0) == -1
