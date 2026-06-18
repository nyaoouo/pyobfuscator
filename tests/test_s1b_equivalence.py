import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions


def _mk(src, name, seed):
    nso = {}; exec(compile(src, "<o>", "exec"), nso)
    out = obf_func(src, ObfOptions(output="text", seed=seed))
    nsf = {}; exec(compile(out, "<f>", "exec"), nsf)
    return nso[name], nsf[name]


SEEDS = [0, 1, 13, 99]


@pytest.mark.parametrize("seed", SEEDS)
def test_multi_closure_shared_read(seed):
    src = ("def make_pair(n):\n"
           "    def getter():\n"
           "        return n\n"
           "    def doubled():\n"
           "        return n * 2\n"
           "    return getter, doubled\n")
    o, f = _mk(src, "make_pair", seed)
    og, od = o(7); fg, fd = f(7)
    assert (og(), od()) == (fg(), fd()) == (7, 14)


@pytest.mark.parametrize("seed", SEEDS)
def test_nested_def_in_for_with_default_capture(seed):
    src = ("def make_fns(n):\n"
           "    fns = []\n"
           "    for i in range(n):\n"
           "        def g(i=i):\n"
           "            return i * i\n"
           "        fns.append(g)\n"
           "    return fns\n")
    o, f = _mk(src, "make_fns", seed)
    of = o(4); ff = f(4)
    assert [x() for x in of] == [x() for x in ff] == [0, 1, 4, 9]


@pytest.mark.parametrize("seed", SEEDS)
def test_closure_with_branching_and_loop(seed):
    src = ("def build(threshold):\n"
           "    def classify(xs):\n"
           "        hi = []\n"
           "        lo = []\n"
           "        for x in xs:\n"
           "            if x >= threshold:\n"
           "                hi.append(x)\n"
           "            else:\n"
           "                lo.append(x)\n"
           "        return hi, lo\n"
           "    return classify\n")
    o, f = _mk(src, "build", seed)
    oc = o(5); fc = f(5)
    data = [1, 7, 5, 3, 9, 5]
    assert oc(data) == fc(data) == ([7, 5, 9, 5], [1, 3])
