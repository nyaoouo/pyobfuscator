# tests/test_protect_s2a_equivalence.py
import sys, os, io, marshal, contextlib, builtins
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

FULL = dict(min_blocks=1, obf_strings=True, obf_ints=True, shuffle_states=True,
            opaque_predicates=True, bogus_blocks=True, slot_vars=True, stack_calls=True,
            hide_external_args=True, split_calls=True, return_var=True, dedup=True,
            state_delta=True, dispatch_tree=True, junk_code=True, dict_indirect=True,
            pack_body=True, key_from_cff=True)


def _load_text(src, name):
    ns = {"__name__": name}; exec(compile(src, "<t>", "exec"), ns); return ns


def _load_pyc(blob, name):
    ns = {"__name__": name}; exec(marshal.loads(blob[16:]), ns); return ns


MOD = ("RESULTS = []\n"
       "for i in range(5):\n    RESULTS.append((i, i * i))\n"
       "def summary():\n    return sum(b for _, b in RESULTS)\n"
       "CFG = {'n': len(RESULTS)}\n")


@pytest.mark.parametrize("seed", [0, 11, 31])
def test_cff_module_text_equivalent(seed):
    out = obf_module(MOD, ModuleObfOptions(output="text", seed=seed, **FULL))
    orig = _load_text(MOD, "m"); obf = _load_text(out, "m")
    assert orig["RESULTS"] == obf["RESULTS"]
    assert orig["summary"]() == obf["summary"]()
    assert orig["CFG"] == obf["CFG"]


def test_cff_module_pyc_equivalent():
    blob = obf_module(MOD, ModuleObfOptions(output="pyc", seed=11, **FULL))
    orig = _load_text(MOD, "m"); obf = _load_pyc(blob, "m")
    assert orig["RESULTS"] == obf["RESULTS"] and orig["CFG"] == obf["CFG"]


ENTRY = ("import sys\n"
         "def check(k):\n    return k == 'sesame'\n"
         "def main():\n"
         "    if len(sys.argv) > 1:\n"
         "        sys.exit(0 if check(sys.argv[1]) else 1)\n"
         "    else:\n        print('Y' if check(input()) else 'N')\n"
         "if __name__ == '__main__':\n    main()\n")


def _argv(ns, key):
    buf = io.StringIO(); old = sys.argv; sys.argv = ["e", key]; code = None
    try:
        with contextlib.redirect_stdout(buf):
            try:
                ns["main"]()
            except SystemExit as e:
                code = e.code if e.code is not None else 0
    finally:
        sys.argv = old
    return buf.getvalue(), code


def test_cff_entry_argv_text_and_pyc():
    text = obf_module(ENTRY, ModuleObfOptions(output="text", seed=9, **FULL))
    pyc = obf_module(ENTRY, ModuleObfOptions(output="pyc", seed=9, **FULL))
    for key in ("sesame", "nope"):
        r = _argv(_load_text(ENTRY, "ref"), key)
        t = _argv(_load_text(text, "txt"), key)
        p = _argv(_load_pyc(pyc, "pyc"), key)
        assert r == t == p, (key, r, t, p)
