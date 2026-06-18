import sys, os, marshal
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

FULL = dict(min_blocks=1, obf_strings=True, obf_ints=True, shuffle_states=True,
            opaque_predicates=True, bogus_blocks=True, slot_vars=True, stack_calls=True,
            hide_external_args=True, split_calls=True, return_var=True, dedup=True,
            state_delta=True, dispatch_tree=True, junk_code=True, dict_indirect=True,
            pack_body=True, key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
            detect_trace=True, key_binds_env=True, obf_imports=True)

def _lt(src, name):
    ns = {"__name__": name}; exec(compile(src, "<t>", "exec"), ns); return ns
def _lp(blob, name):
    ns = {"__name__": name}; exec(marshal.loads(blob[16:]), ns); return ns

MOD = ("R = [i * 2 for i in range(5)]\n"
       "def s():\n    return sum(R)\n"
       "C = {'n': len(R)}\n")

@pytest.mark.parametrize("seed", [0, 5, 19])
def test_s4_text_equiv_and_no_import_literal(seed):
    out = obf_module(MOD, ModuleObfOptions(output="text", seed=seed, **FULL))
    assert "import marshal" not in out and "import sys" not in out
    o = _lt(MOD, "m"); g = _lt(out, "m")
    assert o["R"] == g["R"] and o["s"]() == g["s"]() and o["C"] == g["C"]
    assert "__pyobf_decoy__" not in g

def test_s4_pyc_equiv():
    blob = obf_module(MOD, ModuleObfOptions(output="pyc", seed=5, **FULL))
    o = _lt(MOD, "m"); g = _lp(blob, "m")
    assert o["R"] == g["R"] and o["C"] == g["C"] and "__pyobf_decoy__" not in g
