# tests/test_protect_s2a_structure.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

SRC = "SECRET = 'zzz-token-9'\ndef ok(x):\n    return x == SECRET\ndef main():\n    pass\n"


def test_cff_no_temp_key_and_no_secret():
    out = obf_module(SRC, ModuleObfOptions(output="text", seed=2, min_blocks=1,
                                           pack_body=True, key_from_cff=True))
    assert "0xa5a5a5a5a5a5a5a5" not in out.lower()  # temporary key absent
    assert "SECRET" not in out and "zzz-token-9" not in out
    assert "pyobfuscator" not in out               # standalone


def test_cff_two_seeds_both_run():
    # Different builds (different internal fold) must each self-consistently decrypt + run.
    for seed in (1, 7):
        out = obf_module(SRC, ModuleObfOptions(output="text", seed=seed, min_blocks=1,
                                               pack_body=True, key_from_cff=True))
        ns = {"__name__": "m"}
        exec(compile(out, "<t>", "exec"), ns)
        assert ns["ok"]("zzz-token-9") is True and ns["ok"]("x") is False
