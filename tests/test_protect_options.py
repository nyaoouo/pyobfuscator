import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import ObfOptions, ModuleObfOptions


def test_pack_defaults_off():
    o = ObfOptions()
    assert o.pack_body is False
    assert o.pack_format == "auto"


def test_pack_inherited_by_module_options_and_settable():
    o = ModuleObfOptions(pack_body=True, pack_format="source")
    assert o.pack_body is True
    assert o.pack_format == "source"


def test_key_from_cff_default_off():
    from pyobfuscator import ObfOptions, ModuleObfOptions
    assert ObfOptions().key_from_cff is False
    assert ModuleObfOptions(key_from_cff=True).key_from_cff is True


def test_s2b_options():
    from pyobfuscator import ObfOptions, ModuleObfOptions
    assert ObfOptions().integrity_selfcheck is False
    assert ObfOptions().pack_decoy is False
    assert ObfOptions().key_binds_env is False
    assert ModuleObfOptions().decoy_src is None
    o = ModuleObfOptions(integrity_selfcheck=True, pack_decoy=True, decoy_src="X=1\n")
    assert o.integrity_selfcheck and o.pack_decoy and o.decoy_src == "X=1\n"


def test_detect_trace_default_off():
    from pyobfuscator import ObfOptions
    assert ObfOptions().detect_trace is False


def test_obf_imports_default_off():
    from pyobfuscator import ObfOptions
    assert ObfOptions().obf_imports is False
