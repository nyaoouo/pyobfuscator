# tests/test_protect_s1_structure.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

SECRET_SRC = (
    "PASSWORD_PLAINTEXT_TOKEN = 'hunter2-zzz'\n"
    "def check(x):\n    return x == PASSWORD_PLAINTEXT_TOKEN\n"
    "def main():\n    pass\n"
)


def test_body_plaintext_absent_in_packed_text():
    out = obf_module(SECRET_SRC, ModuleObfOptions(output="text", min_blocks=1, seed=2, pack_body=True))
    # the obfuscated body is encrypted inside the blob; its identifiers/strings must not appear
    assert "PASSWORD_PLAINTEXT_TOKEN" not in out
    assert "hunter2-zzz" not in out


def test_launcher_is_standalone():
    out = obf_module(SECRET_SRC, ModuleObfOptions(output="text", min_blocks=1, seed=2, pack_body=True))
    assert "pyobfuscator" not in out      # no dependency on this package at runtime
    assert "exec(" in out                 # decrypt+exec launcher present
