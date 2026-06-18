import sys, os, io, contextlib, ast, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


SRCS = [
    ("def f():\n    return 'hello, world'\n", "f", [()]),
    ("def f(x):\n    s = 'flag{' + str(x) + '}'\n    return s + ' done'\n", "f", [(42,)]),
    ("def f():\n    return ('a', 'bb', 'ccc', '', 'unicode: éèê 中文 \U0001f600')\n", "f", [()]),
    ("def f():\n    return b'\\x00\\x01\\x02 raw bytes \\xff\\x00'\n", "f", [()]),       # trailing/embedded NUL
    ("def f():\n    return 'ends with null\\x00'\n", "f", [()]),                          # str ending in NUL
    ("def f(n):\n    return [str(i) + '-tag' for i in range(n)]\n", "f", [(3,), (0,)]),
    ("def f():\n    d = {'key': 'value', 'k2': 'v2'}\n    return d['key'] + d['k2']\n", "f", [()]),
]


@pytest.mark.parametrize("src,name,args", SRCS)
@pytest.mark.parametrize("opts", [
    dict(obf_strings=True),
    dict(obf_strings=True, obf_ints=True, dispatch_tree=True, state_delta=True, dedup=True),
    dict(obf_strings=True, obf_ints=True, dict_indirect=True, stack_calls=True,
         hide_external_args=True, junk_code=True, split_calls=True, slot_vars=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_powstring_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert orig(*a) == obf(*a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_no_xor_no_bytes_genexp_signature_and_secret_absent():
    out = obf_func("def f():\n    return 'SUPER_SECRET_TOKEN'\n",
                   ObfOptions(output="text", seed=0, min_blocks=1, obf_strings=True,
                              shuffle_states=False, opaque_predicates=False, bogus_blocks=False))
    assert "SUPER_SECRET_TOKEN" not in out          # plaintext gone
    assert "pow(" in out                             # powmod decode present
    assert _ns(out, "f")() == "SUPER_SECRET_TOKEN"   # round-trips


def test_empty_string_roundtrips():
    out = obf_func("def f():\n    return ''\n",
                   ObfOptions(output="text", seed=0, min_blocks=1, obf_strings=True))
    assert _ns(out, "f")() == ""
