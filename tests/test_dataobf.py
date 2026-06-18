import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _run_func(src, name, opts):
    out = obf_func(src, opts)
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return out, ns[name]


def test_string_literal_obfuscated_and_correct():
    out, f = _run_func("def f():\n    return 'secret_password'\n", "f",
                       ObfOptions(output="text", min_blocks=1))
    assert "secret_password" not in out  # plaintext gone
    assert f() == "secret_password"      # behavior preserved


def test_unicode_string():
    out, f = _run_func("def f():\n    return '你好世界'\n", "f",
                       ObfOptions(output="text", min_blocks=1))
    assert "你好" not in out
    assert f() == "你好世界"


def test_empty_string():
    _, f = _run_func("def f():\n    return ''\n", "f",
                     ObfOptions(output="text", min_blocks=1))
    assert f() == ""


def test_bytes_literal():
    out, f = _run_func("def f():\n    return b'\\x00ABZ'\n", "f",
                       ObfOptions(output="text", min_blocks=1))
    assert f() == b"\x00ABZ"


def test_fstring_expression_obfuscated_pieces_preserved():
    # literal piece 'val=' is preserved (valid AST); the embedded expression still works
    _, f = _run_func("def f(x):\n    return f'val={x}!'\n", "f",
                     ObfOptions(output="text", min_blocks=1))
    assert f(5) == "val=5!"


def test_ints_off_by_default_on_when_requested():
    # Use specific token forms (`return 42`) not bare `42` to avoid coincidental
    # substring matches inside generated powmod chunk constants.
    src = "def f(x):\n    if x > 100:\n        return 42\n    return 7\n"
    out_default = obf_func(src, ObfOptions(output="text", min_blocks=1))
    assert "return 42" in out_default  # ints untouched by default
    out_ints = obf_func(src, ObfOptions(output="text", min_blocks=1, obf_ints=True))
    assert "return 42" not in out_ints  # int obfuscated when requested
    ns = {}
    exec(compile(out_ints, "<t>", "exec"), ns)
    assert ns["f"](200) == 42 and ns["f"](3) == 7


def test_true_false_none_not_touched():
    # bool/None must never be rewritten (type-is guard)
    src = "def f(b):\n    if b:\n        return True\n    return None\n"
    out, f = _run_func(src, "f", ObfOptions(output="text", min_blocks=1, obf_ints=True))
    assert f(1) is True and f(0) is None


def test_disabling_all_is_noop_for_constants():
    src = "def f():\n    return 'plain'\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, obf_strings=False))
    assert "plain" in out


def test_module_docstring_preserved():
    src = "'''module secret doc'''\nX = ['a', 'b', 'c']\ndef get():\n    return list(X)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1))
    ns = {"__name__": "m"}
    exec(compile(out, "<m>", "exec"), ns)
    assert ns["__doc__"] == "module secret doc"
    assert ns["get"]() == ["a", "b", "c"]


def test_string_in_default_arg_and_dict_key():
    src = ("def f(mode='fast'):\n    table = {'fast': 1, 'slow': 2}\n    return table[mode]\n")
    out, f = _run_func(src, "f", ObfOptions(output="text", min_blocks=1))
    assert "fast" not in out and "slow" not in out
    assert f() == 1 and f("slow") == 2


def test_int_obf_resists_constant_folding():
    # `c1 ^ c2` would be folded back by CPython at compile time; the keyed form must NOT be.
    src = "def f():\n    return 27588\n"
    out = obf_func(src, ObfOptions(output="text", seed=1, min_blocks=1, obf_ints=True))
    code = compile(out, "<t>", "exec")

    def all_int_consts(c):
        s = set()
        for k in c.co_consts:
            if isinstance(k, int):
                s.add(k)
            if hasattr(k, "co_consts"):
                s |= all_int_consts(k)
        return s

    assert 27588 not in all_int_consts(code)  # not folded back
    ns = {}
    exec(code, ns)
    assert ns["f"]() == 27588  # still correct at runtime
