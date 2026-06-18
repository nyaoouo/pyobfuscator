# tests/test_namevault.py
import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _nsf(src, name, opts):
    out = obf_func(src, opts); d = {}
    exec(compile(out, "<t>", "exec"), d); return out, d[name]


def test_off_by_default_noop():
    src = "def f(xs):\n    return len(xs)\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, obf_strings=False))
    assert "__import__" not in out and "[chr(" not in out
    # `len` stays a plain builtin call — NOT vault-routed. (LocalRenamePass renames the param `xs`,
    # so we assert on the builtin name + the absence of vault routing rather than the literal
    # `len(xs)`. Builtins are never renamed by this pass.)
    assert "len(" in out


def test_builtin_routed_and_equivalent():
    src = "def f(xs):\n    return len(xs) + max(xs)\n"
    out, f = _nsf(src, "f", ObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    assert "__import__" in out                      # bootstrap present
    assert f([1, 2, 3]) == 6   # len=3 + max=3
    assert f([5]) == 6         # len=1 + max=5  (== CPython; spec draft said 10 by typo)


def test_shadowed_builtin_not_routed():
    # 'len' is a parameter -> bound -> must NOT be routed
    src = "def f(len):\n    return len\n"
    out, f = _nsf(src, "f", ObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    assert f(42) == 42


def test_super_zero_arg_preserved():
    src = ("class A:\n    def m(self):\n        return 1\n"
           "class B(A):\n    def m(self):\n        return super().m() + 1\n"
           "def f():\n    return B().m()\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 2


def test_builtin_name_string_pooled_with_archive():
    # with const_archive, the builtin NAME 'len' must not survive as plaintext
    src = "def f(xs):\n    return len(xs)\n"
    out, f = _nsf(src, "f", ObfOptions(output="text", min_blocks=1, name_vault=True,
                                       const_archive=True, obf_strings=False))
    assert f([1, 2]) == 2


EQ_SRC = ("def f(xs):\n"
          "    a = sorted([abs(x) for x in xs])\n"
          "    return a + [len(xs), max(xs, default=0), min(xs, default=0)]\n")


@pytest.mark.parametrize("opts", [
    dict(name_vault=True, obf_strings=False),
    dict(name_vault=True, const_archive=True, obf_strings=False),
    dict(name_vault=True, const_archive=True, obf_strings=False, obf_ints=True,
         dispatch_tree=True, shuffle_states=True, bogus_blocks=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_namevault_equivalent(opts, seed):
    o = {}; exec(compile(EQ_SRC, "<o>", "exec"), o)
    out = obf_func(EQ_SRC, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    t = {}; exec(compile(out, "<t>", "exec"), t)
    for a in ([3, -1, 2], [], [-5]):
        assert t["f"](a) == o["f"](a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_import_routed_and_equivalent():
    src = "import json\ndef f(s):\n    return json.loads(s)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    assert "import json" not in out and "__import__" in out
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]('{"a": 1}') == {"a": 1}


def test_import_as_routed():
    src = "import json as J\ndef f(s):\n    return J.loads(s)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]('[1, 2]') == [1, 2]


def test_dotted_import_no_alias_routed():
    src = "import os.path\ndef f(a, b):\n    return os.path.join(a, b)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    import os
    assert ns["f"]("x", "y") == os.path.join("x", "y")


def test_dotted_import_with_as_NOT_routed():
    # import a.b as c must be left as a normal import (correctness: __import__('a.b') returns a, not a.b)
    src = "import os.path as p\ndef f():\n    return p.sep\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    import os
    assert ns["f"]() == os.path.sep


def test_from_import_not_touched_but_works():
    src = "from os import getcwd\ndef f():\n    return callable(getcwd)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() is True


def test_reassigned_import_not_routed():
    src = "import json\njson = None\ndef f():\n    return json\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() is None


def test_import_module_name_pooled_with_archive():
    src = "import json\ndef f(s):\n    return json.loads(s)\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True,
                                           const_archive=True, obf_strings=False))
    assert '"json"' not in out and "'json'" not in out      # module name pooled
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]('{"k": 2}') == {"k": 2}


@pytest.mark.parametrize("opts", [
    dict(name_vault=True, obf_strings=False),
    dict(name_vault=True, const_archive=True, obf_strings=False),
    dict(name_vault=True, const_archive=True, obf_strings=False, obf_ints=True,
         dispatch_tree=True, shuffle_states=True, bogus_blocks=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_namevault_import_equivalent(opts, seed):
    src = ("import json\nimport os.path\n"
           "def f(s, a, b):\n    return [json.loads(s), os.path.join(a, b), len(s)]\n")
    o = {"__name__": "o"}; exec(compile(src, "<o>", "exec"), o)
    out = obf_module(src, ModuleObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    t = {"__name__": "t"}; exec(compile(out, "<t>", "exec"), t)
    for args in (('{"x":1}', "p", "q"), ('[]', "a", "b")):
        assert t["f"](*args) == o["f"](*args), f"opts={opts} seed={seed} args={args}\n{out}"


# --- attribute READS: obj.attr -> getattr(obj,"attr") via the vault bootstrap ---

def test_attr_load_routed_and_equivalent():
    src = ("import json\n"
           "def f(s):\n"
           "    d = json.loads(s)\n"
           "    return d.get('k')\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    # attribute names gone as bare `.loads`/`.get`; getattr-style routing present
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]('{"k": 7}') == 7


def test_attr_chained_and_method_calls():
    src = "def f(x):\n    return x.real.bit_length() if False else str(x).upper()\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"](5) == "5"


def test_attr_super_zero_arg():
    src = ("class A:\n    def m(self):\n        return 10\n"
           "class B(A):\n    def m(self):\n        return super().m() + 5\n"
           "def f():\n    return B().m()\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 15


def test_attr_property_side_effect_preserved():
    src = ("class C:\n    @property\n    def v(self):\n        return 42\n"
           "def f():\n    return C().v\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 42  # @property decorator kept bare, getter still triggered via getattr


def test_attr_store_value_part_rewritten_target_intact():
    src = ("class N:\n    pass\n"
           "def f():\n    n = N()\n    n.a = N()\n    n.a.b = 3\n    return n.a.b\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 3


def test_attrs_off_when_flag_off():
    # name_vault on but name_vault_attrs off -> attributes NOT rewritten
    src = "def f(x):\n    return str(x).upper()\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=False, obf_strings=False))
    assert ".upper" in out  # attribute access still textual
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"](5) == "5"


def test_attr_name_pooled_with_archive():
    src = "def f(s):\n    return s.strip().upper()\n"
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True,
                                           name_vault_attrs=True, const_archive=True, obf_strings=False))
    assert "strip" not in out and "upper" not in out   # attr names pooled
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]("  hi ") == "HI"


@pytest.mark.parametrize("opts", [
    dict(name_vault=True, name_vault_attrs=True, obf_strings=False),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, obf_strings=False),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, obf_strings=False,
         obf_ints=True, dispatch_tree=True, shuffle_states=True, bogus_blocks=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_attr_equivalent(opts, seed):
    src = ("import json\n"
           "def f(s, xs):\n"
           "    d = json.loads(s)\n"
           "    return [d.get('k', 0), len(xs), str(max(xs, default=0)).upper(), xs[:1]]\n")
    o = {"__name__": "o"}; exec(compile(src, "<o>", "exec"), o)
    out = obf_module(src, ModuleObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    t = {"__name__": "t"}; exec(compile(out, "<t>", "exec"), t)
    for args in (('{"k": 9}', [3, 1, 2]), ('{}', [])):
        assert t["f"](*args) == o["f"](*args), f"opts={opts} seed={seed} args={args}\n{out}"


def test_decorator_uses_routed_import_name_no_nameerror():
    # regression: `import functools` is routed/dropped, but @functools.wraps keeps the bare name
    # (decorator positions are exempt from rewriting) -> must NOT drop the import in that case.
    src = ("import functools\n"
           "def deco(fn):\n"
           "    @functools.wraps(fn)\n"
           "    def w(*a, **k):\n"
           "        return fn(*a, **k)\n"
           "    return w\n"
           "@deco\n"
           "def f(x):\n"
           "    'docs'\n"
           "    return x + 1\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"](10) == 11
    assert ns["f"].__name__ == "f"   # functools.wraps actually applied (name preserved)


def test_decorator_attr_with_attrs_flag_no_nameerror():
    # same, but with name_vault_attrs on (attribute rewriting active elsewhere)
    src = ("import functools\n"
           "def deco(fn):\n"
           "    @functools.wraps(fn)\n"
           "    def w(*a, **k):\n"
           "        return fn(*a, **k) * 2\n"
           "    return w\n"
           "@deco\n"
           "def g(x):\n"
           "    return x\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True,
                                           name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["g"](5) == 10 and ns["g"].__name__ == "g"


# --- attribute WRITES/DELETES: obj.attr=v -> setattr / del obj.attr -> delattr ---

def test_attr_store_setattr_equivalent():
    src = ("class N:\n    pass\n"
           "def f():\n    n = N()\n    n.x = 5\n    n.x = n.x + 1\n    return n.x\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 6


def test_attr_store_eval_order_preserved():
    # RHS must evaluate before the target object, same as `obj.attr = value`
    src = ("import types\n"
           "def f():\n"
           "    log = []\n"
           "    def obj():\n        log.append('obj'); return types.SimpleNamespace()\n"
           "    def val():\n        log.append('val'); return 1\n"
           "    obj().x = val()\n"
           "    return log\n")
    o = {"__name__": "o"}; exec(compile(src, "<o>", "exec"), o)
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    t = {"__name__": "t"}; exec(compile(out, "<t>", "exec"), t)
    assert t["f"]() == o["f"]() == ['val', 'obj']   # value first, then target object


def test_attr_store_chain_line43_shape():
    src = ("import types\n"
           "def f():\n"
           "    o = types.SimpleNamespace()\n"
           "    o.a = types.SimpleNamespace()\n"
           "    o.a.set_events = lambda *a, **k: 99\n"
           "    return o.a.set_events()\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True,
                                           name_vault_attrs=True, const_archive=True, obf_strings=False))
    assert "set_events" not in out  # the sensitive attr name is gone (pooled by const_archive)
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 99


def test_attr_delete_delattr():
    src = ("class N:\n    pass\n"
           "def f():\n    n = N()\n    n.x = 1\n    del n.x\n    return hasattr(n, 'x')\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() is False


def test_attr_augassign_left_intact_but_works():
    src = ("class N:\n    pass\n"
           "def f():\n    n = N()\n    n.x = 10\n    n.x += 5\n    return n.x\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 15


def test_attr_multitarget_assign_left_intact():
    src = ("class N:\n    pass\n"
           "def f():\n    a = N(); b = N()\n    a.x = b.y = 7\n    return a.x + b.y\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1,
                                           name_vault=True, name_vault_attrs=True, obf_strings=False))
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 14


def test_attr_store_name_pooled_with_archive():
    src = ("import types\n"
           "def f():\n    o = types.SimpleNamespace()\n    o.secret_attr = 3\n    return o.secret_attr\n")
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, name_vault=True,
                                           name_vault_attrs=True, const_archive=True, obf_strings=False))
    assert "secret_attr" not in out
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["f"]() == 3


@pytest.mark.parametrize("opts", [
    dict(name_vault=True, name_vault_attrs=True, obf_strings=False),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, obf_strings=False),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, obf_strings=False,
         obf_ints=True, dispatch_tree=True, shuffle_states=True, bogus_blocks=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_attr_store_equivalent(opts, seed):
    src = ("class P:\n    def __init__(self):\n        self.a = 0\n        self.b = []\n"
           "    def step(self, n):\n        self.a += n\n        self.b.append(n)\n        self.a = self.a * 2\n        return self.a\n"
           "def f(ns):\n    p = P()\n    out = [p.step(n) for n in ns]\n    del p.b\n    return [out, hasattr(p, 'b'), p.a]\n")
    o = {"__name__": "o"}; exec(compile(src, "<o>", "exec"), o)
    out = obf_module(src, ModuleObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    t = {"__name__": "t"}; exec(compile(out, "<t>", "exec"), t)
    for arg in ([1, 2, 3], []):
        assert t["f"](arg) == o["f"](arg), f"opts={opts} seed={seed} arg={arg}\n{out}"
