import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions

def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]

def _helper_name(out):
    # The decode helper is the 2-arg FunctionDef doing the powmod decode (`pow(...).to_bytes(...)`).
    # Detect by STRUCTURE, not by param names — helper params are now renamed to fresh _pyobf names
    # at injection, so the old ['cs', 'L'] name check no longer applies.
    for n in ast.walk(ast.parse(out)):
        if not (isinstance(n, ast.FunctionDef) and len(n.args.args) == 2):
            continue
        has_pow = any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "pow"
                      for c in ast.walk(n))
        has_tobytes = any(isinstance(c, ast.Attribute) and c.attr == "to_bytes" for c in ast.walk(n))
        if has_pow and has_tobytes:
            return n.name
    return None

SRC = "def f(x):\n    s = 'secret-' + str(x)\n    return s + ' / flag{xyz}'\n"

def test_direct_call_when_dict_indirect_off():
    out = obf_func(SRC, ObfOptions(output="text", seed=0, min_blocks=1,
                                   obf_strings=True, dict_indirect=False))
    h = _helper_name(out); assert h is not None
    tree = ast.parse(out)
    direct = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == h]
    assert direct, "expected a direct _dec(...) name-call when dict_indirect is off"

@pytest.mark.parametrize("seed", [0, 1, 7])
@pytest.mark.parametrize("extra", [dict(), dict(obf_ints=True),
                                   dict(obf_ints=True, state_delta=True, dispatch_tree=True)])
def test_helper_indirected_when_dict_indirect_on(seed, extra):
    out = obf_func(SRC, ObfOptions(output="text", seed=seed, min_blocks=1,
                                   obf_strings=True, dict_indirect=True, **extra))
    h = _helper_name(out); assert h is not None, out
    tree = ast.parse(out)
    # 1. helper is NEVER called by bare name
    direct = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == h]
    assert not direct, f"helper still called directly by name\n{out}"
    # 2. helper name still referenced (the registration RHS) and a subscript-func call exists
    name_refs = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == h]
    assert name_refs, "helper name vanished (registration RHS missing)"
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Subscript)
               for n in ast.walk(tree)), "no subscript-form (dict) call present"

# ---- differential equivalence (the real gate) ----
DSRCS = [
    ("def f():\n    return 'hello, world'\n", "f", [()]),
    ("def f(x):\n    return ('flag{' + str(x) + '}', b'\\x00raw\\xff\\x00')\n", "f", [(42,)]),
    ("def f():\n    return 'unicode: \\u4e2d\\u6587 \\U0001f600 \\x00end'\n", "f", [()]),
    ("def f():\n    return ''\n", "f", [()]),
    ("def f(n):\n    d = {'k': 'v', 'k2': 'v2'}\n    return [d['k'] + str(i) for i in range(n)]\n",
     "f", [(0,), (3,)]),
    # nested function that itself contains a string literal (closure over the helper/ds)
    ("def f(x):\n    def g(y):\n        return 'inner:' + str(y)\n    return g(x) + '|outer'\n",
     "f", [(5,)]),
]

@pytest.mark.parametrize("src,name,argl", DSRCS)
@pytest.mark.parametrize("opts", [
    dict(obf_strings=True, dict_indirect=True),
    dict(obf_strings=True, dict_indirect=True, obf_ints=True, state_delta=True,
         dispatch_tree=True, dedup=True),
    dict(obf_strings=True, dict_indirect=True, obf_ints=True, stack_calls=True,
         hide_external_args=True, junk_code=True, split_calls=True, slot_vars=True,
         shuffle_states=True, opaque_predicates=True, bogus_blocks=True),
])
@pytest.mark.parametrize("seed", [0, 3])
def test_dec_indirect_equivalence(src, name, argl, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in argl:
        assert orig(*a) == obf(*a), f"opts={opts} seed={seed} a={a}\n{out}"
