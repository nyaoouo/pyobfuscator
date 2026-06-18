import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

def _ns(code):
    d = {"__name__": "m"}; exec(compile(code, "<m>", "exec"), d); return d

# ---- differential equivalence ----
SRCS = [
    # private constant table read by multiple funcs
    ("_TBL = {'a': 1, 'b': 2, 'c': 3}\n"
     "def look(k):\n    return _TBL.get(k, 0)\n"
     "def total():\n    return sum(_TBL.values())\n"
     "def main(k):\n    return look(k) + total()\n", [("a",), ("z",)]),
    # private sentinel compared by identity (must stay the SAME object)
    ("_MISS = object()\n"
     "def get(d, k):\n    v = d.get(k, _MISS)\n    return 'miss' if v is _MISS else v\n"
     "def main(k):\n    return get({'x': 7}, k)\n", [("x",), ("y",)]),
    # forward ref: func defined before the global's assignment line, called after load
    ("def use():\n    return _CFG * 10\n"
     "_CFG = 5\n"
     "def main(_):\n    return use()\n", [(0,)]),
    # public (non-_) global must NOT be indirected -> still works
    ("LIMIT = 100\n"
     "def main(x):\n    return x if x < LIMIT else LIMIT\n", [(5,), (250,)]),
    # reassigned module-level private global must be EXCLUDED -> behavior preserved
    ("_val = 0\n"
     "_val = 42\n"
     "def main(n):\n    return _val + n\n", [(0,), (3,)]),
    # del'd global excluded
    ("_tmp = [1, 2, 3]\n"
     "def main(x):\n    v = sum(_tmp) + x\n    return v\n", [(10,)]),
    # global whose value references an eligible function (chained)
    ("def _impl(x):\n    return x * x\n"
     "_FN = _impl\n"
     "def main(x):\n    return _FN(x) + _impl(x)\n", [(4,)]),
]

@pytest.mark.parametrize("src,argl", SRCS)
@pytest.mark.parametrize("flags", [
    dict(dict_indirect=True),
    dict(dict_indirect=True, obf_ints=True, state_delta=True, dispatch_tree=True),
    dict(dict_indirect=True, obf_ints=True, obf_strings=True, junk_code=True,
         dedup=True, stack_calls=True, hide_external_args=True, slot_vars=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_global_indirect_equivalence(src, argl, flags, seed):
    orig = _ns(src)
    out = obf_module(src, ModuleObfOptions(output="text", seed=seed, min_blocks=1, **flags))
    obf = _ns(out)
    for a in argl:
        assert orig["main"](*a) == obf["main"](*a), f"flags={flags} seed={seed} a={a}\n{out}"

# ---- structural: private single-assign global IS indirected; public is NOT ----
def test_private_global_indirected_public_kept():
    src = ("_SECRET = 12345\nPUBLIC = 999\n"
           "def main():\n    return _SECRET + PUBLIC\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=0, min_blocks=1,
                                           dict_indirect=True, shuffle_states=False,
                                           opaque_predicates=False, bogus_blocks=False))
    tree = ast.parse(out)
    # _SECRET must no longer appear as a bare Name anywhere (fully routed through the dict)
    assert not any(isinstance(n, ast.Name) and n.id == "_SECRET" for n in ast.walk(tree)), \
        f"_SECRET still present as a name\n{out}"
    # PUBLIC must still be a bare Name (kept as export)
    assert any(isinstance(n, ast.Name) and n.id == "PUBLIC" for n in ast.walk(tree)), \
        f"PUBLIC was wrongly indirected\n{out}"
    assert _ns(out)["main"]() == 12345 + 999

def test_reassigned_global_not_indirected():
    # A module-level private global assigned twice must be excluded (bound_names >= 2)
    src = ("_c = 0\n"
           "_c = 1\n"
           "def main(n):\n    return _c + n\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=0, min_blocks=1,
                                           dict_indirect=True, shuffle_states=False,
                                           opaque_predicates=False, bogus_blocks=False))
    # _c is reassigned -> must remain a normal global name (not indirected)
    assert any(isinstance(n, ast.Name) and n.id == "_c" for n in ast.walk(ast.parse(out))), \
        f"reassigned global _c was wrongly indirected\n{out}"
    assert _ns(out)["main"](4) == 5
