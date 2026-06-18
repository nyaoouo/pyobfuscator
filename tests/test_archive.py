# tests/test_archive.py
import sys, os, ast
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_func, ObfOptions


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


def test_archive_off_by_default_is_noop():
    src = "def f():\n    return 'plain'\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, obf_strings=False))
    assert "plain" in out


def test_archive_flag_accepted():
    src = "def f():\n    return 1234567\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, const_archive=True,
                                   obf_strings=False))
    assert _ns(out, "f")() == 1234567


def test_serialize_roundtrip_all_types():
    from pyobfuscator.cff.passes.archive import _serialize, _deserialize
    cases = [0xDEADBEEF, -9999, 2**80, 3.14159, -0.0, float("inf"),
             "hello", "你好\udce9", "", b"\x00\xff", b""]
    for v in cases:
        rec, cast = _serialize(v)
        assert isinstance(rec, (bytes, bytearray))
        back = _deserialize(bytes(rec), cast)
        assert type(back) is type(v) and (back == v or (back != back and v != v))  # NaN-safe


def test_build_archive_decodes_back():
    import random
    from pyobfuscator.cff.passes.archive import _build_archive, _deserialize
    from pyobfuscator.protect.cipher import _ks_xor, _kdf
    vals = [1234567, "secret", b"\x01\x02", 2.5, -42]
    rng = random.Random(0)
    blob, index, E, D, N, bulk = _build_archive(vals, rng)
    raw = _ks_xor(blob, bulk)  # blob here is the pre-b85 bytes
    for v in vals:
        off, sz, c, cast = index[(type(v), v)]
        k = pow(c, D, N)
        rec = _ks_xor(raw[off:off + sz], _kdf(k))
        assert _deserialize(rec, cast) == v


def test_emit_runtime_accessor_executes():
    import random, ast
    from pyobfuscator.cff.passes.archive import _build_archive, _emit_runtime
    vals = ["alpha", 777, b"\x09", 3.5, -2**70]
    rng = random.Random(1)
    blob, index, E, D, N, bulk = _build_archive(vals, rng)
    names = dict(get="_get", ks="_ks", kdf="_kdf", memo="_C", rawc="_R",
                 blob="_B", b64="_b64", st="_st")
    for fmt in ("text", "bc"):
        stmts = _emit_runtime(names, blob, D, N, bulk, fmt=fmt)
        mod = ast.Module(body=list(stmts), type_ignores=[])
        ast.fix_missing_locations(mod)
        ns = {}
        exec(compile(mod, "<rt>", "exec"), ns)
        for v in vals:
            off, sz, c, cast = index[(type(v), v)]
            got = ns["_get"](off, sz, c, cast)
            assert got == v and type(got) is type(v), f"fmt={fmt} v={v!r} got={got!r}"
        # memoization: a second call returns the SAME object
        off, sz, c, cast = index[(str, "alpha")]
        assert ns["_get"](off, sz, c, cast) is ns["_get"](off, sz, c, cast)


def _run_func(src, name, opts):
    out = obf_func(src, opts); d = {}
    exec(compile(out, "<t>", "exec"), d); return out, d[name]


def test_string_pooled_no_plaintext():
    out, f = _run_func("def f():\n    return 'secret_password'\n", "f",
                       ObfOptions(output="text", min_blocks=1, const_archive=True, obf_strings=False))
    assert "secret_password" not in out
    assert f() == "secret_password"


def test_int_and_float_pooled():
    out, f = _run_func("def f(x):\n    return x + 1234567 + 2.5\n", "f",
                       ObfOptions(output="text", min_blocks=1, const_archive=True, obf_strings=False))
    assert "1234567" not in out
    assert f(0) == 1234567 + 2.5


def test_true_false_none_not_pooled():
    out, f = _run_func("def f(b):\n    if b:\n        return True\n    return None\n", "f",
                       ObfOptions(output="text", min_blocks=1, const_archive=True, obf_strings=False))
    assert f(1) is True and f(0) is None


def test_docstring_and_fstring_pieces_preserved():
    out, f = _run_func("def f(x):\n    'doc'\n    return f'v={x}'\n", "f",
                       ObfOptions(output="text", min_blocks=1, const_archive=True, obf_strings=False))
    assert f(5) == "v=5"


import pytest

ARCH_SRCS = [
    ("def f(x):\n    s = 'hi-' + str(x)\n    return s * 2 + ' end'\n", "f", [(3,), (0,)]),
    ("def f(n):\n    t = {'a': 1000000, 'b': 2.5}\n    return t['a'] + t['b'] + n\n", "f", [(1,)]),
    ("def f(d):\n    return d.get('k', b'\\x00\\x01') + b'z'\n", "f", [({},), ({'k': b'Q'},)]),
    ("def f(x):\n    return 'neg' if x < -9999 else 'pos'\n", "f", [(-100000,), (5,)]),
]


@pytest.mark.parametrize("src,name,args", ARCH_SRCS)
@pytest.mark.parametrize("opts", [
    dict(const_archive=True, obf_strings=False),
    dict(const_archive=True, obf_strings=False, obf_ints=True),  # _get args get state-keyed
    dict(const_archive=True, obf_strings=False, obf_ints=True, dispatch_tree=True,
         shuffle_states=True, bogus_blocks=True, dedup=True, state_delta=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_archive_equivalent(src, name, args, opts, seed):
    o = {}; exec(compile(src, "<o>", "exec"), o)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    t = {}; exec(compile(out, "<t>", "exec"), t)
    for a in args:
        assert t[name](*a) == o[name](*a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_archive_module_level():
    from pyobfuscator import obf_module, ModuleObfOptions
    src = "'''doc'''\nNAMES = ['ann', 'bob']\nGREET = 'hello, '\ndef hi(i):\n    return GREET + NAMES[i]\n"
    out = obf_module(src, ModuleObfOptions(output="text", seed=3, min_blocks=1,
                                           const_archive=True, obf_strings=False))
    assert "hello" not in out and "ann" not in out
    ns = {"__name__": "m"}; exec(compile(out, "<m>", "exec"), ns)
    assert ns["hi"](1) == "hello, bob" and ns["__doc__"] == "doc"


def test_archive_zero_length_literal_no_aliasing():
    # regression: a zero-length literal (''/b'') serializes to 0 bytes and shares its offset with
    # the NEXT record; the _get memo must key on (off, sz, cast) not off alone, else the following
    # literal is aliased to the empty value. (Found via name_vault's ''.join bootstrap.)
    out, f = _run_func("def f():\n    return ['', 'abc', 12345, '', 'xy', b'', b'Q']\n", "f",
                       ObfOptions(output="text", min_blocks=1, const_archive=True, obf_strings=False))
    assert f() == ['', 'abc', 12345, '', 'xy', b'', b'Q']


# ---------------------------------------------------------------------------
# const_archive / name_vault accessor int args must be STATE-KEYED
# (enc - (state & mask)) even when obf_ints is OFF, so the archive/vault
# access pattern is static-resistant on its own. The keying is the per-block
# `key_consts` step; this decouples it from obf_ints.
#
# AST shape produced by _KeyConsts (cff/cfg.py): a keyed int becomes
#   BinOp(Constant(enc), Sub, BinOp(Name(state), BitAnd, Constant(mask)))
# i.e. the bare Constant arg/key turns into an ast.BinOp. We assert
# structurally (node types only, no hardcoded var names) since the accessor
# and vault names are seed-derived.
# ---------------------------------------------------------------------------

# Flatten options that reliably engage the dispatcher (and thus key_consts).
_KEY_FLATTEN = dict(min_blocks=1, dispatch_tree=True, shuffle_states=True)


def _state_keyed_binop(node):
    """True if `node` matches the _KeyConsts shape: <int> - (<name> & <int>)."""
    return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
            and isinstance(node.right, ast.BinOp) and isinstance(node.right.op, ast.BitAnd)
            and isinstance(node.right.left, ast.Name))


def _accessor_call_args(tree):
    """All argument expressions of 4-positional-arg Name() calls -- the const_archive
    accessor is `_get(off, sz, c, cast)`. Returns a flat list of arg AST nodes."""
    args = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and len(n.args) == 4:
            args.extend(n.args)
    return args


def _vault_subscript_keys(tree):
    """All slice/key expressions of Name[...] subscripts -- the name_vault keys are `_D[k]`."""
    keys = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name):
            keys.append(n.slice)
    return keys


def test_archive_args_state_keyed_without_obf_ints():
    # const_archive ON, obf_ints OFF: the _get(off,sz,c,cast) int args must be state-keyed.
    src = "def f(x):\n    return 'hello-' + str(x) + '-end-' + str(12345)\n"
    out, f = _run_func(src, "f", ObfOptions(output="text", seed=0, const_archive=True,
                                            obf_strings=False, obf_ints=False, **_KEY_FLATTEN))
    tree = ast.parse(out)
    args = _accessor_call_args(tree)
    assert args, "no 4-arg accessor calls found -- archive accessor missing?"
    keyed = [a for a in args if _state_keyed_binop(a)]
    assert keyed, ("accessor args are all bare -- not state-keyed without obf_ints:\n"
                   + out)
    # And there genuinely exists the `state & mask` arithmetic referencing a var.
    assert any(_state_keyed_binop(a) for a in args)
    # Equivalence across a couple seeds.
    o = {}; exec(compile(src, "<o>", "exec"), o)
    for seed in (0, 1, 7):
        out_s, fs = _run_func(src, "f", ObfOptions(output="text", seed=seed, const_archive=True,
                                                   obf_strings=False, obf_ints=False, **_KEY_FLATTEN))
        assert fs(3) == o["f"](3), f"seed={seed}\n{out_s}"


def test_archive_args_bare_when_no_flatten_dispatch_off():
    # Sanity counterpart: the keying is the flatten key_consts step. (Documents that the
    # state-keying only appears once flattening renders state==K guards.)
    src = "def f(x):\n    return 'hello-' + str(x) + '-end-' + str(12345)\n"
    out, f = _run_func(src, "f", ObfOptions(output="text", seed=0, const_archive=True,
                                            obf_strings=False, obf_ints=False, min_blocks=1))
    assert f(3) == "hello-3-end-12345"


def test_vault_keys_state_keyed_without_obf_ints():
    # name_vault ON, obf_ints OFF: the _D[k] integer keys must be state-keyed.
    src = "def f(x):\n    return str(abs(x)) + repr(x) + hex(len(str(x)))\n"
    out, f = _run_func(src, "f", ObfOptions(output="text", seed=0, name_vault=True,
                                            obf_strings=False, obf_ints=False, **_KEY_FLATTEN))
    tree = ast.parse(out)
    keys = _vault_subscript_keys(tree)
    assert keys, "no Name[...] subscripts found -- vault subscripts missing?"
    keyed = [k for k in keys if _state_keyed_binop(k)]
    assert keyed, ("vault subscript keys are all bare -- not state-keyed without obf_ints:\n"
                   + out)
    # Equivalence across a couple seeds.
    o = {}; exec(compile(src, "<o>", "exec"), o)
    for seed in (0, 1, 7):
        out_s, fs = _run_func(src, "f", ObfOptions(output="text", seed=seed, name_vault=True,
                                                   obf_strings=False, obf_ints=False, **_KEY_FLATTEN))
        assert fs(-4) == o["f"](-4), f"seed={seed}\n{out_s}"


def test_off_path_ints_stay_bare_without_obf_ints():
    # const_archive=False, name_vault=False, obf_ints=False: key_consts must NOT run.
    # A plain int literal must remain a bare Constant (the fix did not globally enable keying).
    src = "def f():\n    return 31337\n"
    out, f = _run_func(src, "f", ObfOptions(output="text", seed=0, const_archive=False,
                                            name_vault=False, obf_ints=False, **_KEY_FLATTEN))
    tree = ast.parse(out)
    bare = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == 31337]
    assert bare, "31337 should survive as a bare Constant when nothing keys it:\n" + out
    # And it must NOT have been turned into the keyed `enc - (state & mask)` form.
    assert not any(_state_keyed_binop(n) for n in ast.walk(tree)), (
        "key_consts ran on the off-path -- the fix globally enabled keying:\n" + out)
    assert f() == 31337


B_EQUIV_SRCS = [
    ("def f(x):\n    s = 'hi-' + str(x)\n    return s * 2 + ' end-' + str(98765)\n", "f", [(3,), (0,)]),
    ("def f(n):\n    t = {'a': 1000000, 'b': 2.5}\n    return t['a'] + t['b'] + n + 424242\n", "f", [(1,)]),
    ("def f(x):\n    return str(abs(x)) + repr(len(str(x))) + hex(x if x > 0 else 0)\n", "f", [(7,), (-3,), (0,)]),
]


@pytest.mark.parametrize("src,name,args", B_EQUIV_SRCS)
@pytest.mark.parametrize("feat", [
    dict(const_archive=True),
    dict(name_vault=True),
])
@pytest.mark.parametrize("obf_ints", [False, True])
@pytest.mark.parametrize("seed", [0, 2, 5])
def test_archive_vault_keyconsts_equivalence_matrix(src, name, args, feat, obf_ints, seed):
    # key_consts is behavior-preserving: output must equal the original regardless of whether
    # the keying is driven by obf_ints or by const_archive/name_vault.
    o = {}; exec(compile(src, "<o>", "exec"), o)
    out = obf_func(src, ObfOptions(output="text", seed=seed, obf_strings=False,
                                   obf_ints=obf_ints, **feat, **_KEY_FLATTEN))
    t = {}; exec(compile(out, "<t>", "exec"), t)
    for a in args:
        assert t[name](*a) == o[name](*a), f"feat={feat} obf_ints={obf_ints} seed={seed} a={a}\n{out}"
