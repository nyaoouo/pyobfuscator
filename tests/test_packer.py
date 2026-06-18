import sys, os, ast, marshal
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator.packer import pack_module, _ks_xor, _TEMP_KEY
from pyobfuscator import ModuleObfOptions


def _exec(code_or_src, name="packtest"):
    ns = {"__name__": name}
    exec(code_or_src, ns)
    return ns


def test_ks_xor_is_symmetric():
    data = b"the quick brown fox \x00\x01\x02\xff"
    enc = _ks_xor(data, _TEMP_KEY)
    assert enc != data
    assert _ks_xor(enc, _TEMP_KEY) == data  # XOR keystream is its own inverse


def test_pack_source_form_roundtrips_and_hides_body():
    src = "MARKER_ABC = 123\ndef get():\n    return MARKER_ABC * 2\n"
    body = ast.parse(src)
    launcher = pack_module(body, ModuleObfOptions(output="text", pack_format="source"))
    out = ast.unparse(launcher)
    assert "MARKER_ABC" not in out          # body identifier is encrypted, not in plaintext
    ns = _exec(compile(out, "<t>", "exec"))
    assert ns["MARKER_ABC"] == 123 and ns["get"]() == 246


def test_pack_bytecode_form_roundtrips():
    src = "VALUE = 7\ndef total():\n    return VALUE + 1\n"
    body = ast.parse(src)
    launcher = pack_module(body, ModuleObfOptions(output="pyc", pack_format="bytecode"))
    code = compile(launcher, "<t>", "exec")
    ns = _exec(code)
    assert ns["VALUE"] == 7 and ns["total"]() == 8


def test_obf_module_pack_text_equivalent():
    from pyobfuscator import obf_module
    src = "X = 5\ndef f(a):\n    return a + X\n"
    out = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1, pack_body=True))
    assert "exec(" in out  # launcher present
    ns = _exec(compile(out, "<t>", "exec"))
    assert ns["X"] == 5 and ns["f"](10) == 15


def test_obf_module_pack_ast_is_noop():
    # AST output cannot be packed (no decrypt+exec target) -> body passes through.
    from pyobfuscator import obf_module
    src = "Y = 1\n"
    tree = obf_module(src, ModuleObfOptions(output="ast", min_blocks=1, pack_body=True))
    import ast as _ast
    assert isinstance(tree, _ast.Module)
    # no launcher exec(...) call injected at top level
    assert not any(isinstance(n, _ast.Expr) and isinstance(n.value, _ast.Call)
                   and getattr(n.value.func, "id", None) == "exec" for n in tree.body)


def test_kdf_deterministic_and_diffusing():
    from pyobfuscator.packer import _kdf, _MASK
    assert _kdf(0) == _kdf(0)               # deterministic
    assert 0 <= _kdf(123) <= _MASK          # 64-bit range
    assert _kdf(0) != _kdf(1)               # diffuses
    assert _kdf(1) != _kdf(1 << 40)


def test_fold_matches_manual():
    from pyobfuscator.packer import _fold, _MASK
    steps = [(3, 5), (7, 11)]
    acc = 9
    for m, c in steps:
        acc = (acc * m + c) & _MASK
    assert _fold(9, steps) == acc


def test_key_sensitivity_wrong_selector_fails():
    # The crux of key_from_cff: a wrong selector S' -> wrong key -> cannot recover the body.
    from pyobfuscator.packer import _ks_xor, _kdf
    body = b"def f():\n    return 42\n"
    enc = _ks_xor(body, _kdf(0xDEADBEEF))
    assert _ks_xor(enc, _kdf(0xDEADBEEF)) == body          # right selector -> body
    assert _ks_xor(enc, _kdf(0xDEADBEEF ^ 1)) != body      # one-bit-off selector -> garbage


def test_pack_module_cff_key_roundtrips_text():
    import ast
    from pyobfuscator.packer import pack_module, _TEMP_KEY
    from pyobfuscator import ModuleObfOptions
    src = "MARK = 314\ndef get():\n    return MARK + 1\n"
    body = ast.parse(src)
    launcher = pack_module(body, ModuleObfOptions(output="text", seed=11, min_blocks=1,
                                                  pack_format="source", key_from_cff=True))
    out = ast.unparse(launcher)
    assert "MARK" not in out                       # body still encrypted
    assert "0xa5a5a5a5a5a5a5a5" not in out.lower()  # temp key NOT used (hex form)
    assert str(_TEMP_KEY) not in out               # temp key NOT used (decimal form, as ast.unparse emits)
    ns = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["MARK"] == 314 and ns["get"]() == 315


def test_pack_module_cff_key_roundtrips_bytecode():
    import ast, marshal
    from pyobfuscator.packer import pack_module
    from pyobfuscator import ModuleObfOptions
    src = "V = 8\ndef t():\n    return V * 3\n"
    body = ast.parse(src)
    launcher = pack_module(body, ModuleObfOptions(output="pyc", seed=4, min_blocks=1,
                                                  pack_format="bytecode", key_from_cff=True))
    code = compile(launcher, "<t>", "exec")
    ns = {"__name__": "m"}
    exec(code, ns)
    assert ns["V"] == 8 and ns["t"]() == 24


def test_s2b_branchless_selection_unit():
    # The selection identity at the heart of the selection: correct selector -> real key; any other -> decoy key.
    from pyobfuscator.packer import _kdf, _MASK
    MAGIC = 0x100000001B3; SALT_SEL = 0x5E1EC700
    S_correct = 0x1234_5678_9ABC_DEF0
    K_real = _kdf(S_correct ^ 0x4E12B0F5)
    K_decoy = _kdf(0xDEC0DEC0)
    sel_correct = _kdf(S_correct ^ SALT_SEL)
    TABLE = {sel_correct: ((b"R"), (K_real ^ S_correct) & _MASK, 1)}
    DEFAULT = ((b"D"), K_decoy, 0)
    def select(S):
        e = TABLE.get(_kdf(S ^ SALT_SEL), DEFAULT)
        return e[0], (e[1] ^ (S * e[2])) & _MASK
    blob, key = select(S_correct)
    assert blob == b"R" and key == K_real            # correct path -> real, key recovered
    blob, key = select(S_correct ^ 1)                 # one-bit tamper
    assert blob == b"D" and key == K_decoy            # -> decoy, clean decoy key


def test_pack_decoy_untampered_runs_real():
    import ast
    from pyobfuscator.packer import pack_module
    from pyobfuscator import ModuleObfOptions
    src = "REALMARK = 777\ndef who():\n    return 'real'\n"
    launcher = pack_module(ast.parse(src), ModuleObfOptions(
        output="text", seed=3, min_blocks=1, pack_format="source",
        key_from_cff=True, integrity_selfcheck=True, pack_decoy=True))
    out = ast.unparse(launcher)
    ns = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns.get("REALMARK") == 777 and ns["who"]() == "real"
    assert "__pyobf_decoy__" not in ns        # decoy did NOT run


def test_decoy_obf_overrides_changes_embedded_decoy():
    # decoy_obf_overrides dials DOWN the embedded decoy's obfuscation (build-side fine-tuning) so a
    # TRIGGERED decoy is legible, while the untampered path is untouched. obf_module pre-obfuscates the
    # decoy via _obfuscate_decoy, which reads this field (the pack_module/in-process decoy tests bypass
    # it). The override MUST change the emitted artifact (proof it is wired) and MUST NOT disturb the
    # genuine path. attest is force-disabled for the decoy regardless, so it would run under a debugger.
    from pyobfuscator import obf_module, ModuleObfOptions
    src = "REALMARK = 777\ndef who():\n    return 'real'\n"
    decoy = ("def test_key(k):\n    t = 0\n    for c in k:\n        t += ord(c)\n    return t == 1234\n"
             "__pyobf_decoy__ = True\n")
    base = dict(output="text", seed=5, min_blocks=1, pack_format="source", pack_body=True,
                key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
                obf_ints=True, opaque_predicates=True, bogus_blocks=True, junk_code=True)
    full = obf_module(src, ModuleObfOptions(decoy_src=decoy, **base))
    light = obf_module(src, ModuleObfOptions(
        decoy_src=decoy,
        decoy_obf_overrides=dict(opaque_predicates=False, bogus_blocks=False,
                                 junk_code=False, obf_strings=False, const_archive=False),
        **base))
    assert full != light                       # the override actually changes the embedded decoy
    for out in (full, light):                  # both untampered paths still run the real body
        ns = {"__name__": "m"}
        exec(compile(out, "<t>", "exec"), ns)
        assert ns.get("REALMARK") == 777 and ns["who"]() == "real"
        assert "__pyobf_decoy__" not in ns


def test_keybind_untraced_runs_real():
    import ast
    from pyobfuscator.packer import pack_module
    from pyobfuscator import ModuleObfOptions
    src = "RM = 42\ndef who():\n    return 'real'\n"
    launcher = pack_module(ast.parse(src), ModuleObfOptions(
        output="text", seed=4, min_blocks=1, pack_format="source",
        key_from_cff=True, integrity_selfcheck=True, pack_decoy=True,
        detect_trace=True, key_binds_env=True))
    ns = {"__name__": "m"}
    exec(compile(ast.unparse(launcher), "<t>", "exec"), ns)
    assert ns.get("RM") == 42 and ns["who"]() == "real" and "__pyobf_decoy__" not in ns


def test_text_blob_b85_printable_and_compressed():
    """TEXT output embeds the blob as base64.b85decode(b'<printable>') — NOT a b'\\xNN' literal
    (~2.87x in source) — and zlib-compresses the body before encryption, so the embedded blob is
    far smaller than the obfuscated body source it carries."""
    import ast
    from pyobfuscator import obf_module, ModuleObfOptions, ObfOptions
    src = "ACC = 0\n" + "".join(
        "def fn%d(a, b):\n    c = a + b + %d\n    return c * %d\n" % (i, i, i + 1)
        for i in range(50))
    FLAGS = dict(min_blocks=1, shuffle_states=True, bogus_blocks=True, opaque_predicates=True)
    body_src = obf_module(src, ObfOptions(output="text", seed=1, **FLAGS))  # ~the carried body
    out = obf_module(src, ModuleObfOptions(output="text", seed=1, pack_body=True,
                                           key_from_cff=True, pack_decoy=True, **FLAGS))
    assert "b85decode" in out                                   # b85 encoding used
    blobs = [n.value for n in ast.walk(ast.parse(out))
             if isinstance(n, ast.Constant) and isinstance(n.value, bytes)]
    biggest = max(blobs, key=len)
    assert all(32 <= c < 127 for c in biggest)                  # b85 is printable (no \xNN escapes)
    assert len(biggest) < len(body_src) * 0.6                   # body was zlib-compressed first
    ns = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["fn7"](1, 2) == (1 + 2 + 7) * 8                   # body runs correctly


def test_pyc_blob_raw_not_b85():
    """PYC output embeds the blob as raw bytes (b85 would only bloat a binary container). zlib is
    still applied (shrinks the marshalled body too); the roundtrip must still work."""
    import marshal
    from pyobfuscator import obf_module, ModuleObfOptions
    src = "V = 7\ndef t():\n    return V + 1\n"
    out = obf_module(src, ModuleObfOptions(output="pyc", seed=1, min_blocks=1,
                                           pack_body=True, key_from_cff=True, pack_decoy=True))
    assert b"b85decode" not in out                              # no b85 wrapper in the pyc
    ns = {"__name__": "m"}
    exec(marshal.loads(out[16:]), ns)
    assert ns["V"] == 7 and ns["t"]() == 8


def test_obf_imports_no_literal_import_in_launcher():
    import ast
    from pyobfuscator.packer import pack_module
    from pyobfuscator import ModuleObfOptions
    src = "V = 3\ndef f():\n    return V\n"
    # bytecode form exercises the marshal import; key_binds_env exercises the sys import
    launcher = pack_module(ast.parse(src), ModuleObfOptions(
        output="pyc", seed=1, min_blocks=1, pack_format="bytecode",
        key_from_cff=True, pack_decoy=True, integrity_selfcheck=True,
        detect_trace=True, key_binds_env=True, obf_imports=True))
    out = ast.unparse(launcher)
    assert "import marshal" not in out
    assert "import sys" not in out
    assert "__import__" in out  # routed through __import__ instead
    ns = {"__name__": "m"}
    exec(compile(launcher, "<t>", "exec"), ns)
    assert ns["V"] == 3 and ns["f"]() == 3 and "__pyobf_decoy__" not in ns
