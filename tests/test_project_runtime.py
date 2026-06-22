import ast

from pyobfuscator.protect import astutil


def _compiles(fn_node):
    mod = ast.Module(body=[fn_node], type_ignores=[])
    ast.fix_missing_locations(mod)
    compile(mod, "<t>", "exec")


def test_mkdec_template_parses_and_compiles():
    fn = astutil.emit_def("t_mkdec", t_mkdec="_mk")
    assert isinstance(fn, ast.FunctionDef) and fn.name == "_mk"
    _compiles(fn)


def test_mkdec_bc_template_parses_and_compiles():
    fn = astutil.emit_def("t_mkdec_bc", t_mkdec_bc="_mkb")
    assert isinstance(fn, ast.FunctionDef) and fn.name == "_mkb"
    _compiles(fn)


def test_mkdec_factory_roundtrip_executes():
    # Instantiate the factory, call it with concrete cipher fns, and confirm the returned _d
    # decrypts + execs a real+decoy bigblob the way build_satellite will lay it out.
    import zlib
    from pyobfuscator.protect.cipher import _kdf, _ks_xor, _SALT_SEL, _SALT_KEY, _SALT_DECOY, _MASK

    fn = astutil.emit_def("t_mkdec", t_mkdec="_mk")
    ns = {}
    mod = ast.Module(body=[fn], type_ignores=[]); ast.fix_missing_locations(mod)
    exec(compile(mod, "<t>", "exec"), ns)
    mk = ns["_mk"]

    s_correct = 0xABCDEF12345
    body_src = "def f(x):\n    return x * 3\n"
    e_real = _ks_xor(zlib.compress(body_src.encode()), _kdf((s_correct ^ _SALT_KEY) & _MASK))
    e_decoy = _ks_xor(zlib.compress(b"raise SystemExit(1)"), _kdf(_SALT_DECOY))
    bigblob = e_real + e_decoy
    sel = _kdf((s_correct ^ _SALT_SEL) & _MASK)
    table = {sel: (0, len(e_real), (_kdf((s_correct ^ _SALT_KEY) & _MASK) ^ s_correct) & _MASK, 1)}
    default = (len(e_real), len(e_decoy), _kdf(_SALT_DECOY), 0)

    dec = mk(s_correct, _ks_xor, _kdf, "ORACLE_SENTINEL", "_oname", zlib, _SALT_SEL, _MASK, "<x>")
    g = {}
    dec(bigblob, table, default, "app.secret", g)
    assert g["f"](14) == 42                 # real body materialized
    assert g["_oname"] == "ORACLE_SENTINEL"  # oracle injected into the satellite globals


def test_build_satellite_roundtrip():
    import zlib
    from pyobfuscator import _MODULE_PIPELINE
    from pyobfuscator.cff.module_wrap import wrap_module
    from pyobfuscator.options import ModuleObfOptions
    from pyobfuscator.protect import core
    from pyobfuscator.protect.cipher import _kdf, _ks_xor, _SALT_SEL, _MASK

    opts = ModuleObfOptions(output="text", seed=11, pack_body=True, key_from_cff=True,
                            pack_decoy=True, attest=False)
    tree = ast.parse("def f(x):\n    return x + 1\n")
    tree = _MODULE_PIPELINE.run(tree, opts)
    tree = wrap_module(tree, opts)
    s_correct = core.project_s_correct(opts)
    stub, blob, table, default = core.build_satellite(
        tree, opts, module_id="app.secret", s_correct=s_correct, magic=0,
        dec_name_str="__pyobf_dec_test__", decoy_tree=None)

    # recover the real slice with the shared selector (the dec's exact computation)
    sel = _kdf((s_correct ^ _SALT_SEL) & _MASK)
    ent = table.get(sel, default)
    key = (ent[2] ^ (s_correct * ent[3])) & _MASK
    src = zlib.decompress(_ks_xor(blob[ent[0]:ent[0] + ent[1]], key)).decode("utf-8")
    ns = {}
    exec(compile(src, "<x>", "exec"), ns)
    assert ns["f"](41) == 42

    stub_src = ast.unparse(stub)
    assert "x + 1" not in stub_src          # the body is encrypted, not in the stub
    assert "getattr" in stub_src            # stub resolves + calls the published dec
    assert "__pyobf_dec_test__" not in stub_src  # dec name is char-code hidden, not a literal


def test_salt_module_distinguishes_modules():
    from pyobfuscator.protect import core
    assert core._salt_module("app.a") != core._salt_module("app.b")


def _write(p, s):
    import os
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def _shared_project(root):
    _write(root + "/main.py",
           "from app.logic import greet\nimport sys\n"
           "def main():\n    print(greet(sys.argv[1]))\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(root + "/app/__init__.py", "")
    _write(root + "/app/secret.py", "def transform(s):\n    return s[::-1]\n")
    _write(root + "/app/logic.py",
           "from app.secret import transform\n"
           "def greet(n):\n    return 'r=' + transform(n)\n")


def test_project_shared_runtime_runs(tmp_path):
    import os
    import subprocess
    import sys
    from pyobfuscator import obf_project, ModuleObfOptions

    src = str(tmp_path / "src")
    out = str(tmp_path / "dist")
    _shared_project(src)
    obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                options=ModuleObfOptions(output="text", seed=33, pack_body=True, key_from_cff=True,
                                         pack_decoy=True, attest=True))
    stub = open(os.path.join(out, "app", "secret.py")).read()
    assert "[::-1]" not in stub                 # body is encrypted, not in the stub
    assert "transform" not in stub              # no plaintext symbols
    r = subprocess.run([sys.executable, os.path.join(out, "main.py"), "abc"],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stderr
    assert "r=cba" in r.stdout, (r.stdout, r.stderr)


def test_foreign_import_fails_loud(tmp_path):
    # D7: importing a satellite WITHOUT the entry (so the shared dec was never published to builtins)
    # must fail loud — not silently load garbage. Killable subprocess.
    import os
    import subprocess
    import sys
    from pyobfuscator import obf_project, ModuleObfOptions

    src = str(tmp_path / "src")
    out = str(tmp_path / "dist")
    _write(src + "/main.py", "def main():\n    pass\n")
    _write(src + "/app/__init__.py", "")
    _write(src + "/app/secret.py", "VALUE = 99\ndef get():\n    return VALUE\n")
    obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                options=ModuleObfOptions(output="text", seed=5, pack_body=True, key_from_cff=True,
                                         pack_decoy=True, attest=True))
    probe = ("import sys\n"
             "sys.path.insert(0, %r)\n"
             "try:\n"
             "    import app.secret\n"
             "    print('LOADED', getattr(app.secret, 'VALUE', None))\n"
             "except BaseException as e:\n"
             "    print('FAILED', type(e).__name__)\n" % out)
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=30)
    assert "FAILED" in r.stdout, (r.stdout, r.stderr)
    assert "LOADED" not in r.stdout

