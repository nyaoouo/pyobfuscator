"""Beta (default) vs alpha (`shared_oracle_decouple`) oracle binding, and satellite attestation."""
import ast
import os
import subprocess
import sys
import zlib

from pyobfuscator import obf_project, ModuleObfOptions, _MODULE_PIPELINE
from pyobfuscator.cff.module_wrap import wrap_module
from pyobfuscator.cff.attest import MAGIC, dec_name
from pyobfuscator.protect import core
from pyobfuscator.protect.cipher import _kdf, _ks_xor, _SALT_SEL, _MASK


def _write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def _proj(root):
    _write(root + "/main.py",
           "from app.secret import token\n"
           "def main():\n    print('TOK', token())\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(root + "/app/__init__.py", "")
    _write(root + "/app/secret.py", "def token():\n    return 'REALTOKEN'\n")


def _opts():
    return ModuleObfOptions(output="text", seed=44, pack_body=True, key_from_cff=True,
                            pack_decoy=True, attest=True)


def _run(out):
    r = subprocess.run([sys.executable, os.path.join(out, "main.py")],
                       capture_output=True, text=True, timeout=90)
    return r.stdout


def test_beta_and_alpha_genuine_run(tmp_path):
    for decouple in (False, True):                      # beta (default), then alpha
        src = str(tmp_path / ("s_%s" % decouple))
        out = str(tmp_path / ("d_%s" % decouple))
        _proj(src)
        obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                    options=_opts(), shared_oracle_decouple=decouple)
        assert "TOK REALTOKEN" in _run(out), ("decouple=%s" % decouple)


def test_beta_alpha_entry_differs_satellite_identical(tmp_path):
    src = str(tmp_path / "src")
    _proj(src)
    ob = str(tmp_path / "beta")
    oa = str(tmp_path / "alpha")
    obf_project(root=src, out=ob, entry="main.py", protect=["app/secret.py"],
                options=_opts(), shared_oracle_decouple=False)
    obf_project(root=src, out=oa, entry="main.py", protect=["app/secret.py"],
                options=_opts(), shared_oracle_decouple=True)
    beta_entry = open(os.path.join(ob, "main.py")).read()
    alpha_entry = open(os.path.join(oa, "main.py")).read()
    beta_sat = open(os.path.join(ob, "app", "secret.py")).read()
    alpha_sat = open(os.path.join(oa, "app", "secret.py")).read()
    # the binding flag changes ONLY the entry's published dec (runtime selector vs build constant)
    assert beta_entry != alpha_entry
    # satellites are byte-identical between beta and alpha (built against s_correct = f(seed))
    assert beta_sat == alpha_sat


def test_satellite_dump_replay_diverges(tmp_path):
    # Attestation: a satellite's real body, run WITHOUT the launcher-injected oracle, must diverge
    # (it binds the decoy oracle via setdefault -> wrong gated states). Killable subprocess.
    opts = ModuleObfOptions(output="text", seed=77, pack_body=True, key_from_cff=True,
                            pack_decoy=True, attest=True, min_blocks=1)
    body_src = ("def compute():\n"
                "    t = 0\n"
                "    for i in range(5):\n"
                "        t = t + i * 2\n"
                "    return t\n"
                "RESULT = compute()\n")            # genuine RESULT == 20
    tree = ast.parse(body_src)
    tree = _MODULE_PIPELINE.run(tree, opts)
    tree = wrap_module(tree, opts)
    s_correct = core.project_s_correct(opts)
    _stub, blob, table, default = core.build_satellite(
        tree, opts, module_id="m.secret", s_correct=s_correct, magic=MAGIC(opts.seed),
        dec_name_str=dec_name(opts.seed), decoy_tree=None)
    sel = _kdf((s_correct ^ _SALT_SEL) & _MASK)
    ent = table[sel]
    key = (ent[2] ^ (s_correct * ent[3])) & _MASK
    body = zlib.decompress(_ks_xor(blob[ent[0]:ent[0] + ent[1]], key)).decode("utf-8")
    probe = ("import sys\n"
             "src = sys.stdin.read()\n"
             "ns = {}\n"
             "try:\n"
             "    exec(compile(src, '<replay>', 'exec'), ns)\n"
             "    print('VALUE', ns.get('RESULT'))\n"
             "except BaseException as e:\n"
             "    print('DIVERGED', type(e).__name__)\n")
    try:
        r = subprocess.run([sys.executable, "-c", probe], input=body,
                           capture_output=True, text=True, timeout=15)
        out = r.stdout
    except subprocess.TimeoutExpired:
        out = "DIVERGED hang"                     # busy-loop = diverged = protected
    assert "VALUE 20" not in out, out             # the real result must NOT survive without the oracle
