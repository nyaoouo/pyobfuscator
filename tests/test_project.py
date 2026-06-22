"""Suite-level smoke for obf_project: partial-update + determinism (text) and the pyc path."""
import os
import shutil
import subprocess
import sys

from pyobfuscator import obf_project, ModuleObfOptions


def _write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def _proj(root, ver):
    _write(root + "/main.py",
           "from app.logic import show\n"
           "def main():\n    print(show())\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(root + "/app/__init__.py", "")
    _write(root + "/app/secret.py", "def tag():\n    return %r\n" % ver)
    _write(root + "/app/logic.py",
           "from app.secret import tag\n"
           "def show():\n    return 'ver=' + tag()\n")


def _opts(fmt="text", seed=21):
    return ModuleObfOptions(output=fmt, seed=seed, pack_body=True, key_from_cff=True,
                            pack_decoy=True, attest=True)


def _run(path, *args):
    r = subprocess.run([sys.executable, path, *args], capture_output=True, text=True, timeout=120)
    return r


def test_partial_update_only_secret_and_determinism(tmp_path):
    src1 = str(tmp_path / "src1")
    _proj(src1, "V1")
    out1 = str(tmp_path / "out1")
    out1b = str(tmp_path / "out1b")
    obf_project(root=src1, out=out1, entry="main.py", protect=["app/secret.py"], options=_opts())
    obf_project(root=src1, out=out1b, entry="main.py", protect=["app/secret.py"], options=_opts())
    # determinism: same source + seed -> byte-identical entry and satellite
    assert open(os.path.join(out1, "main.py")).read() == open(os.path.join(out1b, "main.py")).read()
    assert (open(os.path.join(out1, "app", "secret.py")).read()
            == open(os.path.join(out1b, "app", "secret.py")).read())

    # change ONLY secret, rebuild (same seed) into out2, then swap just secret.py into out1
    src2 = str(tmp_path / "src2")
    _proj(src2, "V2")
    out2 = str(tmp_path / "out2")
    obf_project(root=src2, out=out2, entry="main.py", protect=["app/secret.py"], options=_opts())
    # main is independent of secret's content (s_correct = f(seed)) -> identical entry
    assert open(os.path.join(out1, "main.py")).read() == open(os.path.join(out2, "main.py")).read()
    shutil.copyfile(os.path.join(out2, "app", "secret.py"), os.path.join(out1, "app", "secret.py"))
    # the V1-era entry runs the swapped-in V2 satellite
    r = _run(os.path.join(out1, "main.py"))
    assert r.returncode == 0, r.stderr
    assert "ver=V2" in r.stdout, (r.stdout, r.stderr)


def test_project_pyc_runs(tmp_path):
    src = str(tmp_path / "src")
    _write(src + "/main.py",
           "from app.secret import tag\n"
           "def main():\n    print('ver=' + tag())\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(src + "/app/__init__.py", "")
    _write(src + "/app/secret.py", "def tag():\n    return 'PYC'\n")
    out = str(tmp_path / "dist")
    obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                options=_opts(fmt="pyc", seed=9))
    # obfuscated files are sourceless .pyc; the plaintext package marker stays .py
    assert os.path.exists(os.path.join(out, "main.pyc"))
    assert os.path.exists(os.path.join(out, "app", "secret.pyc"))
    assert os.path.exists(os.path.join(out, "app", "__init__.py"))
    r = _run(os.path.join(out, "main.pyc"))
    assert r.returncode == 0, r.stderr
    assert "ver=PYC" in r.stdout, (r.stdout, r.stderr)
