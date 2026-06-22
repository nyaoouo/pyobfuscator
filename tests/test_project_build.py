import os
import subprocess
import sys

from pyobfuscator import obf_project, ModuleObfOptions


def _write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def _make_project(root):
    _write(os.path.join(root, "main.py"),
           "from app.logic import greet\n"
           "import sys\n"
           "def main():\n"
           "    print(greet(sys.argv[1] if len(sys.argv) > 1 else 'x'))\n"
           "if __name__ == '__main__':\n"
           "    main()\n")
    _write(os.path.join(root, "app/__init__.py"), "")
    _write(os.path.join(root, "app/secret.py"),
           "def transform(s):\n    return s.upper() + '!'\n")
    _write(os.path.join(root, "app/logic.py"),
           "from app.secret import transform\n"
           "def greet(name):\n    return 'hi ' + transform(name)\n")


def test_obf_project_builds_and_runs(tmp_path):
    src = os.path.join(str(tmp_path), "src")
    out = os.path.join(str(tmp_path), "dist")
    _make_project(src)
    manifest = obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                           options=ModuleObfOptions(output="text", seed=7))
    # manifest reports roles
    assert manifest["main.py"] == "entry"
    assert manifest["app/secret.py"] == "protect"
    assert manifest["app/logic.py"] == "plaintext"
    # tree mirrored
    assert os.path.exists(os.path.join(out, "main.py"))
    assert os.path.exists(os.path.join(out, "app/secret.py"))
    assert os.path.exists(os.path.join(out, "app/logic.py"))
    # plaintext copied verbatim
    assert (open(os.path.join(out, "app/logic.py")).read()
            == open(os.path.join(src, "app/logic.py")).read())
    # protected secret.py is NOT the original source
    assert "s.upper()" not in open(os.path.join(out, "app/secret.py")).read()
    # end-to-end genuine run (reverse import: logic -> secret)
    r = subprocess.run([sys.executable, os.path.join(out, "main.py"), "bob"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "hi BOB!" in r.stdout


def test_obf_project_plaintext_only_tree(tmp_path):
    # A project with no protected files still mirrors the tree (all plaintext copies).
    src = os.path.join(str(tmp_path), "src")
    out = os.path.join(str(tmp_path), "dist")
    _write(os.path.join(src, "main.py"), "def main():\n    print('ok')\n")
    _write(os.path.join(src, "util.py"), "K = 1\n")
    obf_project(root=src, out=out, entry="main.py", protect=[],
                options=ModuleObfOptions(output="text", seed=1))
    assert open(os.path.join(out, "util.py")).read() == "K = 1\n"
    # entry is obfuscated even with no protected satellites
    assert os.path.exists(os.path.join(out, "main.py"))
