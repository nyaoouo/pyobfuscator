import os
import subprocess
import sys

import pytest

from pyobfuscator import obf_project, ModuleObfOptions


def _write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def _full():
    return dict(output="text", seed=8, pack_body=True, key_from_cff=True,
                pack_decoy=True, attest=True)


def test_import_hook_centralized(tmp_path):
    src = str(tmp_path / "src")
    out = str(tmp_path / "dist")
    _write(src + "/main.py",
           "from app.secret import f\n"
           "import sys\n"
           "def main():\n    print('R', f(int(sys.argv[1])))\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(src + "/app/__init__.py", "")
    _write(src + "/app/logic.py",
           "from app.secret import f\n"
           "def via_logic(n):\n    return f(n) + 1\n")
    _write(src + "/app/secret.py", "def f(x):\n    return x * x\n")

    obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                options=ModuleObfOptions(**_full()), import_hook=True)

    # centralized: the satellite file is NOT emitted (its blob lives in the entry's registry)
    assert not os.path.exists(os.path.join(out, "app", "secret.py"))
    # plaintext package files ARE present
    assert os.path.exists(os.path.join(out, "app", "__init__.py"))
    assert os.path.exists(os.path.join(out, "app", "logic.py"))
    # genuine run: the entry's finder serves app.secret on import
    r = subprocess.run([sys.executable, os.path.join(out, "main.py"), "6"],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, r.stderr
    assert "R 36" in r.stdout, (r.stdout, r.stderr)


def test_import_hook_requires_shared_stack(tmp_path):
    # import_hook without the attest stack is rejected (the finder needs the published dec).
    src = str(tmp_path / "src")
    out = str(tmp_path / "dist")
    _write(src + "/main.py", "def main():\n    pass\n")
    _write(src + "/app/__init__.py", "")
    _write(src + "/app/secret.py", "X = 1\n")
    with pytest.raises(ValueError):
        obf_project(root=src, out=out, entry="main.py", protect=["app/secret.py"],
                    options=ModuleObfOptions(output="text", seed=1), import_hook=True)
