"""PyInstaller collection and frozen-entry regressions.

The integration tests use real bundles: an in-process exec cannot prove that
``detect_stack`` sees the same entry boundary as PyInstaller's bootloader.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

from pyobfuscator import (ModuleObfOptions, collect_pyinstaller_imports,
                          obf_module, obf_project, write_pyinstaller_hook)


def _write(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _bundle(entry: Path, hook: Path, build: Path, mode: str) -> Path:
    if importlib.util.find_spec("PyInstaller") is None:
        pytest.skip("PyInstaller is not installed")
    name = f"frozen_{mode}"
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", f"--{mode}",
           "--name", name, "--runtime-hook", str(hook),
           "--distpath", str(build / "dist"), "--workpath", str(build / "work"),
           "--specpath", str(build), str(entry)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    exe = name + (".exe" if os.name == "nt" else "")
    return build / "dist" / (name if mode == "onedir" else "") / exe


def _run(exe: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)


def test_generated_hook_collects_static_imports_without_running_them(tmp_path):
    source = tmp_path / "src"
    _write(source / "main.py", "from app.logic import run\nimport json\n")
    _write(source / "app" / "__init__.py", "")
    _write(source / "app" / "logic.py", "from .secret import answer\n")
    _write(source / "app" / "secret.py", "import decimal\n")
    manifest = {"main.py": "entry", "app/__init__.py": "plaintext",
                "app/logic.py": "plaintext", "app/secret.py": "protect"}
    imports = collect_pyinstaller_imports(
        source, manifest=manifest, import_hook=True, extra_imports=("fractions",))
    assert imports == ["app", "app.logic", "decimal", "fractions", "json"]

    hook = tmp_path / "pyi_rth.py"
    assert write_pyinstaller_hook(source, hook, manifest=manifest,
                                  import_hook=True, extra_imports=("fractions",)) == imports
    text = hook.read_text(encoding="utf-8")
    assert "import app.secret" not in text
    assert "    import decimal" in text
    exec(compile(text, str(hook), "exec"), {})  # definition only: no imports or stack frame persist


def test_generated_hook_omits_build_marker_only_imports(tmp_path):
    original = tmp_path / "main.py"
    _write(original, "from pyobfuscator import load_bytes, precompile\n"
           "import json\nDATA = load_bytes('asset.bin')\nVALUE = precompile(2)\n")
    assert collect_pyinstaller_imports(original) == ["json"]


def test_generated_hook_keeps_unfolded_marker_import(tmp_path):
    original = tmp_path / "main.py"
    _write(original, "from pyobfuscator import load_bytes\nREADER = load_bytes\n")
    assert collect_pyinstaller_imports(original) == ["pyobfuscator"]


def test_import_hook_requires_manifest(tmp_path):
    _write(tmp_path / "main.py", "import json\n")
    with pytest.raises(ValueError, match="requires the obf_project manifest"):
        collect_pyinstaller_imports(tmp_path, import_hook=True)


def test_extra_imports_reject_invalid_module_names(tmp_path):
    _write(tmp_path / "main.py", "pass\n")
    with pytest.raises(ValueError, match="invalid module name"):
        collect_pyinstaller_imports(tmp_path / "main.py", extra_imports=("class",))


@pytest.mark.parametrize("mode", ["onedir", "onefile"])
def test_frozen_single_entry_keeps_stack_and_hidden_imports(tmp_path, mode):
    source = tmp_path / "src"
    _write(source / "dep.py", "def answer():\n    return 73\n")
    original = source / "main.py"
    _write(original, "import dep\n"
           "def label():\n    if dep.answer() == 73:\n        return 'REAL'\n"
           "    return 'WRONG'\n"
           "if __name__ == '__main__':\n    print(label(), dep.answer())\n")
    out = tmp_path / "obf"
    out.mkdir()
    opts = ModuleObfOptions(
        output="text", seed=14, min_blocks=1, protect_level="full",
        detect_stack=True, compress_output=True, compress_rounds=2,
        attest=True, const_archive=True, name_vault=True,
        name_vault_attrs=True, obf_ints=True, hide_compares=True,
        cohash_integrity=True, detect_audit=True, attest_runtime_bind=True,
        anti_trace_neuter=True, handler_src="print('STACKSIG', M.STACK)",
    )
    entry = out / "main.py"
    with pytest.warns(UserWarning, match="cohash_integrity hashes co_code"):
        entry.write_text(obf_module(original.read_text(encoding="utf-8"), opts),
                         encoding="utf-8")
    hook = out / "pyi_rth_pyobfuscator.py"
    assert "dep" in write_pyinstaller_hook(original, hook)
    # PyInstaller resolves a hidden import relative to the protected entry.
    _write(out / "dep.py", (source / "dep.py").read_text(encoding="utf-8"))
    frozen = _run(_bundle(entry, hook, tmp_path / "build", mode))
    assert frozen.returncode == 0, (frozen.stdout, frozen.stderr)
    assert frozen.stdout.strip().splitlines() == ["STACKSIG 0", "REAL 73"]


@pytest.mark.parametrize("mode", ["onedir", "onefile"])
def test_frozen_text_entry_with_bytecode_body_cohash(tmp_path, mode):
    original = tmp_path / "main_original.py"
    _write(original, "VALUE = 321\nif __name__ == '__main__':\n    print('REAL', VALUE)\n")
    opts = ModuleObfOptions(
        output="text", pack_format="bytecode", seed=4, min_blocks=1,
        pack_body=True, key_from_cff=True, integrity_selfcheck=True,
        pack_decoy=True, key_binds_env=True, detect_stack=True,
        attest=True, body_cohash=True, cohash_integrity=True,
        compress_output=True, compress_rounds=2,
        handler_src="print('STACKSIG', M.STACK)",
    )
    entry = tmp_path / "main.py"
    with pytest.warns(UserWarning, match="body_cohash.*locks this TEXT artifact"):
        entry.write_text(obf_module(original.read_text(encoding="utf-8"), opts),
                         encoding="utf-8")
    hook = tmp_path / "pyi_rth.py"
    write_pyinstaller_hook(original, hook)
    frozen = _run(_bundle(entry, hook, tmp_path / "build", mode))
    assert frozen.returncode == 0, (frozen.stdout, frozen.stderr)
    assert frozen.stdout.strip().splitlines() == ["STACKSIG 0", "REAL 321"]


def test_frozen_load_bytes_needs_no_external_asset(tmp_path):
    asset = tmp_path / "asset.bin"
    asset.write_bytes(b"frozen\x00asset")
    original = tmp_path / "main_original.py"
    _write(original, "from pyobfuscator import load_bytes\n"
           f"if __name__ == '__main__':\n    print(load_bytes({str(asset)!r}).hex())\n")
    entry = tmp_path / "main.py"
    entry.write_text(obf_module(original.read_text(encoding="utf-8"), ModuleObfOptions(
        output="text", seed=6, min_blocks=1, pack_body=True, key_from_cff=True,
        detect_stack=True, key_binds_env=True,
        handler_src="print('STACKSIG', M.STACK)",
    )), encoding="utf-8")
    hook = tmp_path / "pyi_rth.py"
    assert write_pyinstaller_hook(original, hook) == []
    asset.unlink()
    frozen = _run(_bundle(entry, hook, tmp_path / "build", "onedir"))
    assert frozen.returncode == 0, (frozen.stdout, frozen.stderr)
    assert frozen.stdout.strip().splitlines() == ["STACKSIG 0", b"frozen\x00asset".hex()]


@pytest.mark.parametrize("import_hook", [False, True])
@pytest.mark.parametrize("bytecode_body", [False, True])
def test_frozen_multi_module_project(tmp_path, import_hook, bytecode_body):
    source = tmp_path / "src"
    _write(source / "main.py", "from app.logic import value\n"
           "if __name__ == '__main__':\n    print('PROJECT', value())\n")
    _write(source / "app" / "__init__.py", "")
    _write(source / "app" / "logic.py", "from .secret import answer\n"
           "def value():\n    return answer()\n")
    _write(source / "app" / "secret.py", "def answer():\n    return 91\n")
    out = tmp_path / "obf"
    opts = ModuleObfOptions(output="text", seed=18, min_blocks=1,
                            pack_format="bytecode" if bytecode_body else "source",
                            pack_body=True, key_from_cff=True, pack_decoy=True,
                            attest=True, body_cohash=bytecode_body,
                            key_binds_env=True, detect_stack=True)
    if bytecode_body:
        with pytest.warns(UserWarning, match="body_cohash.*locks this TEXT artifact"):
            manifest = obf_project(root=str(source), out=str(out), entry="main.py",
                                   protect=["app/secret.py"], options=opts,
                                   import_hook=import_hook)
    else:
        manifest = obf_project(root=str(source), out=str(out), entry="main.py",
                               protect=["app/secret.py"], options=opts,
                               import_hook=import_hook)
    hook = tmp_path / "pyi_rth_project.py"
    imports = write_pyinstaller_hook(source, hook, manifest=manifest,
                                     import_hook=import_hook)
    if import_hook:
        assert "app.secret" not in imports
        assert not (out / "app" / "secret.py").exists()
    else:
        assert "app.secret" in imports
    frozen = _run(_bundle(out / "main.py", hook, tmp_path / "build", "onedir"))
    assert frozen.returncode == 0, (frozen.stdout, frozen.stderr)
    assert frozen.stdout.strip() == "PROJECT 91"
