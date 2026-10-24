"""Build-time file bytes are archived and remain available without the source file."""
from __future__ import annotations

import marshal
import subprocess
import sys

import pytest

from pyobfuscator import (ModuleObfOptions, ObfOptions, load_bytes,
                          obf_func, obf_module, obf_project)


def _module_source(path):
    return f"from pyobfuscator import load_bytes\nDATA = load_bytes({str(path)!r})\n"


def test_load_bytes_plain_reads_file_each_time(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"first")
    assert load_bytes(path) == b"first"
    path.write_bytes(b"second")
    assert load_bytes(path) == b"second"


@pytest.mark.parametrize("output", ["text", "pyc"])
@pytest.mark.parametrize("const_archive", [False, True])
def test_load_bytes_embeds_archive_without_runtime_file(tmp_path, output, const_archive):
    path = tmp_path / "asset.bin"
    payload = b"ARCHIVE-SECRET\x00\xff"
    path.write_bytes(payload)
    artifact = obf_module(
        _module_source(path),
        ModuleObfOptions(output=output, seed=9, min_blocks=1,
                         obf_strings=False, const_archive=const_archive),
    )
    path.unlink()
    if output == "text":
        assert "load_bytes" not in artifact
        assert "pyobfuscator" not in artifact
        assert str(path) not in artifact
        assert "ARCHIVE-SECRET" not in artifact
        assert "b85decode" in artifact
        code = compile(artifact, "<obf>", "exec")
    else:
        code = marshal.loads(bytes(artifact)[16:])
    ns = {"__name__": "asset_test"}
    exec(code, ns)
    assert ns["DATA"] == payload


def test_load_bytes_uses_current_working_directory(tmp_path, monkeypatch):
    path = tmp_path / "resource.bin"
    path.write_bytes(b"relative")
    monkeypatch.chdir(tmp_path)
    source = "from pyobfuscator import load_bytes\nDATA = load_bytes('resource.bin')\n"
    plain = {}
    exec(source, plain)
    assert plain["DATA"] == b"relative"
    artifact = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    path.unlink()
    frozen = {}
    exec(artifact, frozen)
    assert frozen["DATA"] == b"relative"


def test_load_bytes_empty_and_nonempty_records_do_not_alias(tmp_path):
    empty = tmp_path / "empty.bin"
    full = tmp_path / "full.bin"
    empty.write_bytes(b"")
    full.write_bytes(b"next")
    source = ("from pyobfuscator import load_bytes\n"
              f"A = load_bytes({str(empty)!r})\n"
              f"B = load_bytes({str(full)!r})\n")
    artifact = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    ns = {}
    exec(artifact, ns)
    assert (ns["A"], ns["B"]) == (b"", b"next")


def test_load_bytes_alias_and_attribute_forms(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"alias")
    source = ("from pyobfuscator import load_bytes as read_asset\n"
              "import pyobfuscator as pyo\n"
              f"A = read_asset({str(path)!r})\n"
              f"B = pyo.load_bytes({str(path)!r})\n")
    artifact = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    path.unlink()
    assert "read_asset" not in artifact and "pyobfuscator" not in artifact
    ns = {}
    exec(artifact, ns)
    assert (ns["A"], ns["B"]) == (b"alias", b"alias")


@pytest.mark.parametrize("form", ["expression", "decorator", "helper"])
def test_load_bytes_inside_precompile_still_uses_archive(tmp_path, form):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"nested")
    if form == "expression":
        source = ("from pyobfuscator import precompile, load_bytes\n"
                  f"DATA = precompile(load_bytes({str(path)!r}))\n")
    elif form == "decorator":
        source = ("from pyobfuscator import precompile, load_bytes\n"
                  "@precompile\n"
                  "def DATA():\n"
                  f"    return load_bytes({str(path)!r})\n")
    else:
        source = ("from pyobfuscator import precompile, load_bytes\n"
                  "def read_asset():\n"
                  f"    return load_bytes({str(path)!r})\n"
                  "@precompile\n"
                  "def DATA():\n"
                  "    return read_asset()\n")
    artifact = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    path.unlink()
    assert "b85decode" in artifact
    ns = {}
    exec(artifact, ns)
    assert ns["DATA"] == b"nested"


def test_load_bytes_build_reloads_changed_file(tmp_path):
    path = tmp_path / "asset.bin"
    source = ("from pyobfuscator import precompile, load_bytes\n"
              f"DATA = precompile(load_bytes({str(path)!r}))\n")
    path.write_bytes(b"first")
    first = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    path.write_bytes(b"second")
    second = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    assert first != second
    ns = {}
    exec(second, ns)
    assert ns["DATA"] == b"second"


def test_load_bytes_module_scope_path_expression(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"computed")
    source = ("from pyobfuscator import load_bytes\n"
              f"P = {str(path)!r}\nDATA = load_bytes(P)\n")
    artifact = obf_module(source, ModuleObfOptions(output="text", obf_strings=False))
    path.unlink()
    ns = {}
    exec(artifact, ns)
    assert ns["DATA"] == b"computed"


def test_load_bytes_in_obf_func(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"function")
    source = ("from pyobfuscator import load_bytes\n"
              f"def payload():\n    return load_bytes({str(path)!r})\n")
    artifact = obf_func(source, ObfOptions(output="text", obf_strings=False))
    path.unlink()
    ns = {}
    exec(artifact, ns)
    assert ns["payload"]() == b"function"


@pytest.mark.parametrize("import_hook", [False, True])
def test_load_bytes_in_protected_project_satellite(tmp_path, import_hook):
    root = tmp_path / "src"
    app = root / "app"
    app.mkdir(parents=True)
    (root / "main.py").write_text(
        "from app.secret import read\nif __name__ == '__main__':\n    print(read().hex())\n",
        encoding="utf-8")
    (app / "__init__.py").write_text("", encoding="utf-8")
    asset = root / "resource.bin"
    asset.write_bytes(b"project\x00bytes")
    (app / "secret.py").write_text(
        "from pyobfuscator import load_bytes\n"
        f"def read():\n    return load_bytes({str(asset)!r})\n",
        encoding="utf-8")
    out = tmp_path / "dist"
    obf_project(root=str(root), out=str(out), entry="main.py",
                protect=["app/secret.py"], import_hook=import_hook,
                options=ModuleObfOptions(output="text", seed=7, min_blocks=1,
                                         pack_body=True, key_from_cff=True,
                                         attest=True, obf_strings=False))
    asset.unlink()
    run = subprocess.run([sys.executable, str(out / "main.py")],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == b"project\x00bytes".hex()


@pytest.mark.parametrize("call", ["load_bytes()", "load_bytes('a', 'b')",
                                        "load_bytes(filepath='a')"])
def test_load_bytes_invalid_build_call_rejected(call):
    source = f"from pyobfuscator import load_bytes\nP = 'asset.bin'\nDATA = {call}\n"
    with pytest.raises(ValueError, match="load_bytes"):
        obf_module(source, ModuleObfOptions(output="text"))


def test_load_bytes_function_parameter_cannot_be_precompiled():
    source = "from pyobfuscator import load_bytes\ndef read(path):\n    return load_bytes(path)\n"
    with pytest.raises(ValueError, match="load_bytes\\(path\\)"):
        obf_module(source, ModuleObfOptions(output="text"))


def test_load_bytes_missing_file_fails_at_build(tmp_path):
    with pytest.raises(ValueError, match="load_bytes.*could not read file at build time"):
        obf_module(_module_source(tmp_path / "missing.bin"),
                   ModuleObfOptions(output="text"))
