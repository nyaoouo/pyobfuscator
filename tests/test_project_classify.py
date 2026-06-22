import os

import pytest

from pyobfuscator.protect.project import classify_files, Role


def _touch(p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write("x = 1\n")


def test_classify_entry_protect_plaintext(tmp_path):
    root = str(tmp_path)
    for rel in ("main.py", "app/__init__.py", "app/secret.py", "app/logic.py"):
        _touch(os.path.join(root, rel))
    result = classify_files(root, entry="main.py", protect=["app/secret.py"])
    assert result["main.py"] is Role.ENTRY
    assert result["app/secret.py"] is Role.PROTECT
    assert result["app/logic.py"] is Role.PLAINTEXT
    assert result["app/__init__.py"] is Role.PLAINTEXT


def test_classify_protect_glob(tmp_path):
    root = str(tmp_path)
    for rel in ("main.py", "app/a.py", "app/b.py"):
        _touch(os.path.join(root, rel))
    result = classify_files(root, entry="main.py", protect=["app/*.py"])
    assert result["app/a.py"] is Role.PROTECT
    assert result["app/b.py"] is Role.PROTECT


def test_classify_entry_never_protected(tmp_path):
    # A protect glob that also matches the entry must not reclassify the entry.
    root = str(tmp_path)
    for rel in ("main.py", "app/a.py"):
        _touch(os.path.join(root, rel))
    result = classify_files(root, entry="main.py", protect=["**/*.py", "*.py"])
    assert result["main.py"] is Role.ENTRY


def test_classify_entry_must_exist(tmp_path):
    _touch(os.path.join(str(tmp_path), "main.py"))
    with pytest.raises(ValueError):
        classify_files(str(tmp_path), entry="nope.py", protect=[])


def test_classify_protect_pattern_must_match(tmp_path):
    _touch(os.path.join(str(tmp_path), "main.py"))
    with pytest.raises(ValueError):
        classify_files(str(tmp_path), entry="main.py", protect=["app/ghost.py"])
