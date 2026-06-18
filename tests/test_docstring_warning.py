"""#1 — docstrings are NOT stripped (preserving __doc__ equivalence); the obfuscator WARNS that they
leak as plaintext so the user can remove sensitive ones themselves."""
import warnings

import pytest

from pyobfuscator import obf_module, obf_func
from pyobfuscator.options import ModuleObfOptions, ObfOptions, OutputFormat


def test_module_docstring_warns():
    src = '"""sensitive module description here"""\ndef f(x):\n    return x + 1\n'
    with pytest.warns(UserWarning, match="docstrings are PRESERVED"):
        obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=1))


def test_no_docstring_no_warn():
    src = "x = 1\ndef f(y):\n    return y + 1\n"
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=1))
    assert not any("docstrings are PRESERVED" in str(x.message) for x in w)


def test_module_docstring_preserved_plaintext_in_output():
    # confirm the warning is truthful: the module docstring really does survive verbatim.
    src = '"""LEAKYDOCSTRING42"""\ndef f(x):\n    return x + 1\n'
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=1, obf_strings=True))
    assert "LEAKYDOCSTRING42" in out


def test_func_docstring_warns_only_without_string_obf():
    src = "def f(x):\n    '''fn doc'''\n    return x + 1\n"
    # string-obf ON -> the function docstring is encoded -> no docstring leak warning
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=1, obf_strings=True))
    assert not any("docstrings are PRESERVED" in str(x.message) for x in w)
    # string-obf OFF -> the function docstring stays plaintext -> warn
    with pytest.warns(UserWarning, match="docstrings are PRESERVED"):
        obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=1, obf_strings=False, const_archive=False))


# ---- version-lock warning: cohash_integrity hashes co_code (version-specific) -> TEXT not portable ----

_NODOC = "def f(x):\n    return x + 1\n"


def test_text_cohash_warns_version_lock():
    with pytest.warns(UserWarning, match="LOCKED to the build Python"):
        obf_module(_NODOC, ModuleObfOptions(output=OutputFormat.TEXT, seed=1, pack_body=True,
                                            key_from_cff=True, cohash_integrity=True))


def test_pyc_cohash_no_version_warn():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        obf_module(_NODOC, ModuleObfOptions(output=OutputFormat.PYC, seed=1, pack_body=True,
                                            key_from_cff=True, cohash_integrity=True))
    assert not any("LOCKED to the build Python" in str(x.message) for x in w)


def test_text_without_cohash_no_version_warn():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        obf_module(_NODOC, ModuleObfOptions(output=OutputFormat.TEXT, seed=1, pack_body=True,
                                            key_from_cff=True, cohash_integrity=False))
    assert not any("LOCKED to the build Python" in str(x.message) for x in w)
