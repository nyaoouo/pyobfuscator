"""require_min_python: a PLAINTEXT min-version guard in the OUTERMOST TEXT layer. Enforces
MIN_SUPPORTED_PYTHON (the obfuscator's declared floor) with a clean SystemExit message. TEXT-only
(compress_output -> top of bootstrap; else top of source after docstring/__future__); PYC/AST warn+skip."""
import subprocess
import sys
import warnings

import pytest

import pyobfuscator
from pyobfuscator import obf_module, ModuleObfOptions, MIN_SUPPORTED_PYTHON


def _run(src_text, *argv):
    r = subprocess.run([sys.executable, "-c", src_text, *argv], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def test_min_supported_matches_runtime_floor():
    assert isinstance(MIN_SUPPORTED_PYTHON, tuple) and len(MIN_SUPPORTED_PYTHON) == 2
    assert sys.version_info[:2] >= MIN_SUPPORTED_PYTHON   # we run on a supported interpreter


def test_guard_present_and_runs_text_uncompressed():
    out = obf_module("print('ran')\n", ModuleObfOptions(output="text", seed=1, min_blocks=1,
                                                         require_min_python=True))
    assert "_pyx_sys.version_info" in out and "SystemExit" in out      # plaintext guard present
    rc, so, se = _run(out)
    assert rc == 0 and "ran" in so, (rc, so, se)


def test_guard_present_and_runs_text_compressed():
    out = obf_module("print('ran')\n", ModuleObfOptions(output="text", seed=1, min_blocks=1,
                                                         require_min_python=True, compress_output=True))
    # guard is ABOVE the compression bootstrap (runs before any decode/exec)
    assert out.startswith("import sys as _pyx_sys")
    assert out.index("_pyx_sys.version_info") < out.index("__import__('zlib')")
    rc, so, se = _run(out)
    assert rc == 0 and "ran" in so, (rc, so, se)


def test_guard_blocks_too_old_interpreter(monkeypatch):
    """Fake a FUTURE floor so the current interpreter is 'too old' -> the guard SystemExits."""
    monkeypatch.setattr(pyobfuscator, "MIN_SUPPORTED_PYTHON", (9, 9))
    for compress in (False, True):
        out = obf_module("print('SHOULD-NOT-RUN')\n",
                         ModuleObfOptions(output="text", seed=1, min_blocks=1,
                                          require_min_python=True, compress_output=compress))
        rc, so, se = _run(out)
        assert rc != 0, ("expected SystemExit", compress, rc, so)
        assert "SHOULD-NOT-RUN" not in so, ("ran despite the guard", compress, so)
        assert "9.9" in (so + se), ("no version message", compress, so, se)


def test_guard_is_future_safe(monkeypatch):
    """A source with `from __future__` must still parse — the guard is inserted AFTER it, not before."""
    src = "from __future__ import annotations\nprint('ok')\n"
    out = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1, require_min_python=True))
    assert out.index("from __future__") < out.index("_pyx_sys")   # __future__ stays first
    rc, so, se = _run(out)
    assert rc == 0 and "ok" in so, (rc, so, se)
    # and it actually blocks under a faked future floor
    monkeypatch.setattr(pyobfuscator, "MIN_SUPPORTED_PYTHON", (9, 9))
    out2 = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1, require_min_python=True))
    rc2, so2, se2 = _run(out2)
    assert rc2 != 0 and "ok" not in so2


def test_pyc_warns_and_no_guard():
    import marshal
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        pyc = obf_module("VALUE = 7\n", ModuleObfOptions(output="pyc", seed=1, min_blocks=1,
                                                         require_min_python=True))
    assert any("require_min_python is TEXT-only" in str(x.message) for x in w), [str(x.message) for x in w]
    ns = {}
    exec(marshal.loads(bytes(pyc)[16:]), ns)             # still a valid .pyc, no guard injected
    assert ns["VALUE"] == 7


def test_off_is_noop_byte_identical():
    src = "print('x')\n"
    a = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1, require_min_python=False))
    b = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1))
    assert a == b and "_pyx_sys" not in a               # default off -> no guard, unchanged
