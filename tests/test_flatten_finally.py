import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


def _run(out, name, *args):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rv = ns[name](*args)
    return rv, buf.getvalue()


def test_finally_safe_mode_flattens_and_runs():
    src = ("def f(x):\n    try:\n        return 10 // x\n    finally:\n        print('fin')\n")
    out = obf_func(src, ObfOptions(output="text", min_blocks=1))
    assert "while True" in out and "finally:" in out  # flattened bodies + real finally
    rv, so = _run(out, "f", 2)
    assert rv == 5 and so == "fin\n"
    # x=0 -> ZeroDivisionError, but finally still printed
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        with pytest.raises(ZeroDivisionError):
            ns["f"](0)
    assert buf.getvalue() == "fin\n"


def test_finally_safe_mode_off_supported():
    # try/finally is supported under safe_mode=False (full-flatten).
    src = ("def f():\n    try:\n        pass\n    finally:\n        pass\n")
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, safe_mode=False))
    assert "finally" not in out  # no real finally survives in full-flatten
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    ns["f"]()  # must not raise


def test_break_across_finally_rejected_via_pipeline():
    src = ("def f(n):\n    for i in range(n):\n        try:\n            if i == 2:\n"
           "                break\n            print(i)\n        finally:\n            print('f')\n")
    with pytest.raises(UnsupportedConstructError):
        obf_func(src, ObfOptions(output="text", min_blocks=1))


def test_with_supported_under_safe_mode_false():
    # `with` is supported under safe_mode=False (desugared to
    # try/except/finally then full-flattened; no real finally survives).
    cm = "class _CM:\n    def __enter__(self): return self\n    def __exit__(self, *a): return False\n"
    src = "def f():\n    with _CM():\n        return 42\n"
    ns = {}
    exec(compile(cm, "<cm>", "exec"), ns)
    out = obf_func(src, ObfOptions(output="text", min_blocks=1, safe_mode=False))
    assert "finally" not in out
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["f"]() == 42
