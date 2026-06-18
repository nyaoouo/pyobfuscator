import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


def test_try_except_flattens_and_runs():
    src = ("def f(a, b):\n"
           "    try:\n"
           "        return a // b\n"
           "    except ZeroDivisionError:\n"
           "        return -1\n")
    out = obf_func(src, ObfOptions(output="text"))
    assert "while True" in out and "try:" in out  # the wrapper try exists, but not the user's
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    assert ns["f"](6, 2) == 3 and ns["f"](6, 0) == -1


@pytest.mark.parametrize("bad,needle,opts", [
    # try/finally and with are supported under safe_mode=False (full-flatten).
    # Only finally-overrides (return/break/continue inside finally) are rejected.
    ("def f():\n    try:\n        return 1\n    finally:\n        return 2\n", "return",
     ObfOptions(safe_mode=False)),
])
def test_finally_override_rejected(bad, needle, opts):
    with pytest.raises(UnsupportedConstructError) as ei:
        obf_func(bad, opts)
    assert any(needle.lower() in (d.node_type + " " + d.message).lower()
               for d in ei.value.diagnostics)
