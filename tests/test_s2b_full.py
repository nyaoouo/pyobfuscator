import sys, os, io, contextlib, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions
from pyobfuscator.cff.diagnostics import UnsupportedConstructError


def _obs(fn, args):
    buf = io.StringIO()
    rv = exc = None
    with contextlib.redirect_stdout(buf):
        try:
            rv = fn(*args)
        except BaseException as e:
            exc = (type(e).__name__, str(e))
    return (repr(rv), exc, buf.getvalue())


def _ns(code):
    ns = {}
    exec(compile(code, "<m>", "exec"), ns)
    return ns


def _check(src, name, batteries, seeds=(0, 1, 7)):
    orig = _ns(src)[name]
    for seed in seeds:
        out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, safe_mode=False))
        assert "finally" not in out  # no real finally survives in full-flatten
        obf = _ns(out)[name]
        for args in batteries:
            assert _obs(orig, args) == _obs(obf, args), f"seed={seed} args={args}"


def test_finally_runs_on_normal_and_exception():
    src = ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n"
           "    finally:\n        print('fin')\n")
    _check(src, "f", [(2,), (0,)])


def test_try_except_finally():
    src = ("def f(x):\n    try:\n        print('t')\n        return 10 // x\n"
           "    except ZeroDivisionError:\n        print('h')\n        return -1\n"
           "    finally:\n        print('f')\n")
    _check(src, "f", [(2,), (0,)])


def test_nested_finally_order():
    src = ("def f(x):\n    try:\n        try:\n            print('it')\n            return 10 // x\n"
           "        finally:\n            print('if')\n    finally:\n        print('of')\n")
    _check(src, "f", [(2,), (0,)])


def test_raise_in_finally_supersedes():
    src = ("def f():\n    try:\n        raise ValueError('orig')\n    finally:\n        raise KeyError('new')\n")
    _check(src, "f", [()])


def test_finally_raises_during_propagation():
    src = ("def f():\n    try:\n        try:\n            raise ValueError('E')\n"
           "        finally:\n            raise KeyError('E2')\n    finally:\n        print('Fo')\n")
    _check(src, "f", [()])


def test_break_continue_through_finally():
    src = ("def f(n):\n    out = []\n    for i in range(n):\n        try:\n            if i % 2 == 0:\n"
           "                continue\n            if i > 6:\n                break\n            out.append(i)\n"
           "        finally:\n            out.append(('fin', i))\n    return out\n")
    _check(src, "f", [(10,), (0,)])


def test_with_under_safe_mode_false():
    cm = ("class CM:\n    def __enter__(self):\n        print('enter')\n        return self\n"
          "    def __exit__(self, *a):\n        print('exit')\n        return False\n")
    src = "def f():\n    with CM():\n        return 'r'\n"
    orig = {}
    exec(compile(cm + src, "<o>", "exec"), orig)
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, safe_mode=False))
    assert "finally" not in out
    t = {}
    exec(compile(cm, "<c>", "exec"), t)
    exec(compile(out, "<t>", "exec"), t)
    assert _obs(orig["f"], ()) == _obs(t["f"], ())


def test_return_in_finally_rejected():
    src = "def f():\n    try:\n        return 1\n    finally:\n        return 2\n"
    with pytest.raises(UnsupportedConstructError):
        obf_func(src, ObfOptions(safe_mode=False))


def test_break_in_finally_rejected():
    src = ("def f(n):\n    for i in range(n):\n        try:\n            pass\n"
           "        finally:\n            break\n    return n\n")
    with pytest.raises(UnsupportedConstructError):
        obf_func(src, ObfOptions(safe_mode=False))


def test_safe_mode_true_unaffected():
    # hybrid still keeps a real finally
    src = "def f():\n    try:\n        return 1\n    finally:\n        return 2\n"
    out = obf_func(src, ObfOptions(output="text", min_blocks=1))  # safe_mode=True default
    ns = _ns(out)
    assert ns["f"]() == 2  # return-in-finally works under hybrid


# ---- differential fuzzer (deterministic, no RNG in script) ----------------
def _programs():
    bodies = [
        "x = x + 1",
        "if x > 3:\n            x = x * 2\n        else:\n            x = x - 1",
        "for _ in range(2):\n            x += 1",
        "raise ValueError('b')",
        "return x",
        "return x // (x - 3)",
    ]
    fins = [
        "log.append('f1')",
        "log.append('f2')\n        x = x + 100",
        "raise KeyError('kf')",
        "log.append('f3')\n        if x > 100:\n            raise RuntimeError('rf')",
    ]
    for bi, body in enumerate(bodies):
        for fi, fin in enumerate(fins):
            src = (f"def f(x):\n    log = []\n    try:\n        {body}\n"
                   f"    finally:\n        {fin}\n    return ('end', x, log)\n")
            yield (f"b{bi}f{fi}", src)


@pytest.mark.parametrize("label,src", list(_programs()))
@pytest.mark.parametrize("xval", [0, 3, 5, 200])
def test_fuzz_finally_matches_cpython(label, src, xval):
    orig = _ns(src)["f"]
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, safe_mode=False))
    assert "finally" not in out
    obf = _ns(out)["f"]
    assert _obs(orig, (xval,)) == _obs(obf, (xval,))
