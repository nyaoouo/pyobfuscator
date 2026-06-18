import sys, os, io, contextlib, itertools
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


def _obs(fn, a):
    b = io.StringIO(); r = e = None
    with contextlib.redirect_stdout(b):
        try: r = fn(*a)
        except BaseException as x: e = (type(x).__name__, str(x))
    return (repr(r), e, b.getvalue())


def _ns(code, name):
    d = {}; exec(compile(code, "<m>", "exec"), d); return d[name]


EXT_SRCS = [
    ("def f(s):\n    return len(s) + len(s) * 2\n", "f", [("abc",), ("",)]),
    ("def f(a, b):\n    print(a, b)\n    return max(a, b) - min(a, b)\n", "f", [(3, 7), (9, 2)]),
    ("def f(xs):\n    return sorted(xs, reverse=True)\n", "f", [([3, 1, 2],)]),  # has keyword -> stays normal
    ("def f(s):\n    return s.upper().count('A') + len(s)\n", "f", [("banana",)]),
    ("def f(n):\n    return [str(i) for i in range(n)]\n", "f", [(4,), (0,)]),
    ("def f(x):\n    return abs(x) + pow(x, 2) + int(str(x))\n", "f", [(-5,), (3,)]),
]


@pytest.mark.parametrize("src,name,args", EXT_SRCS)
@pytest.mark.parametrize("opts", [
    dict(hide_external_args=True),
    dict(hide_external_args=True, stack_calls=True),
    dict(hide_external_args=True, stack_calls=True, obf_strings=True, obf_ints=True,
         dispatch_tree=True, state_delta=True, dedup=True),
])
@pytest.mark.parametrize("seed", [0, 1, 5])
def test_external_equivalent(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_threading_local_storage_used():
    out = obf_func("def f(s):\n    return len(s)\n",
                   ObfOptions(output="text", seed=0, min_blocks=1, hide_external_args=True))
    assert "threading" in out  # thread-safe storage


def test_off_by_default_no_external_routing():
    out = obf_func("def f(s):\n    return len(s)\n",
                   ObfOptions(output="text", seed=0, min_blocks=1))
    assert "threading" not in out


def test_internal_stack_calls_thread_safe():
    src = ("def pub(x):\n    def _h(a, b):\n        return a * b + 1\n"
           "    return _h(x, x) + _h(x, 2)\n")
    orig = _ns(src, "pub")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, stack_calls=True))
    assert "threading" in out
    obf = _ns(out, "pub")
    assert _obs(orig, (4,)) == _obs(obf, (4,))


def test_multithread_no_arg_corruption():
    # the hidden stack must be per-thread: concurrent calls must not corrupt each other's args
    import threading
    src = ("def work(a, b, c):\n    return (a, b, c)\n"
           "def f(x):\n    return work(x, x + 1, x + 2)\n")
    out = obf_func(src, ObfOptions(output="text", seed=0, min_blocks=1, hide_external_args=True))
    f = _ns(out, "f")
    results = {}
    def run(i): results[i] = f(i * 1000)
    ts = [threading.Thread(target=run, args=(i,)) for i in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert all(results[i] == (i * 1000, i * 1000 + 1, i * 1000 + 2) for i in range(8))
