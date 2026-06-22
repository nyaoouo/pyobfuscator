import pytest

from pyobfuscator import obf_module, ModuleObfOptions, precompile, precompile_arg


def _obf(src, **opts):
    return obf_module(src, ModuleObfOptions(output="text", seed=1, **opts))


def _obf_exec(src, **opts):
    text = _obf(src, **opts)
    ns = {"__name__": "obftest"}
    exec(compile(text, "<obf>", "exec"), ns)
    return text, ns


# --- markers are identity/default at runtime (un-obfuscated source still runs) ---

def test_markers_identity_at_runtime():
    assert precompile(42) == 42
    assert precompile([1, 2]) == [1, 2]
    assert precompile_arg("K") is None
    assert precompile_arg("K", "d") == "d"


# --- precompile: build-time folding ---

def test_precompile_folds_pure_constant():
    text, ns = _obf_exec("from pyobfuscator import precompile\nR = precompile(2 ** 10 + 24)\n")
    assert ns["R"] == 1048
    assert "precompile" not in text


def test_precompile_runs_module_function():
    src = ("from pyobfuscator import precompile\n"
           "def _scr(t):\n"
           "    return tuple((ord(c) + i) % 256 for i, c in enumerate(t))\n"
           "R = precompile(_scr('AB'))\n")
    text, ns = _obf_exec(src, obf_strings=False)
    assert ns["R"] == (65, 67)        # 'A'+0, 'B'+1
    assert "AB" not in text           # the input literal was folded away
    assert "precompile" not in text


def test_precompile_result_types():
    src = ("from pyobfuscator import precompile\n"
           "A = precompile([1, 2, 3])\n"
           "B = precompile({'x': 1, 'y': 2})\n"
           "C = precompile(b'\\x00\\x01\\xff')\n"
           "D = precompile({1, 2, 3})\n")
    _text, ns = _obf_exec(src, obf_strings=False)
    assert ns["A"] == [1, 2, 3]
    assert ns["B"] == {"x": 1, "y": 2}
    assert ns["C"] == b"\x00\x01\xff"
    assert ns["D"] == {1, 2, 3}


# --- precompile_arg: build-script-injected values ---

def test_precompile_arg_injected_value():
    src = "from pyobfuscator import precompile_arg\nR = precompile_arg('VERSION', 'dev')\n"
    text, ns = _obf_exec(src, obf_strings=False, precompile_args={"VERSION": "1.2.3"})
    assert ns["R"] == "1.2.3"
    assert "'1.2.3'" in text          # folded as a literal
    assert "dev" not in text          # the default was not used
    assert "precompile_arg" not in text


def test_precompile_arg_default_when_missing():
    src = "from pyobfuscator import precompile_arg\nR = precompile_arg('VERSION', 'dev')\n"
    _text, ns = _obf_exec(src, obf_strings=False)   # no precompile_args
    assert ns["R"] == "dev"


def test_precompile_arg_required_missing_fails():
    src = "from pyobfuscator import precompile_arg\nR = precompile_arg('SECRET')\n"
    with pytest.raises(ValueError):
        _obf(src)                      # 1-arg = required, none provided


def test_precompile_arg_nested_in_precompile():
    src = ("from pyobfuscator import precompile, precompile_arg\n"
           "def _scr(t):\n"
           "    return tuple((ord(c) + i) % 256 for i, c in enumerate(t))\n"
           "R = precompile(_scr(precompile_arg('KEY', 'AB')))\n")
    _text, ns = _obf_exec(src, obf_strings=False, precompile_args={"KEY": "AB"})
    assert ns["R"] == (65, 67)


# --- composition with the literal-obfuscation passes ---

def test_precompile_composes_and_hides_input():
    src = ("from pyobfuscator import precompile\n"
           "def _scr(t):\n"
           "    return tuple((ord(c) + i * 3) % 256 for i, c in enumerate(t))\n"
           "def check(k):\n"
           "    return _scr(k) == precompile(_scr('PYOBF-PRO-2026'))\n")
    text, ns = _obf_exec(src, obf_ints=True, const_archive=True)
    assert ns["check"]("PYOBF-PRO-2026") is True
    assert ns["check"]("wrong") is False
    assert "PYOBF-PRO-2026" not in text   # folded, then encrypted by const_archive


# --- fail-loud ---

def test_precompile_param_reference_fails():
    src = ("from pyobfuscator import precompile\n"
           "def f(x):\n"
           "    return precompile(x + 1)\n")   # x is a parameter — not available at build
    with pytest.raises(ValueError):
        _obf(src)


def test_precompile_bad_arity_fails():
    with pytest.raises(ValueError):
        _obf("from pyobfuscator import precompile\nR = precompile(1, 2)\n")


def test_precompile_non_literal_result_fails():
    with pytest.raises(ValueError):
        _obf("from pyobfuscator import precompile\nR = precompile(lambda: 1)\n")


def test_precompile_arg_non_literal_key_fails():
    src = ("from pyobfuscator import precompile_arg\n"
           "K = 'V'\n"
           "R = precompile_arg(K)\n")          # key must be a string literal
    with pytest.raises(ValueError):
        _obf(src)


# --- determinism ---

def test_precompile_deterministic():
    src = ("from pyobfuscator import precompile\n"
           "def _scr(t):\n"
           "    return tuple((ord(c) + i) % 256 for i, c in enumerate(t))\n"
           "R = precompile(_scr('hello'))\n")
    a = obf_module(src, ModuleObfOptions(output="text", seed=5))
    b = obf_module(src, ModuleObfOptions(output="text", seed=5))
    assert a == b


# --- configurable timeout ---

def test_precompile_timeout_fails_loud():
    src = ("from pyobfuscator import precompile\n"
           "R = precompile(__import__('time').sleep(5) or 1)\n")
    with pytest.raises(ValueError):
        _obf(src, precompile_timeout=1.0)


# --- caching: an identical re-build reuses the result instead of re-spawning ---

def test_precompile_caches_subprocess():
    from pyobfuscator.cff.passes import precompile as pc
    src = ("from pyobfuscator import precompile\n"
           "def _f(n):\n    return n * n\n"
           "R = precompile(_f(7))\n")
    pc._CACHE.clear()
    before = pc._subprocess_spawns
    t1, ns1 = _obf_exec(src)
    spawns1 = pc._subprocess_spawns
    t2, ns2 = _obf_exec(src)              # identical inputs -> cache hit, no new subprocess
    spawns2 = pc._subprocess_spawns
    assert ns1["R"] == 49 and ns2["R"] == 49
    assert spawns1 == before + 1          # first build spawned exactly once
    assert spawns2 == spawns1             # second build reused the cache
    assert t1 == t2                       # identical output (cache does not alter the result)


# --- a module that doesn't use the markers is unaffected (no-op fast path) ---

def test_no_markers_is_noop():
    src = "def f(x):\n    return x + 1\n"
    _text, ns = _obf_exec(src)
    assert ns["f"](41) == 42
