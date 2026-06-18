# tests/test_protect_s1_equivalence.py
import sys, os, io, ast, marshal, contextlib, builtins
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

OPTS = dict(min_blocks=1, seed=7, pack_body=True)


def _load_text(src, name):
    ns = {"__name__": name}
    exec(compile(src, "<t>", "exec"), ns)
    return ns


def _load_pyc(blob, name):
    ns = {"__name__": name}
    exec(marshal.loads(blob[16:]), ns)  # 16-byte hash-based pyc header
    return ns


MOD = (
    "import sys\n"
    "RESULTS = []\n"
    "for i in range(4):\n"
    "    RESULTS.append((i, i * i))\n"
    "def summary():\n    return sum(b for _, b in RESULTS)\n"
    "CONFIG = {'n': len(RESULTS)}\n"
)


@pytest.mark.parametrize("seed", [0, 7, 23])
def test_module_namespace_text(seed):
    out = obf_module(MOD, ModuleObfOptions(output="text", min_blocks=1, seed=seed, pack_body=True))
    orig = _load_text(MOD, "m")
    obf = _load_text(out, "m")
    assert orig["RESULTS"] == obf["RESULTS"]
    assert orig["summary"]() == obf["summary"]()
    assert orig["CONFIG"] == obf["CONFIG"]


def test_module_namespace_pyc():
    blob = obf_module(MOD, ModuleObfOptions(output="pyc", min_blocks=1, seed=7, pack_body=True))
    orig = _load_text(MOD, "m")
    obf = _load_pyc(blob, "m")
    assert orig["RESULTS"] == obf["RESULTS"] and orig["CONFIG"] == obf["CONFIG"]


@pytest.mark.parametrize("modname,ran", [("__main__", True), ("imported", False)])
def test_main_guard(modname, ran):
    src = (
        "LOG = []\n"
        "def main():\n    LOG.append('ran'); return 'done'\n"
        "if __name__ == '__main__':\n    main()\n"
    )
    out = obf_module(src, ModuleObfOptions(output="text", min_blocks=1, seed=3, pack_body=True))
    orig = _load_text(src, modname)
    obf = _load_text(out, modname)
    assert orig["LOG"] == obf["LOG"]
    assert obf["LOG"] == (["ran"] if ran else [])


# ---- ctf-style entry (argv + interactive), text AND pyc ----
ENTRY = (
    "import sys\n"
    "def check(k):\n    return k == 'open-sesame'\n"
    "def main():\n"
    "    if len(sys.argv) > 1:\n"
    "        if check(sys.argv[1]):\n            print('Y'); sys.exit(0)\n"
    "        else:\n            print('N'); sys.exit(1)\n"
    "    else:\n"
    "        print('Y' if check(input()) else 'N')\n"
    "if __name__ == '__main__':\n    main()\n"
)


def _run_argv(ns, key):
    buf = io.StringIO(); old = sys.argv; sys.argv = ["e"] + ([key] if key is not None else [])
    code = None
    try:
        with contextlib.redirect_stdout(buf):
            try:
                ns["main"]()
            except SystemExit as e:
                code = e.code if e.code is not None else 0
    finally:
        sys.argv = old
    return buf.getvalue(), code


def _run_interactive(ns, typed):
    buf = io.StringIO(); oi = builtins.input; builtins.input = lambda *a, **k: typed
    old = sys.argv; sys.argv = ["e"]
    try:
        with contextlib.redirect_stdout(buf):
            try:
                ns["main"]()
            except SystemExit:
                pass
    finally:
        builtins.input = oi; sys.argv = old
    return buf.getvalue()


def test_entry_argv_and_interactive_text_and_pyc():
    text = obf_module(ENTRY, ModuleObfOptions(output="text", min_blocks=1, seed=5, pack_body=True))
    pyc = obf_module(ENTRY, ModuleObfOptions(output="pyc", min_blocks=1, seed=5, pack_body=True))
    for key in ("open-sesame", "wrong"):
        r = _run_argv(_load_text(ENTRY, "ref"), key)
        t = _run_argv(_load_text(text, "txt"), key)
        p = _run_argv(_load_pyc(pyc, "pyc"), key)
        assert r == t == p, (key, r, t, p)
    for typed in ("open-sesame", "nope"):
        r = _run_interactive(_load_text(ENTRY, "ref"), typed)
        t = _run_interactive(_load_text(text, "txt"), typed)
        p = _run_interactive(_load_pyc(pyc, "pyc"), typed)
        assert r == t == p, (typed, r, t, p)
