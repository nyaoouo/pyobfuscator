import sys, os, io, contextlib, marshal
sys.path.insert(0, os.path.dirname(__file__))
import ast
import pytest
from pyobfuscator import obf_func, ObfOptions, build_model, analyze_html
from pyobfuscator.cff.diagnostics import UnsupportedConstructError
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.names import Namer, collect_names

CM_SRC = (
    "class CM:\n"
    "    def __init__(self, name, suppress=False):\n"
    "        self.name = name\n"
    "        self.suppress = suppress\n"
    "    def __enter__(self):\n"
    "        print('enter', self.name)\n"
    "        return self\n"
    "    def __exit__(self, t, v, tb):\n"
    "        print('exit', self.name, t.__name__ if t else None)\n"
    "        return self.suppress\n"
)


def _observe(fn, args):
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
    exec(CM_SRC, ns)
    exec(compile(code, "<w>", "exec"), ns)
    return ns


# (label, func_src, name, list-of-argtuples)
CORPUS = [
    ("basic", "def f():\n    with CM('a'):\n        print('body')\n    return 'done'\n",
     "f", [()]),
    ("as-var", "def f():\n    with CM('a') as c:\n        print('using', c.name)\n    return 'd'\n",
     "f", [()]),
    ("exc-not-suppressed", "def f():\n    with CM('a'):\n        raise ValueError('boom')\n",
     "f", [()]),
    ("suppress-flag",
     "def f(s):\n    with CM('a', s):\n        raise ValueError('x')\n    return 'after'\n",
     "f", [(True,), (False,)]),
    ("return-in-body", "def f():\n    with CM('a'):\n        return 'early'\n", "f", [()]),
    ("multi-item",
     "def f():\n    with CM('a'), CM('b'):\n        print('body')\n    return 'd'\n", "f", [()]),
    ("multi-item-exc",
     "def f():\n    with CM('a'), CM('b'):\n        raise KeyError('k')\n", "f", [()]),
    ("nested",
     "def f():\n    with CM('a'):\n        with CM('b'):\n            print('body')\n    return 'd'\n",
     "f", [()]),
    ("with-in-loop",
     "def f(n):\n    for i in range(n):\n        with CM(str(i)):\n            print('iter', i)\n    return 'd'\n",
     "f", [(3,), (0,)]),
    ("nested-inner-suppress",
     "def f():\n    with CM('a'):\n        with CM('b', True):\n            raise ValueError('x')\n"
     "        print('after-inner')\n    return 'd'\n", "f", [()]),
    ("as-var-loop-sum",
     "def f(n):\n    with CM('a') as c:\n        total = 0\n        for k in range(n):\n"
     "            total += k\n    return total\n", "f", [(4,), (0,)]),
]


@pytest.mark.parametrize("label,src,name,batteries", CORPUS)
@pytest.mark.parametrize("seed", [0, 1, 11, 41])
def test_with_equivalent(label, src, name, batteries, seed):
    orig = _ns(src)[name]
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
    assert "with " not in out  # no `with` statement survives the desugar
    obf = _ns(out)[name]
    for args in batteries:
        o = _observe(orig, args)
        t = _observe(obf, args)
        assert o == t, f"{label} seed={seed} args={args}: {o} != {t}"


def test_with_pyc_path():
    src = ("def f(s):\n    with CM('a', s):\n        raise ValueError('x')\n    return 'after'\n")
    orig = _ns(src)["f"]
    blob = obf_func(src, ObfOptions(output="pyc", seed=5, min_blocks=1))
    code = marshal.loads(blob[16:])
    ns = {}
    exec(CM_SRC, ns)
    exec(code, ns)
    obf = ns["f"]
    for args in [(True,), (False,)]:
        assert _observe(orig, args) == _observe(obf, args)


@pytest.mark.parametrize("src", [
    # break inside a `with` body targeting the OUTER loop -> crosses finally -> reject
    "def f(n):\n    for i in range(n):\n        with CM('a'):\n            if i == 1:\n                break\n    return 'd'\n",
    # continue inside a `with` body targeting the OUTER loop -> reject
    "def f(n):\n    s = 0\n    for i in range(n):\n        with CM('a'):\n            if i % 2:\n"
    "                continue\n            s += i\n    return s\n",
])
def test_break_continue_across_with_rejected(src):
    with pytest.raises(UnsupportedConstructError):
        obf_func(src, ObfOptions(output="text", min_blocks=1))


def test_async_with_still_rejected():
    src = "async def f():\n    async with CM('a'):\n        pass\n"
    with pytest.raises(UnsupportedConstructError):
        obf_func(src)


def test_cfg_with_via_flatten_function():
    src = "def f():\n    with CM('a'):\n        return 1\n"
    tree = ast.parse(src)
    fn = tree.body[0]
    flatten_function(fn, Namer(0, collect_names(fn)))  # build_blocks desugars `with`
    out = ast.unparse(tree)
    assert "with " not in out and "while True" in out and "__exit__" in out


def test_with_scope_builds_and_html_assembles():
    src = "def f():\n    with CM('a') as c:\n        return c\n"
    sc = build_model(src, ObfOptions(min_blocks=1))["scopes"][0]
    assert sc["supported"] is True and sc["flattened"] is True
    assert "__exit__" in sc["flattened_source"]
    assert "window.__PYOBF__ =" in analyze_html(src, ObfOptions(min_blocks=1))
