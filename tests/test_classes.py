import sys, os, io, contextlib, marshal
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, ObfOptions, build_model, analyze_html


def _run(thunk):
    buf = io.StringIO()
    rv = exc = None
    with contextlib.redirect_stdout(buf):
        try:
            rv = thunk()
        except BaseException as e:
            exc = (type(e).__name__, str(e))
    return (repr(rv), exc, buf.getvalue())


def _check(src, probe, seed=0):
    ns_o = {}
    exec(compile(src, "<o>", "exec"), ns_o)
    out = obf_func(src, ObfOptions(output="text", seed=seed, min_blocks=1))
    assert "while True" in out  # at least one method was flattened
    ns_t = {}
    exec(compile(out, "<t>", "exec"), ns_t)
    assert _run(lambda: probe(ns_o)) == _run(lambda: probe(ns_t))


CLS_BASIC = (
    "class Calc:\n"
    "    def classify(self, n):\n"
    "        if n < 0:\n            return 'neg'\n"
    "        elif n == 0:\n            return 'zero'\n"
    "        else:\n            return 'pos'\n"
)

def test_basic_method_flattened():
    _check(CLS_BASIC, lambda ns: [ns['Calc']().classify(v) for v in (-2, 0, 5)])


def test_inheritance_and_super():
    src = (
        "class Base:\n"
        "    def greet(self):\n        return 'base'\n"
        "class Derived(Base):\n"
        "    def greet(self):\n"
        "        prefix = ''\n"
        "        for i in range(2):\n            prefix += '*'\n"
        "        return prefix + super().greet()\n"
    )
    _check(src, lambda ns: ns['Derived']().greet())


def test_staticmethod_classmethod_property():
    src = (
        "class C:\n"
        "    @staticmethod\n"
        "    def s(x):\n        if x:\n            return 'y'\n        return 'n'\n"
        "    @classmethod\n"
        "    def c(cls, x):\n        out = []\n        for i in range(x):\n            out.append(i)\n        return (cls.__name__, out)\n"
        "    @property\n"
        "    def p(self):\n        v = 0\n        for i in range(4):\n            v += i\n        return v\n"
    )
    _check(src, lambda ns: (ns['C'].s(1), ns['C'].s(0), ns['C'].c(3), ns['C']().p))


def test_class_in_function_closure():
    src = (
        "def make(base):\n"
        "    class Counter:\n"
        "        def value(self):\n"
        "            total = base\n"
        "            for i in range(3):\n                total += i\n            return total\n"
        "    return Counter\n"
    )
    _check(src, lambda ns: ns['make'](10)().value())


def test_nested_class():
    src = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def m(self, n):\n            if n > 0:\n                return n * 2\n            return 0\n"
        "    def use(self, n):\n        return Outer.Inner().m(n)\n"
    )
    _check(src, lambda ns: (ns['Outer']().use(5), ns['Outer']().use(-1)))


def test_method_with_comprehension():
    src = (
        "class Repo:\n"
        "    def __init__(self, items):\n        self.items = items\n"
        "    def evens(self):\n        if not self.items:\n            return []\n        return [x for x in self.items if x % 2 == 0]\n"
    )
    _check(src, lambda ns: ns['Repo']([1, 2, 3, 4, 5, 6]).evens())


def test_method_exception_equiv():
    src = (
        "class C:\n"
        "    def div(self, a, b):\n"
        "        try:\n            return a // b\n"
        "        except ZeroDivisionError:\n            return 'inf'\n"
    )
    _check(src, lambda ns: (ns['C']().div(6, 2), ns['C']().div(6, 0)))


def test_method_with_in_body():
    src = (
        "class Res:\n"
        "    def use(self, cm):\n"
        "        with cm:\n            return 'used'\n"
    )
    class _CM:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    _check(src, lambda ns: ns['Res']().use(_CM()))


@pytest.mark.parametrize("seed", [0, 1, 13, 41])
def test_class_corpus_across_seeds(seed):
    _check(CLS_BASIC, lambda ns: [ns['Calc']().classify(v) for v in (-2, 0, 5)], seed=seed)


def test_class_pyc_path():
    blob = obf_func(CLS_BASIC, ObfOptions(output="pyc", seed=4, min_blocks=1))
    code = marshal.loads(blob[16:])
    ns = {}
    exec(code, ns)
    assert ns['Calc']().classify(-1) == 'neg' and ns['Calc']().classify(7) == 'pos'


def test_class_scope_analyzed_and_html_assembles():
    scopes = build_model(CLS_BASIC, ObfOptions(min_blocks=1))["scopes"]
    assert "classify" in {s["name"] for s in scopes}
    assert "window.__PYOBF__ =" in analyze_html(CLS_BASIC, ObfOptions(min_blocks=1))
