import ast
import marshal

from equivalence import observe, Observation, assert_func_equivalent
from pyobfuscator import obf_func, ObfOptions


def _loader_from_text(text, name):
    def factory():
        ns = {}
        exec(compile(text, "<eq>", "exec"), ns)
        return ns[name]
    return factory


def test_observe_captures_return():
    obs = observe(lambda: (lambda a, b: a + b), (2, 3), {})
    assert obs == Observation(result=5, exc_type=None, exc_msg=None, stdout="")


def test_observe_captures_exception():
    def boom_factory():
        def boom():
            raise ValueError("nope")
        return boom
    obs = observe(boom_factory, (), {})
    assert obs.exc_type == "ValueError"
    assert obs.exc_msg == "nope"
    assert obs.result is None


def test_observe_captures_stdout():
    def p_factory():
        def p(x):
            print("v", x)
            return x
        return p
    obs = observe(p_factory, (7,), {})
    assert obs.stdout == "v 7\n"
    assert obs.result == 7


def test_roundtripped_function_is_equivalent_text():
    src = "def f(a, b):\n    print(a)\n    if b:\n        return a - b\n    return a + b\n"
    text = obf_func(src, ObfOptions(output="text"))
    assert_func_equivalent(
        original_src=src,
        transformed_factory=_loader_from_text(text, "f"),
        func_name="f",
        batteries=[((1, 0), {}), ((5, 2), {}), ((0, 9), {})],
    )


def test_roundtripped_function_is_equivalent_pyc():
    src = "def g(n):\n    return n * n\n"
    pyc = obf_func(src, ObfOptions(output="pyc"))

    def factory():
        code = marshal.loads(pyc[16:])
        ns = {}
        exec(code, ns)
        return ns["g"]

    assert_func_equivalent(
        original_src=src,
        transformed_factory=factory,
        func_name="g",
        batteries=[((3,), {}), ((-4,), {}), ((0,), {})],
    )
