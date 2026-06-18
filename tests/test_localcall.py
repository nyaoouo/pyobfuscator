import sys, os, io, contextlib, ast
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions, local_call


def _run(code, name, *args):
    ns = {}
    exec(compile(code, "<m>", "exec"), ns)
    return ns[name](*args)


def test_local_call_is_identity_at_runtime():
    @local_call
    def f(x):
        return x + 1
    assert f(2) == 3  # original source runs normally


RENAME_SRC = (
    "from pyobfuscator import local_call\n"
    "@local_call\n"
    "def check(s):\n"
    "    def inner(n):\n"
    "        return n * 2\n"
    "    return inner(len(s)) + 1\n"
    "def main(s):\n"
    "    return check(s)\n"
)

def test_marked_name_obfuscated_and_decorator_stripped():
    out = obf_module(RENAME_SRC, ModuleObfOptions(output="text", seed=1, min_blocks=1,
                                                  shuffle_states=False, opaque_predicates=False,
                                                  bogus_blocks=False, obf_strings=False))
    assert "local_call" not in out                 # decorator + import gone
    assert "def check" not in out and "check(" not in out  # name obfuscated everywhere
    # behavior preserved
    orig = {}; exec(compile(RENAME_SRC, "<o>", "exec"), orig)
    obf = {}; exec(compile(out, "<t>", "exec"), obf)
    assert obf["main"]("hello") == orig["main"]("hello")


INLINE_SRC = (
    "from pyobfuscator import local_call\n"
    "@local_call\n"
    "def greet(name):\n"
    "    msg = 'hi ' + name\n"
    "    print(msg)\n"
    "def main(name):\n"
    "    greet(name)\n"
    "    return 1\n"
)

def test_single_call_no_return_func_inlined():
    out = obf_module(INLINE_SRC, ModuleObfOptions(output="text", seed=2, min_blocks=1,
                                                  shuffle_states=False, opaque_predicates=False,
                                                  bogus_blocks=False, obf_strings=False))
    assert "greet" not in out  # the function is gone (inlined), name obfuscated/removed
    orig_buf, obf_buf = io.StringIO(), io.StringIO()
    orig = {}; exec(compile(INLINE_SRC, "<o>", "exec"), orig)
    obf = {}; exec(compile(out, "<t>", "exec"), obf)
    with contextlib.redirect_stdout(orig_buf): r0 = orig["main"]("bob")
    with contextlib.redirect_stdout(obf_buf): r1 = obf["main"]("bob")
    assert r0 == r1 and orig_buf.getvalue() == obf_buf.getvalue()


def test_not_renamed_when_name_shadowed():
    # `helper` is also a param name elsewhere -> NOT uniquely the function -> rename skipped,
    # but decorator still stripped and behavior preserved.
    src = ("from pyobfuscator import local_call\n"
           "@local_call\n"
           "def helper(x):\n    return x + 1\n"
           "def other(helper):\n    return helper\n"
           "def main():\n    return helper(1) + other(5)\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=3, min_blocks=1,
                                           shuffle_states=False, opaque_predicates=False,
                                           bogus_blocks=False, obf_strings=False))
    assert "local_call" not in out  # decorator stripped regardless
    orig = {}; exec(compile(src, "<o>", "exec"), orig)
    obf = {}; exec(compile(out, "<t>", "exec"), obf)
    assert obf["main"]() == orig["main"]()


@pytest.mark.parametrize("seed", [0, 1, 7])
def test_full_strength_equivalence(seed):
    out = obf_module(RENAME_SRC, ModuleObfOptions(output="text", seed=seed, min_blocks=1))
    orig = {}; exec(compile(RENAME_SRC, "<o>", "exec"), orig)
    obf = {}; exec(compile(out, "<t>", "exec"), obf)
    assert obf["main"]("abcdef") == orig["main"]("abcdef")
