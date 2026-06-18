"""#2 follow-up — generated runtime helpers (const-archive _ks/_kdf/_get, stack-call push/invoke,
lifted-lambda defs) get their params/locals renamed AT INJECTION (mint from the global counter,
unified by finalize), so no plaintext helper identifier survives. Verified the const-archive helper's
multi-char params (off/sz/c/cast/data/key) and the stack helpers' v/n are gone.
"""
import ast

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, OutputFormat

SRC = "import json\ndef f(x):\n    return len(json.dumps([x, abs(x), str(x)]))\nr = f(-3)\n"


def _plaintext_params(out: str):
    """FunctionDef params that are neither a fresh _pyobf name nor self/cls — i.e. plaintext leaks."""
    tree = ast.parse(out)
    bad = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs + (
                    [a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else []):
                if not arg.arg.startswith("_pyobf") and arg.arg not in ("self", "cls"):
                    bad.append((n.name, arg.arg))
    return bad


def _run(out):
    ns = {}
    exec(compile(ast.parse(out), "<t>", "exec"), ns)
    return ns


def _ref():
    ns = {}
    exec(compile(ast.parse(SRC), "<t>", "exec"), ns)
    return ns


def _opts(**kw):
    return ModuleObfOptions(output=OutputFormat.TEXT, seed=3, min_blocks=1, **kw)


def test_const_archive_helper_params_renamed():
    out = obf_module(SRC, _opts(const_archive=True))
    assert not _plaintext_params(out), f"plaintext helper params: {_plaintext_params(out)}"
    assert _run(out)["r"] == _ref()["r"]


def test_stackcall_helper_params_renamed():
    out = obf_module(SRC, _opts(stack_calls=True, hide_external_args=True))
    assert not _plaintext_params(out), f"plaintext helper params: {_plaintext_params(out)}"
    assert _run(out)["r"] == _ref()["r"]


def test_full_combo_no_plaintext_helper_params():
    out = obf_module(SRC, _opts(name_vault=True, const_archive=True, stack_calls=True,
                                hide_external_args=True))
    assert not _plaintext_params(out), f"plaintext helper params: {_plaintext_params(out)}"
    assert _run(out)["r"] == _ref()["r"]


def test_deterministic():
    a = obf_module(SRC, _opts(const_archive=True, stack_calls=True, hide_external_args=True))
    b = obf_module(SRC, _opts(const_archive=True, stack_calls=True, hide_external_args=True))
    assert a == b
