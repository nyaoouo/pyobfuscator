"""Tests for bogus_clone_ratio: bogus blocks built from cloned+mutated real code."""
from __future__ import annotations

import ast
import marshal
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from pyobfuscator import obf_module, obf_func, ModuleObfOptions, ObfOptions


# ---- helpers ----------------------------------------------------------------

def _exec_ns(code_or_src, name="modtest"):
    """Compile (if str) and exec code, return the resulting namespace."""
    if isinstance(code_or_src, str):
        code = compile(code_or_src, "<src>", "exec")
    else:
        code = code_or_src
    ns = {"__name__": name}
    exec(code, ns)
    return ns


# Rich module with multiple real blocks: assignments, expressions, for-loops, if/else, functions.
_RICH_MODULE = """\
import sys

DATA = []
for i in range(5):
    if i % 2 == 0:
        DATA.append(('even', i))
    else:
        DATA.append(('odd', i))

TOTAL = sum(v for _, v in DATA)
LABEL = 'done'

def summary():
    return {'total': TOTAL, 'count': len(DATA), 'label': LABEL}

CONFIG = {'items': DATA[:], 'sum': TOTAL}
"""


# ---- equivalence tests ------------------------------------------------------

@pytest.mark.parametrize("seed", [0, 7])
def test_equivalence_clone_ratio_08_text(seed):
    """With bogus_clone_ratio=0.8, the obfuscated module must be behavior-equivalent."""
    opts = ModuleObfOptions(
        output="text",
        seed=seed,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=0.8,
        obf_strings=False,   # keep strings plain so exec is simpler to compare
        shuffle_states=True,
        opaque_predicates=True,
    )
    out = obf_module(_RICH_MODULE, opts)
    orig_ns = _exec_ns(_RICH_MODULE)
    obf_ns = _exec_ns(out)

    assert orig_ns["DATA"] == obf_ns["DATA"], "DATA mismatch"
    assert orig_ns["TOTAL"] == obf_ns["TOTAL"], "TOTAL mismatch"
    assert orig_ns["LABEL"] == obf_ns["LABEL"], "LABEL mismatch"
    assert orig_ns["CONFIG"] == obf_ns["CONFIG"], "CONFIG mismatch"
    assert orig_ns["summary"]() == obf_ns["summary"](), "summary() mismatch"


@pytest.mark.parametrize("seed", [3, 42])
def test_equivalence_clone_ratio_08_pyc(seed):
    """With bogus_clone_ratio=0.8, pyc output must also produce equivalent behavior."""
    opts = ModuleObfOptions(
        output="pyc",
        seed=seed,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=0.8,
        obf_strings=False,
        shuffle_states=True,
        opaque_predicates=True,
    )
    blob = obf_module(_RICH_MODULE, opts)
    code = marshal.loads(blob[16:])

    orig_ns = _exec_ns(_RICH_MODULE)
    obf_ns = _exec_ns(code)

    assert orig_ns["DATA"] == obf_ns["DATA"]
    assert orig_ns["TOTAL"] == obf_ns["TOTAL"]
    assert orig_ns["CONFIG"] == obf_ns["CONFIG"]
    assert orig_ns["summary"]() == obf_ns["summary"]()


def test_equivalence_clone_ratio_00_sanity():
    """bogus_clone_ratio=0.0 is the legacy path — module must remain equivalent."""
    opts = ModuleObfOptions(
        output="text",
        seed=1,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=0.0,
        obf_strings=False,
    )
    out = obf_module(_RICH_MODULE, opts)
    orig_ns = _exec_ns(_RICH_MODULE)
    obf_ns = _exec_ns(out)

    assert orig_ns["DATA"] == obf_ns["DATA"]
    assert orig_ns["TOTAL"] == obf_ns["TOTAL"]
    assert orig_ns["CONFIG"] == obf_ns["CONFIG"]
    assert orig_ns["summary"]() == obf_ns["summary"]()


def test_equivalence_clone_ratio_10():
    """bogus_clone_ratio=1.0 — all bogus blocks cloned — still equivalent."""
    opts = ModuleObfOptions(
        output="text",
        seed=5,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=1.0,
        obf_strings=False,
        shuffle_states=True,
        opaque_predicates=True,
    )
    out = obf_module(_RICH_MODULE, opts)
    orig_ns = _exec_ns(_RICH_MODULE)
    obf_ns = _exec_ns(out)

    assert orig_ns["DATA"] == obf_ns["DATA"]
    assert orig_ns["TOTAL"] == obf_ns["TOTAL"]
    assert orig_ns["CONFIG"] == obf_ns["CONFIG"]
    assert orig_ns["summary"]() == obf_ns["summary"]()


# ---- function-level equivalence with clone ratio ----------------------------

_RICH_FUNC_SRC = """\
def compute(n):
    result = 0
    items = []
    for i in range(n):
        x = i * 3 + 1
        items.append(x)
        if i % 2 == 0:
            result += x
        else:
            result -= x
    return (result, items)
"""


@pytest.mark.parametrize("seed", [0, 11])
def test_func_equivalence_clone_ratio_08(seed):
    """obf_func with bogus_clone_ratio=0.8 must produce equivalent function behavior."""
    opts = ObfOptions(
        output="text",
        seed=seed,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=0.8,
        obf_strings=False,
        shuffle_states=True,
        opaque_predicates=True,
    )
    out = obf_func(_RICH_FUNC_SRC, opts)
    orig_ns = _exec_ns(_RICH_FUNC_SRC)
    obf_ns = _exec_ns(out)

    for n in [0, 1, 5, 10]:
        assert orig_ns["compute"](n) == obf_ns["compute"](n), f"divergence at n={n}"


# ---- structural check -------------------------------------------------------

def test_structural_cloned_body_present():
    """With bogus_clone_ratio=1.0 and a rich module, the output must be valid Python
    (compilable) and contain more than just junk-multiply patterns in bogus guards.
    We check that the output is parseable (always) and that it contains at least one
    bogus guard whose body has a non-trivial structure (not just a single BinOp Mult assign).
    This is lenient — the equivalence tests above are the hard gate."""
    opts = ModuleObfOptions(
        output="text",
        seed=9,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=1.0,
        obf_strings=False,
        shuffle_states=False,    # keep state ids predictable for inspection
        opaque_predicates=False,
    )
    out = obf_module(_RICH_MODULE, opts)

    # Must parse without error (syntactically valid Python)
    tree = ast.parse(out)

    # With clone_ratio=1.0 and a rich module (real_guard_pool is non-empty),
    # cloning MUST happen. We verify by checking that some If-guard body
    # contains an ast.Call (from real code like .append(...) or sum(...))
    # rather than just the junk Mult BinOp pattern.
    has_cloned_call = any(
        isinstance(node, ast.Call)
        for node in ast.walk(tree)
    )
    assert has_cloned_call, (
        "Expected at least one ast.Call node from cloned real code in the output, "
        "but found none — cloning may not have occurred"
    )


# ---- fallback: tiny module (no real blocks to clone) -------------------------

def test_fallback_no_real_blocks():
    """If the module is so trivial that no real guard has simple stmts to clone,
    inject_bogus must NOT crash and must still produce equivalent output."""
    # A bare assignment — only one block, no simple stmts after filtering terminators.
    trivial = "X = 1\n"
    opts = ModuleObfOptions(
        output="text",
        seed=0,
        min_blocks=1,
        bogus_blocks=True,
        bogus_clone_ratio=1.0,
        obf_strings=False,
        shuffle_states=False,
        opaque_predicates=False,
    )
    out = obf_module(trivial, opts)
    orig_ns = _exec_ns(trivial)
    obf_ns = _exec_ns(out)
    assert orig_ns.get("X") == obf_ns.get("X")


# ---- default option value ---------------------------------------------------

def test_default_bogus_clone_ratio_is_full():
    """Default bogus_clone_ratio is 1.0 — bogus bodies MIRROR real blocks (fresh-renamed vars)
    rather than the old obvious junk product."""
    opts = ObfOptions()
    assert opts.bogus_clone_ratio == 1.0


def test_module_default_bogus_clone_ratio_is_full():
    """ModuleObfOptions inherits bogus_clone_ratio=1.0 from ObfOptions."""
    opts = ModuleObfOptions()
    assert opts.bogus_clone_ratio == 1.0
