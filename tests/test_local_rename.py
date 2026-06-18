"""Tests for LocalRenamePass: scope-aware rename of user-code params / locals / comprehension &
for-loop targets. Each test obfuscates-then-runs and compares behaviour to the original, and asserts
the targeted user identifiers no longer survive as bare Name/arg ids in the output.

The genuine (correct) path of a flattened body always terminates, so these run in-process (same as
the slotvar/namevault suites). RULE #0 (killable subprocess) is for WRONG-path/dump-replay bodies,
which these tests never exercise.
"""
import ast
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest

from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions, OutputFormat


# --- helpers ---------------------------------------------------------------

def _func_opts(**kw):
    base = dict(output=OutputFormat.TEXT, seed=1, min_blocks=1,
                obf_strings=False, shuffle_states=False, opaque_predicates=False,
                bogus_blocks=False)
    base.update(kw)
    return ObfOptions(**base)


def _mod_opts(**kw):
    base = dict(output=OutputFormat.TEXT, seed=1, min_blocks=1,
                obf_strings=False, shuffle_states=False, opaque_predicates=False,
                bogus_blocks=False)
    base.update(kw)
    return ModuleObfOptions(**base)


def _exec_func(out, name="f"):
    ns = {}
    exec(compile(out, "<t>", "exec"), ns)
    return ns[name]


def _exec_mod(out):
    ns = {"__name__": "m"}
    exec(compile(out, "<t>", "exec"), ns)
    return ns


def _names_in(out):
    """Set of every bare identifier (ast.Name id + ast.arg arg) in the obfuscated source."""
    tree = ast.parse(out)
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            ids.add(n.id)
        elif isinstance(n, ast.arg):
            ids.add(n.arg)
    return ids


def _arg_names_in(out):
    tree = ast.parse(out)
    return {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}


# --- 1. simple function: params + locals renamed --------------------------

def test_simple_params_and_locals_renamed():
    src = "def f(a, b):\n    c = a + b\n    return c\n"
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f(2, 3) == 5 and f(10, -4) == 6
    ids = _names_in(out)
    assert "a" not in ids and "b" not in ids and "c" not in ids


# --- 2. keyword call site -> param NOT renamed ----------------------------

def test_keyword_call_site_param_skipped():
    src = ("def f(key):\n    return key * 2\n"
           "def caller():\n    return f(key=5)\n")
    out = obf_module(src, _mod_opts())
    ns = _exec_mod(out)
    assert ns["f"](5) == 10
    assert ns["caller"]() == 10
    # the param `key` must survive because there is a keyword call site f(key=...)
    assert "key" in _arg_names_in(out)


# --- 3. positional call only -> param renamed -----------------------------

def test_positional_call_param_renamed():
    src = ("def f(key):\n    return key * 2\n"
           "def caller():\n    return f(5)\n")
    out = obf_module(src, _mod_opts())
    ns = _exec_mod(out)
    assert ns["f"](7) == 14 and ns["caller"]() == 10
    # no keyword call site -> param renamed away
    assert "key" not in _names_in(out)


# --- 4. global / nonlocal function -> whole function skipped ---------------
# NOTE: the flatten gate (FLATTEN_ALLOWED) does NOT support `global`/`nonlocal` statements, so the FULL
# obfuscate pipeline rejects such functions before any runnable output (a pre-existing limitation,
# independent of this pass). We therefore verify the skip decision at the PASS level — exactly what
# LocalRenamePass is responsible for — by running the pass directly and asserting (a) the declared
# names survive verbatim and (b) the transformed AST still executes identically.

def _localrename_only(src):
    from pyobfuscator.cff.passes.localrename import LocalRenamePass
    tree = ast.parse(src)
    LocalRenamePass().transform(tree, ObfOptions(seed=1))
    return ast.unparse(tree)


def test_global_function_skipped():
    src = ("g = 0\n"
           "def f(x):\n    global g\n    g = x + 1\n    local = g * 2\n    return local\n")
    out = _localrename_only(src)
    ns = _exec_mod(out)
    assert ns["f"](4) == 10 and ns["g"] == 5
    ids = _names_in(out)
    # whole function skipped: param x and local survive (global g declared -> never renamed)
    assert "x" in ids and "local" in ids and "g" in ids


def test_nonlocal_function_skipped():
    # `inner` uses nonlocal -> inner's scope is skipped; `acc` (bound in outer) is PINNED in outer so
    # the rename stays consistent with `nonlocal acc`. `inner`'s name + outer's other names may be
    # renamed, but `acc` survives and the program is correct.
    src = ("def outer():\n"
           "    acc = 0\n"
           "    def inner(v):\n"
           "        nonlocal acc\n"
           "        acc = acc + v\n"
           "        return acc\n"
           "    inner(3)\n"
           "    inner(4)\n"
           "    return acc\n")
    out = _localrename_only(src)
    ns = _exec_mod(out)
    assert ns["outer"]() == 7
    ids = _names_in(out)
    assert "acc" in ids  # nonlocal target pinned -> never renamed


# --- 5. locals() / exec function -> skipped -------------------------------

def test_locals_function_skipped():
    src = ("def f(a):\n"
           "    b = a + 1\n"
           "    d = locals()\n"
           "    return d['b'] + d['a']\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f(5) == 11  # b=6, a=5
    ids = _names_in(out)
    assert "a" in ids and "b" in ids  # whole function skipped


def test_exec_function_skipped():
    src = ("def f(code):\n"
           "    ns = {}\n"
           "    exec(code, ns)\n"
           "    return ns['z']\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f("z = 41") == 41
    ids = _names_in(out)
    assert "code" in ids and "ns" in ids


def test_eval_function_skipped():
    src = ("def f(expr, x):\n"
           "    val = eval(expr)\n"
           "    return val\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f("x * 3", 4) == 12
    ids = _names_in(out)
    assert "expr" in ids and "x" in ids and "val" in ids


# --- 6. **kwargs function -> skipped --------------------------------------

def test_kwargs_function_skipped():
    src = ("def f(a, **rest):\n"
           "    total = a\n"
           "    for v in rest.values():\n"
           "        total = total + v\n"
           "    return total\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f(1, b=2, c=3) == 6
    ids = _names_in(out)
    # whole function skipped (kwargs forwarding undetectable)
    assert "a" in ids and "rest" in ids and "total" in ids


# --- 7. closure: nested fn reads enclosing local -> consistent rename -----

def test_closure_free_var_consistent_rename():
    src = ("def f(x):\n"
           "    base = x * 10\n"
           "    def inner(y):\n"
           "        return base + y\n"
           "    return inner(5)\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f(2) == 25
    ids = _names_in(out)
    # base is a free var of inner; it must be renamed in BOTH the binding (f) and the use (inner)
    # consistently -> base must be gone and the program still correct (already asserted).
    assert "base" not in ids and "x" not in ids and "y" not in ids


def test_closure_deep_and_rebinding():
    # inner REBINDS `x` (its own local), so it must NOT share f's x rename; both still correct.
    src = ("def f(x):\n"
           "    def inner():\n"
           "        x = 99\n"
           "        return x\n"
           "    return x + inner()\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f(1) == 100
    assert "x" not in _names_in(out)


# --- 8. comprehension targets renamed within comp scope -------------------

def test_comprehension_targets_renamed():
    src = "def f():\n    return [x * i for i in range(3) for x in range(i)]\n"
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f() == [0, 0, 2]
    ids = _names_in(out)
    assert "x" not in ids and "i" not in ids


def test_genexp_and_dictcomp_targets_renamed():
    src = ("def f(items):\n"
           "    g = sum(v * 2 for v in items)\n"
           "    d = {k: k + 1 for k in items}\n"
           "    return g + d[items[0]]\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f([1, 2, 3]) == 12 + 2  # sum=12, d[1]=2
    ids = _names_in(out)
    assert "v" not in ids and "k" not in ids


def test_comprehension_with_enclosing_local():
    # outermost iterable `data` is evaluated in enclosing scope -> stays consistent with its binding
    src = ("def f():\n"
           "    data = [1, 2, 3]\n"
           "    factor = 3\n"
           "    return [v * factor for v in data]\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f() == [3, 6, 9]
    ids = _names_in(out)
    assert "v" not in ids and "data" not in ids and "factor" not in ids


def test_walrus_in_comprehension():
    # walrus target leaks to enclosing function scope (PEP 572); must rename consistently
    src = ("def f():\n"
           "    total = [y := i for i in range(4)]\n"
           "    return y + sum(total)\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f() == 3 + 6  # y=3, sum=6
    ids = _names_in(out)
    assert "y" not in ids and "i" not in ids and "total" not in ids


# --- 9. self / cls preserved in a method ----------------------------------

def test_self_cls_preserved_method_works():
    src = ("class C:\n"
           "    def __init__(self, n):\n"
           "        self.n = n\n"
           "    def calc(self, x):\n"
           "        tmp = x + 1\n"
           "        return self.n + tmp\n"
           "    @classmethod\n"
           "    def make(cls, n):\n"
           "        return cls(n)\n")
    out = obf_module(src, _mod_opts())
    ns = _exec_mod(out)
    obj = ns["C"](10)
    assert obj.calc(4) == 15
    assert ns["C"].make(7).calc(1) == 9
    ids = _names_in(out)
    assert "self" in ids and "cls" in ids
    # ordinary method param/local should still be renamed
    assert "tmp" not in ids


# --- 10. for-loop variable renamed ----------------------------------------

def test_for_loop_var_renamed():
    src = ("def f(s):\n"
           "    acc = 0\n"
           "    for ch in s:\n"
           "        acc = acc + ord(ch)\n"
           "    return acc\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f("ABC") == ord("A") + ord("B") + ord("C")
    ids = _names_in(out)
    assert "ch" not in ids and "acc" not in ids and "s" not in ids


def test_for_tuple_target_renamed():
    src = ("def f(pairs):\n"
           "    out = []\n"
           "    for k, v in pairs:\n"
           "        out.append(k + v)\n"
           "    return out\n")
    out = obf_func(src, _func_opts())
    f = _exec_func(out)
    assert f([(1, 2), (3, 4)]) == [3, 7]
    ids = _names_in(out)
    assert "k" not in ids and "v" not in ids


# --- extra: with / except targets, augassign ------------------------------

def test_with_and_except_targets_renamed():
    src = ("import io\n"
           "def f(data):\n"
           "    with io.StringIO(data) as buf:\n"
           "        content = buf.read()\n"
           "    try:\n"
           "        x = int(content)\n"
           "    except ValueError as err:\n"
           "        return str(err.__class__.__name__)\n"
           "    return x\n")
    out = obf_module(src, _mod_opts())
    ns = _exec_mod(out)
    assert ns["f"]("42") == 42
    assert ns["f"]("nope") == "ValueError"
    ids = _names_in(out)
    assert "buf" not in ids and "content" not in ids and "err" not in ids


# --- determinism: same seed -> byte-identical -----------------------------

def test_rename_deterministic_same_seed():
    src = ("def f(a, b):\n    c = a * b\n    return [c + i for i in range(b)]\n")
    o1 = obf_func(src, _func_opts(seed=7))
    o2 = obf_func(src, _func_opts(seed=7))
    assert o1 == o2


# --- full-strength equivalence across seeds (the real safety net) ---------

@pytest.mark.parametrize("seed", [0, 1, 7, 23])
def test_full_strength_equivalence(seed):
    src = ("def f(n, scale):\n"
           "    total = 0\n"
           "    for ch in str(n):\n"
           "        total = total + int(ch) * scale\n"
           "    squares = [d * d for d in range(scale)]\n"
           "    try:\n"
           "        return total // scale + sum(squares)\n"
           "    except ZeroDivisionError:\n"
           "        return total\n")
    ns_o = {}
    exec(compile(src, "<o>", "exec"), ns_o)
    out = obf_func(src, ObfOptions(output=OutputFormat.TEXT, seed=seed, min_blocks=1,
                                   obf_ints=True, slot_vars=True))
    ns_t = {}
    exec(compile(out, "<t>", "exec"), ns_t)
    for n in (0, 7, 123, 999):
        for scale in (1, 2, 5):
            assert ns_o["f"](n, scale) == ns_t["f"](n, scale)
