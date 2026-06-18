"""Second, targeted StackCall pass that arg-hides the constant-archive accessor CALL
SITES (`_get(off,sz,c,cast)`) through the push/invoke stack, WITHOUT touching helper internals.

Design that these tests pin down (see stackcall.StackCallPass(phase="post_vault") +
archive._pyobf_stackroute marker):
  * The second pass runs AFTER NameVault/Archive/DataObf, BEFORE Flatten, gated on the SAME
    `hide_external_args` flag as the first StackCall.
  * It routes ONLY archive `_get(...)` calls that ArchivePass MARKED, and ONLY when they are the
    direct value of a top-level Expr / Assign-to-Name / Return statement. So:
      - helper FUNCTION BODIES (the first pass's push/pop/invoke helpers, the archive `_ks`/`_kdf`/
        `_get` helpers, the dataobf `_dec` helper, the vault boot registrations) are NEVER touched —
        their `pow`/`range`/`getattr`/`int.from_bytes`/`.join` calls and the `_get(...)` calls nested
        inside them as arguments stay byte-identical;
      - vault `_D[k](...)` calls are deliberately NOT routed (NameVault rewrites the first pass's
        `s = getattr(tls, "s", None)` push-helper statement into `s = _D[k](...)`, a routable
        statement value INSIDE the helper — routing it would corrupt the helper; and no additional
        user `_D[k]` call site survives at a routable position because the first pass, under the same
        flag, already absorbed every routable user builtin call).
  * `hide_external_args=False` => the second pass is inert (no change).
"""
import ast
import contextlib
import io
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import pytest

from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions
from pyobfuscator.options import ObfOptions as _O
from pyobfuscator.cff.passes.localcall import LocalCallPass
from pyobfuscator.cff.passes.dictindirect import DictIndirectPass
from pyobfuscator.cff.passes.normalize import NormalizePass
from pyobfuscator.cff.passes.stackcall import StackCallPass
from pyobfuscator.cff.passes.slotvar import SlotVarPass
from pyobfuscator.cff.passes.namevault import NameVaultPass
from pyobfuscator.cff.passes.archive import ArchivePass
from pyobfuscator.cff.passes.dataobf import DataObfPass


# --------------------------------------------------------------------------- helpers
def _obs(fn, a):
    b = io.StringIO(); r = e = None
    with contextlib.redirect_stdout(b):
        try:
            r = fn(*a)
        except BaseException as x:
            e = (type(x).__name__, str(x))
    return (repr(r), e, b.getvalue())


def _ns(code, name):
    d = {}
    exec(compile(code, "<m>", "exec"), d)
    return d[name]


# The pipeline up to (but not including) Flatten, so we can inspect the routed AST and run the
# second pass in isolation. Mirrors _FUNC_PIPELINE / _MODULE_PIPELINE minus FlattenPass.
def _pre_flatten(src, opts, include_second=True):
    tree = ast.parse(src)
    passes = [LocalCallPass(), DictIndirectPass(), NormalizePass(), StackCallPass(),
              SlotVarPass(), NameVaultPass(), ArchivePass(), DataObfPass()]
    if include_second:
        passes.append(StackCallPass(phase="post_vault"))
    for p in passes:
        tree = p.transform(tree, opts)
    ast.fix_missing_locations(tree)
    return tree


def _n_ifs(code):
    return sum(isinstance(x, ast.If) for x in ast.walk(ast.parse(code)))


def _has_bundled_call_subscript(code):
    for node in ast.walk(ast.parse(code)):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Tuple)
                and node.value.elts and isinstance(node.value.elts[-1], ast.Call)):
            return True
    return False


_FLAT = dict(output="text", min_blocks=1, obf_strings=False,
             shuffle_states=False, opaque_predicates=False, bogus_blocks=False)


# --------------------------------------------------------------------------- intent 2: _get routed
def test_get_calls_routed_at_statement_positions():
    """A const_archive `_get(...)` accessor that is the direct value of an Assign-to-Name / Return
    becomes a push/invoke sequence under hide_external_args. Structural signals: a fresh threading
    preamble appears, the call scatters into more dispatcher states, no bundled `(...)[-1]` tuple
    survives, and no Ellipsis marker leaks."""
    src = ("def f():\n"
           "    x = \"hello world here\"\n"
           "    y = \"second string val\"\n"
           "    return x + y\n")
    off = obf_func(src, _O(const_archive=True, hide_external_args=False, **_FLAT))
    on = obf_func(src, _O(const_archive=True, hide_external_args=True, **_FLAT))
    # f itself has no external calls, so the ONLY routing source is the marked _get accessors.
    assert "import threading" not in off, "second pass must be inert without hide_external_args"
    assert on.count("import threading") == 1, "routed _get must inject a fresh push/invoke preamble"
    assert _n_ifs(on) > _n_ifs(off), "routed _get must scatter into more dispatcher states"
    assert not _has_bundled_call_subscript(on), "routed _get must be flat, not a bundled tuple"
    assert "..." not in on, "Ellipsis markers must be consumed by the flattener"
    # equivalence
    orig = _ns(src, "f"); obf = _ns(on, "f")
    assert _obs(orig, ()) == _obs(obf, ())


def test_get_routed_structurally_in_pre_flatten_ast():
    """Pre-flatten: the marked `_get(...)` statement values become the tagged push/invoke bundle
    that the splitter expands; assert the routed (push,...,invoke) statements exist in user code."""
    src = "def f():\n    s = \"abcdefghij\"\n    return s\n"
    opts = _O(const_archive=True, hide_external_args=True, **_FLAT)
    tree = _pre_flatten(src, opts, include_second=True)
    fdef = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "f")
    # After the splitter, the routed accessor shows as `<push>(<arg>)` Expr stmts + an invoke call.
    has_push_expr = any(isinstance(st, ast.Expr) and isinstance(st.value, ast.Call)
                        and isinstance(st.value.func, ast.Name) for st in fdef.body)
    assert has_push_expr, f"expected push() statements in routed user body:\n{ast.unparse(fdef)}"


# --------------------------------------------------------------------------- intent 3: helpers untouched
@pytest.mark.parametrize("opts", [
    dict(const_archive=True, hide_external_args=True, obf_strings=False),
    dict(const_archive=True, hide_external_args=True, obf_strings=True),
    dict(name_vault=True, const_archive=True, hide_external_args=True, obf_strings=True),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, hide_external_args=True,
         obf_strings=True),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, hide_external_args=True,
         stack_calls=True, split_calls=True, obf_strings=True),
])
def test_helper_bodies_unchanged_by_second_pass(opts):
    """The SECOND pass must leave every helper FUNCTION BODY byte-identical. We run the pipeline up
    to DataObf, snapshot, run the second pass on the SAME tree, and assert no helper def body's
    `ast.dump` changed (only the user function `f` changes)."""
    import copy
    src = ("def f(a):\n"
           "    x = \"hello world\"\n"
           "    y = 1234567\n"
           "    return x.upper() + str(y) + repr(len(x)) + str(max(a, 0))\n")
    o = _O(output="text", min_blocks=1, **opts)
    tree = _pre_flatten(src, o, include_second=False)
    before = copy.deepcopy(tree)
    after = StackCallPass(phase="post_vault").transform(tree, o)

    def helpers(t):
        return {n.name: ast.dump(ast.Module(body=n.body, type_ignores=[]))
                for n in ast.walk(t) if isinstance(n, ast.FunctionDef) and n.name != "f"}

    hb, ha = helpers(before), helpers(after)
    common = set(hb) & set(ha)
    changed = [k for k in common if hb[k] != ha[k]]
    assert not changed, f"second pass changed helper bodies {changed} (opts={opts})"


def test_helper_get_calls_not_routed_in_emitted_module():
    """In a fully emitted module, no helper def's body may contain a routed push/invoke wrapper:
    the `_get`/`_ks`/`_kdf`/`_dec`/push/pop/invoke helper internals stay plain. We assert that the
    routed-call marker (`_pyobf_pushn` tagged Subscript) appears ONLY inside the user function."""
    src = ("def f():\n"
           "    x = \"hello world here\"\n"
           "    return x.upper() + str(len(x))\n")
    opts = _O(output="text", min_blocks=1, name_vault=True, name_vault_attrs=True,
              const_archive=True, hide_external_args=True, obf_strings=True)
    tree = _pre_flatten(src, opts, include_second=True)

    def body_has_routed(body):
        return any(isinstance(n, ast.Subscript) and getattr(n, "_pyobf_pushn", 0) >= 1
                   for st in body for n in ast.walk(st))

    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name != "f":
            assert not body_has_routed(n.body), f"helper {n.name} body was routed by the second pass"


# --------------------------------------------------------------------------- intent 1: _D[k] NOT routed
def test_vault_subscript_calls_not_routed():
    """Vault `_D[k](...)` calls are deliberately NOT routed by the second pass (routing them would
    corrupt the first pass's push helper, whose `s = getattr(...)` NameVault rewrites into a routable
    `s = _D[k](...)` statement). Assert: the SECOND pass does not change a tree whose only routable
    candidates are vault `_D[k]` calls (no const_archive => no `_get` markers). Equivalence holds."""
    import copy
    src = "def f(xs):\n    return len(xs) + max(xs)\n"
    # name_vault on, const_archive OFF => marked calls are ONLY vault _D[k] (no _get); the second
    # pass must be a no-op here (vault calls are unmarked for routing).
    o = _O(output="text", min_blocks=1, name_vault=True, hide_external_args=True, obf_strings=False)
    tree = _pre_flatten(src, o, include_second=False)
    before = ast.dump(tree)
    after = StackCallPass(phase="post_vault").transform(tree, o)
    assert ast.dump(after) == before, "second pass must not route vault _D[k] calls"
    # full build still equivalent
    out = obf_func(src, o)
    orig = _ns(src, "f"); obf = _ns(out, "f")
    for a in ([1, 2, 3], [5], [9, 2]):
        assert _obs(orig, (a,)) == _obs(obf, (a,))


# --------------------------------------------------------------------------- intent 6: OFF => inert
def test_hide_external_off_second_pass_inert():
    """With hide_external_args=False the second pass is a strict no-op: running it on a fully
    pre-flattened tree leaves the tree byte-identical (`ast.dump` unchanged). Snapshot-before/after
    on the SAME tree object (comparing two separate builds would spuriously differ by name/RSA-key
    drift from the process-global name counter + per-build RNG)."""
    src = ("def f():\n"
           "    a = \"alpha\"\n"
           "    b = \"beta\"\n"
           "    return a + b\n")
    for opts in (dict(const_archive=True),
                 dict(const_archive=True, name_vault=True, name_vault_attrs=True, obf_strings=True),
                 dict(const_archive=True, obf_strings=True, obf_ints=True)):
        o = _O(output="text", min_blocks=1, hide_external_args=False, **opts)
        tree = _pre_flatten(src, o, include_second=False)
        before = ast.dump(tree)
        after = StackCallPass(phase="post_vault").transform(tree, o)
        assert ast.dump(after) == before, f"second pass not inert when OFF (opts={opts})"


# --------------------------------------------------------------------------- intent 4: equivalence matrix
_MATRIX_SRCS = [
    ("def f():\n    x = \"hello world\"\n    y = 12345\n    return x.upper() + str(y)\n", "f", [()]),
    ("def f(xs):\n    p = \"sum=\"\n    return p + str(sum(xs)) + str(max(xs, default=0))\n",
     "f", [([1, 2, 3],), ([],), ([-4, 9],)]),
    ("def f(n):\n    m = \"i\"\n    out = []\n    for i in range(n):\n        out.append(m + str(i))\n    return out\n",
     "f", [(3,), (0,)]),
    ("def f(x):\n    msg = \"divide\"\n    try:\n        return 100 // x\n    except ZeroDivisionError:\n        return msg\n",
     "f", [(4,), (0,)]),
    ("def f():\n    log = []\n    big = 99887766\n    def _rec(t):\n        log.append(t)\n        return t\n"
     "    r = _rec(\"a\") + _rec(\"b\")\n    return (r, log, big)\n", "f", [()]),
    ("def f(s):\n    d = {\"k\": \"v\"}\n    return d.get(s, \"none\") + str(len(s))\n",
     "f", [("k",), ("zz",)]),
]


@pytest.mark.parametrize("src,name,args", _MATRIX_SRCS)
@pytest.mark.parametrize("opts", [
    dict(const_archive=True, hide_external_args=True),
    dict(const_archive=True, hide_external_args=True, obf_strings=True),
    dict(name_vault=True, const_archive=True, hide_external_args=True, obf_strings=True),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, hide_external_args=True,
         obf_strings=True),
    dict(name_vault=True, name_vault_attrs=True, const_archive=True, hide_external_args=True,
         obf_strings=True, obf_ints=True, dispatch_tree=True, state_delta=True, dedup=True),
    dict(name_vault=True, const_archive=True, hide_external_args=True, stack_calls=True,
         split_calls=True, obf_strings=True),
])
@pytest.mark.parametrize("seed", [0, 1, 7])
def test_equivalence_matrix(src, name, args, opts, seed):
    orig = _ns(src, name)
    out = obf_func(src, _O(output="text", seed=seed, min_blocks=1, **opts))
    obf = _ns(out, name)
    for a in args:
        assert _obs(orig, a) == _obs(obf, a), f"opts={opts} seed={seed} a={a}\n{out}"


def test_equivalence_module_path():
    """The second pass is wired into BOTH pipelines; exercise the module-body path for equivalence."""
    src = ("g = \"global string\"\n"
           "def f(n):\n"
           "    local = \"loc\"\n"
           "    return g + local + str(n) + str(len(g))\n")
    out = obf_module(src, ModuleObfOptions(output="text", seed=3, min_blocks=1, name_vault=True,
                                           name_vault_attrs=True, const_archive=True,
                                           hide_external_args=True, obf_strings=True))
    d_orig = {}
    exec(compile(src, "<m>", "exec"), d_orig)
    d_obf = {}
    exec(compile(out, "<m>", "exec"), d_obf)
    for a in (0, 5, -2):
        assert _obs(d_orig["f"], (a,)) == _obs(d_obf["f"], (a,))


# --------------------------------------------------------------------------- intent 5: launcher (RULE #0)
def _launcher_combo(**extra):
    base = dict(
        seed=1, min_blocks=1, output="text", obf_strings=True, obf_ints=True,
        shuffle_states=True, opaque_predicates=True, bogus_blocks=True, pack_body=True,
        key_from_cff=True, integrity_selfcheck=True, cohash_integrity=True, pack_decoy=True,
        detect_trace=True, detect_tools=True, detect_env=True, key_binds_env=True, attest=True,
        attest_density=0.5, detect_audit=True, attest_runtime_bind=True, anti_trace_neuter=True,
        name_vault=True, name_vault_attrs=True, const_archive=True,
        hide_external_args=True, stack_calls=True, split_calls=True,   # the call-hiding additions
    )
    base.update(extra)
    return ModuleObfOptions(**base)


_LAUNCHER_SRC = (
    "import json\n"
    "def main():\n"
    "    print(json.dumps({\"ok\": 1}, sort_keys=True))\n"
    "main()\n"
)


def _run_subprocess(text, timeout=30):
    d = tempfile.gettempdir()
    f = tempfile.NamedTemporaryFile("w", suffix="_vsr_mod.py", dir=d, delete=False, encoding="utf-8")
    f.write(text); f.close()
    try:
        r = subprocess.run([sys.executable, f.name], capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode, False
    except subprocess.TimeoutExpired:
        return "", None, True
    finally:
        os.unlink(f.name)


def _run_traced(text, timeout=30):
    d = tempfile.gettempdir()
    mod = tempfile.NamedTemporaryFile("w", suffix="_vsr_mod.py", dir=d, delete=False, encoding="utf-8")
    mod.write(text); mod.close()
    harness = (
        "import sys, runpy\n"
        "def _tr(f, e, a): return _tr\n"
        "sys.settrace(_tr)\n"
        "sys.argv = ['x']\n"
        "try: runpy.run_path(%r, run_name='__main__')\n"
        "except SystemExit: pass\n"
        "except BaseException as ex: print('EXC:', type(ex).__name__)\n"
        "finally: sys.settrace(None)\n"
    ) % (mod.name,)
    hf = tempfile.NamedTemporaryFile("w", suffix="_h.py", dir=d, delete=False, encoding="utf-8")
    hf.write(harness); hf.close()
    try:
        r = subprocess.run([sys.executable, hf.name], capture_output=True, text=True, timeout=timeout)
        return r.stdout, False
    except subprocess.TimeoutExpired:
        return "", True
    finally:
        os.unlink(mod.name); os.unlink(hf.name)


_DETECT_NAMES = ("gettrace", "settrace", "getprofile", "setprofile",
                 "addaudithook", "monitoring", "set_events", "breakpoint")


def test_launcher_with_hide_external_genuine_correct():
    """RULE #0: full attest + anti-TOCTOU + vault + const_archive + hide_external_args build runs the
    genuine path correctly in a KILLABLE subprocess. (The second pass is disabled on the launcher by
    the existing anti-TOCTOU call-routing disable, so the oracle closures stay intact.)"""
    built = obf_module(_LAUNCHER_SRC, _launcher_combo())
    out, rc, hung = _run_subprocess(built)
    assert not hung, "launcher hung (RULE #0 divergence on the GENUINE path)"
    assert rc == 0, f"launcher exit {rc}, stdout={out!r}"
    assert out.strip() == '{"ok": 1}'


def test_launcher_with_hide_external_traced_diverges():
    """RULE #0: under sys.settrace the same build must NOT print the genuine output (anti-TOCTOU
    diverges to decoy / hangs / exits). A hang counts as diverged == PASS."""
    built = obf_module(_LAUNCHER_SRC, _launcher_combo())
    out_clean, rc_clean, hung_clean = _run_subprocess(built)
    assert not hung_clean and rc_clean == 0 and out_clean.strip() == '{"ok": 1}', \
        f"genuine run broken before trace test: rc={rc_clean} hung={hung_clean} out={out_clean!r}"
    out_traced, hung_traced = _run_traced(built)
    assert hung_traced or '{"ok": 1}' not in out_traced, \
        f"traced launcher did NOT diverge (anti-TOCTOU broke): {out_traced!r}"


def test_launcher_with_hide_external_detect_surface_hidden():
    """The detect_* anti-debug API names must remain 0 plaintext in the launcher even with the
    call-hiding additions."""
    built = obf_module(_LAUNCHER_SRC, _launcher_combo())
    present = {n: built.count(n) for n in _DETECT_NAMES if n in built}
    assert not present, f"detect_* surface leaked as plaintext: {present}"
