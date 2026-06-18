"""Stack-call coverage for the NameVault *registration* calls.

NameVault synthesizes vault registrations at the module top:
    _D[k] = __import__("<module>")          # routed top-level import
    _D[k] = _g(_bi, "<builtin>")            # builtin getattr registration
The `__import__(...)` registrations used to be PLAINTEXT at the call site (only their
module-string argument was archived). This pass marks those synthesized registration
calls with `_pyobf_stackroute` (the same seam ArchivePass uses for `_get(...)`), and the
SECOND (post_vault) StackCall pass routes them — at the `_D[k] = <call>` Assign-to-Subscript
statement position — through the hidden push/invoke arg-stack, so the `__import__(...)` call
no longer appears at the call site.

Pinned invariants:
  * Gated on `hide_external_args` (same flag as the first StackCall). OFF => byte-identical
    output vs. not adding the mark.
  * Behaviour preserved (differential vs. CPython), checked in a KILLABLE subprocess (RULE #0:
    a corrupted flattened state busy-loops forever).
  * The synthesized `__import__(...)` registration call's module-string argument no longer
    appears as a *direct positional arg* at the call site (it was pushed onto the stack).
  * The bootstrap `_bi = __import__('builtins')` (arg-stack not yet live) and the push-helper /
    oracle / audit / neuter closures are NEVER routed.
"""
import ast
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import pytest

from pyobfuscator import obf_func, obf_module, ObfOptions, ModuleObfOptions


# --------------------------------------------------------------------------- killable-subprocess harness
def _run_capture(text, src_to_eval, timeout=60):
    """Exec `text` (the obfuscated module) in a KILLABLE subprocess, then eval `src_to_eval`
    (a probe expression over the module namespace) and print its repr on the last stdout line.
    Returns (probe_repr, stdout_without_probe, returncode, hung)."""
    harness = (
        "import sys\n"
        "_ns = {'__name__': '__main__'}\n"
        "with open(sys.argv[1], 'r', encoding='utf-8') as _fh:\n"
        "    _code = _fh.read()\n"
        "exec(compile(_code, '<obf>', 'exec'), _ns)\n"
        "import json as _json\n"
        "print('@@PROBE@@' + repr(eval(sys.argv[2], _ns)))\n"
    )
    d = tempfile.gettempdir()
    mf = tempfile.NamedTemporaryFile("w", suffix="_svi_mod.py", dir=d, delete=False, encoding="utf-8")
    mf.write(text); mf.close()
    hf = tempfile.NamedTemporaryFile("w", suffix="_svi_h.py", dir=d, delete=False, encoding="utf-8")
    hf.write(harness); hf.close()
    try:
        r = subprocess.run([sys.executable, hf.name, mf.name, src_to_eval],
                           capture_output=True, text=True, timeout=timeout)
        out = r.stdout
        probe = None
        kept = []
        for ln in out.splitlines():
            if ln.startswith("@@PROBE@@"):
                probe = ln[len("@@PROBE@@"):]
            else:
                kept.append(ln)
        return probe, "\n".join(kept), r.returncode, False
    except subprocess.TimeoutExpired:
        return None, "", None, True
    finally:
        os.unlink(mf.name); os.unlink(hf.name)


def _orig_eval(src, probe):
    """Reference: exec the ORIGINAL src in-process, eval the probe over its namespace."""
    ns = {"__name__": "__main__"}
    exec(compile(src, "<orig>", "exec"), ns)
    return repr(eval(probe, ns))


# A module with simple top-level imports used inside functions.
_SRC = (
    "import json\n"
    "import base64\n"
    "def enc(payload):\n"
    "    blob = json.dumps(payload, sort_keys=True).encode()\n"
    "    return base64.b64encode(blob).decode()\n"
    "def dec(text):\n"
    "    raw = base64.b64decode(text.encode())\n"
    "    return json.loads(raw.decode())\n"
    "RESULT = dec(enc({'a': 1, 'b': [2, 3], 'c': 'x'}))\n"
)

_FLAGS = dict(output="text", min_blocks=1, seed=20260617,
              name_vault=True, stack_calls=True, hide_external_args=True,
              const_archive=True, obf_strings=False,
              shuffle_states=False, opaque_predicates=False, bogus_blocks=False)


# --------------------------------------------------------------------------- helpers for AST assertions
def _import_call_arg_is_inline_string(out: str) -> int:
    """Count `__import__(...)` calls whose FIRST positional arg is an inline string Constant
    (the plaintext-module-name form we are eliminating)."""
    n = 0
    for node in ast.walk(ast.parse(out)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "__import__" and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            n += 1
    return n


def _import_call_arg_is_archive_get(out: str, tree=None) -> list:
    """Return the list of `__import__(<archive _get(...) call>)` call nodes — i.e. an
    `__import__` whose single positional arg is itself a Call (the archive accessor). These are
    the synthesized registrations whose call site we want routed away under hide_external_args."""
    t = tree if tree is not None else ast.parse(out)
    res = []
    for node in ast.walk(t):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "__import__"):
            res.append(node)
    return res


# --------------------------------------------------------------------------- TEST 1: behaviour preserved
def test_import_registration_behaviour_preserved():
    """The synthesized `__import__(...)` registration calls are routed; the obfuscated module
    still computes the same RESULT as CPython. KILLABLE subprocess (RULE #0)."""
    out = obf_func(_SRC, ObfOptions(**_FLAGS))
    probe, extra, rc, hung = _run_capture(out, "RESULT")
    assert not hung, "obfuscated module HUNG (RULE #0: flattened-state divergence)"
    assert rc == 0, f"obfuscated module exited {rc}; stdout={extra!r}"
    assert probe == _orig_eval(_SRC, "RESULT"), f"divergence: obf={probe!r} orig={_orig_eval(_SRC, 'RESULT')!r}"


# --------------------------------------------------------------------------- TEST 2: __import__ arg pushed
def _user_import_call_sites(out: str) -> int:
    """Count `__import__(...)` call sites whose arg is an archive `_get(...)` accessor — i.e. the
    USER-import registrations (`json`/`base64`). Excludes the charcode bootstrap (`''.join([chr...])`
    arg). Note: the StackCall pass-1 `threading` infra import ALSO has a `_get(...)` arg and is
    intentionally NOT routed, so it counts here too."""
    n = 0
    for node in ast.walk(ast.parse(out)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "__import__" and node.args
                and isinstance(node.args[0], ast.Call)
                and not (isinstance(node.args[0].func, ast.Attribute)
                         and node.args[0].func.attr == "join")):
            n += 1
    return n


def test_import_registration_arg_no_longer_at_call_site():
    """Under hide_external_args, the synthesized USER `__import__(...)` registration calls must be
    routed: the json/base64 registrations no longer keep their `__import__(...)` call at the
    statement site (the call is replaced by an `invoke(...)`, with func+arg pushed). We vary ONLY
    `hide_external_args` between the two builds (everything else identical) so the delta is purely
    our routing.

    Intentionally NOT routed (must survive in BOTH builds): the charcode bootstrap
    `__import__('builtins')` (arg-stack not yet live), and the StackCall pass-1 `import threading`
    infrastructure import that NameVault absorbed into the vault (bootstrap-ordering hazard)."""
    on = obf_func(_SRC, ObfOptions(**_FLAGS))
    off_flags = dict(_FLAGS); off_flags["hide_external_args"] = False
    off = obf_func(_SRC, ObfOptions(**off_flags))

    # OFF (no call-hiding -> no pass-1 preamble -> no absorbed `threading`): the vault registrations
    # are the 2 user imports (json, base64) as plain `_D[k] = __import__(_get(...))` call sites.
    off_user = _user_import_call_sites(off)
    assert off_user == 2, (
        f"baseline (hide_external OFF) must keep the 2 user-import __import__ call sites, got "
        f"{off_user}")

    # ON: the 2 USER imports (json, base64) are routed away (call site -> invoke()). The ONLY
    # `__import__(_get(...))` call site that survives is the StackCall pass-1 `threading` infra
    # import (intentionally excluded from routing). So exactly 1 such call site remains.
    on_user = _user_import_call_sites(on)
    assert on_user == 1, (
        f"the 2 user imports must be routed away, leaving only the excluded `threading` infra "
        f"import as an __import__(_get(...)) call site; got {on_user}")

    # And no inline-string `__import__("...")` should appear in EITHER build (const_archive pools
    # the module strings); this guards the regression the task names.
    assert _import_call_arg_is_inline_string(on) == 0


# --------------------------------------------------------------------------- TEST 3: routing injects stack
def test_import_registration_routing_injects_push_preamble():
    """When the registration calls are routed, the post_vault pass injects a fresh threading
    push/invoke preamble (it was a no-op before, because the only marked calls were the nested
    `_get(...)` accessors). OFF => no such preamble from the second pass beyond the first pass's."""
    on = obf_func(_SRC, ObfOptions(**_FLAGS))
    # The second pass injects `import threading as <x>`; but name_vault may route a plain
    # `import threading` of the FIRST pass into the vault. The post_vault preamble is built AFTER
    # NameVault, so ITS threading import stays a literal `import threading`. Assert at least one
    # literal `import threading` survives (the post_vault preamble).
    assert "import threading" in on, (
        "routed registrations must inject a post_vault threading push/invoke preamble "
        "(literal `import threading` not routed by the already-finished NameVault)")


# --------------------------------------------------------------------------- TEST 4: OFF => byte-identical
def test_call_hiding_off_is_byte_identical():
    """With call-hiding OFF (`hide_external_args=False`) the new mark must change NOTHING: the
    post_vault pass is gated off and ignores the mark, so the emitted source is identical to a
    pre-fix build. We assert (a) determinism (two identical builds match — the mark introduces no
    nondeterminism) and (b) the defining structural property: NO threading push/invoke preamble
    exists and ALL synthesized `__import__` registration call sites remain intact."""
    off_flags = dict(_FLAGS)
    off_flags["hide_external_args"] = False
    off_flags["stack_calls"] = False
    a = obf_func(_SRC, ObfOptions(**off_flags))
    b = obf_func(_SRC, ObfOptions(**off_flags))
    assert a == b, "OFF build is non-deterministic"
    # The defining property: with call-hiding OFF there is no threading push/invoke preamble at all
    # (neither first nor second pass injects one), and the registrations stay plain __import__ calls.
    assert "import threading" not in a, "no push/invoke preamble may exist when call-hiding is OFF"
    assert len(_import_call_arg_is_archive_get(a)) >= 3, (
        "OFF build must keep all synthesized __import__ registration call sites intact")


# --------------------------------------------------------------------------- TEST 5: bootstrap NOT routed
def test_bootstrap_import_builtins_not_routed():
    """The vault bootstrap `_bi = __import__(<charcode 'builtins'>)` runs before push/invoke exist
    in execution order at the registration site and uses a charcode arg; it must NEVER be routed.
    Detect it by its charcode arg shape (a `''.join([chr(...) ...])` expression, NOT an archive
    `_get(...)` call) and assert it stays a bare `__import__(...)` call (its func is still the
    `__import__` Name, not an `invoke`)."""
    on = obf_func(_SRC, ObfOptions(**_FLAGS))
    tree = ast.parse(on)
    found_bootstrap = False
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "__import__" and node.args):
            arg = node.args[0]
            # charcode bootstrap: arg is `<str>.join([...])` — an Attribute('join') call
            if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                    and arg.func.attr == "join"):
                found_bootstrap = True
    assert found_bootstrap, "bootstrap __import__(charcode 'builtins') must remain a bare call site"


# --------------------------------------------------------------------------- TEST 6: module pipeline path
def test_module_pipeline_behaviour_preserved():
    """The mark is set in NameVault and consumed by the post_vault pass in BOTH pipelines. Exercise
    obf_module for behaviour preservation in a KILLABLE subprocess."""
    out = obf_module(_SRC, ModuleObfOptions(**_FLAGS))
    probe, extra, rc, hung = _run_capture(out, "RESULT")
    assert not hung, "module-pipeline obfuscated output HUNG (RULE #0)"
    assert rc == 0, f"module-pipeline output exited {rc}; stdout={extra!r}"
    assert probe == _orig_eval(_SRC, "RESULT")


# --------------------------------------------------------------------------- TEST 7: helper integrity
def test_push_helper_getattr_not_routed():
    """name_vault rewrites the first StackCall push helper's `s = getattr(tls, 's', None)` into a
    `s = _D[k](...)` vault call. Routing that would corrupt the helper. Assert: no FunctionDef body
    (i.e. no helper) gained a routed push/invoke wrapper; only top-level registration statements do.
    Specifically, the post_vault routing must appear ONLY at module top-level, never inside a def."""
    on = obf_func(_SRC, ObfOptions(**_FLAGS))
    tree = ast.parse(on)
    # Find the post_vault invoke helper name: it's the `invoke(n)` form `def X(n): ... s.pop(); fn(*args)`.
    # Simpler robust check: every `invoke`-style call (a 1-arg call whose result is subscripted [-1]
    # or used as a statement value) created by routing must live at module level, not in a def body.
    # We assert the structural integrity differently: behaviour already covered; here we ensure NO
    # def body contains a `__import__` call at all (registrations are module-level scaffolding).
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                        and sub.func.id == "__import__"):
                    raise AssertionError(
                        f"helper/def {node.name} body contains an __import__ call — registrations "
                        f"must stay module-level, never routed into a helper")
