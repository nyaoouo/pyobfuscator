"""Gate for the cross-pass name-collision fix (global-counter unique names + final seeded rename).

ORIGINAL BUG: every pass built `Namer(options.seed, taken)` and drew from the SAME seeded RNG
sequence; collisions were prevented only by the per-pass `taken` set. On the packed launcher, the
dense name population made FlattenPass (taken = one function's locals) re-emit a name another pass
had already used for a module global (e.g. the const-archive `_get` accessor), so `_get` and a
dispatcher state variable collided -> RecursionError / "'int' object has no attribute 'pop'".

These tests build the launcher with the FULL attest + anti-TOCTOU combo PLUS name_vault +
name_vault_attrs + const_archive, run the genuine path in a KILLABLE SUBPROCESS (RULE #0: a
diverged CFF dispatcher busy-loops forever), and assert it exits 0 with output identical to the
same build WITHOUT the vault/archive flags.
"""
import os
import subprocess
import sys
import tempfile

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions


_SRC = (
    "import json\n"
    "def main():\n"
    "    print(json.dumps({\"ok\": 1}, sort_keys=True))\n"
    "main()\n"
)


def _full_combo(**extra):
    base = dict(
        seed=1, min_blocks=1, output="text", obf_strings=True, obf_ints=True,
        shuffle_states=True, opaque_predicates=True, bogus_blocks=True, pack_body=True,
        key_from_cff=True, integrity_selfcheck=True, cohash_integrity=True, pack_decoy=True,
        detect_trace=True, detect_tools=True, detect_env=True, key_binds_env=True, attest=True,
        attest_density=0.5, detect_audit=True, attest_runtime_bind=True, anti_trace_neuter=True,
    )
    base.update(extra)
    return ModuleObfOptions(**base)


def _run(launcher_text, timeout=20):
    """Run launcher in a fresh subprocess (RULE #0). Returns (stdout, returncode, hung)."""
    d = tempfile.gettempdir()
    f = tempfile.NamedTemporaryFile("w", suffix="_vault_mod.py", dir=d, delete=False,
                                    encoding="utf-8")
    f.write(launcher_text); f.close()
    try:
        r = subprocess.run([sys.executable, f.name], capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout, r.returncode, False
    except subprocess.TimeoutExpired:
        return "", None, True
    finally:
        os.unlink(f.name)


def _run_traced(launcher_text, timeout=20):
    """Run the launcher under sys.settrace in a fresh subprocess (the _solve_capture attack shape,
    mirroring tests/test_protect_toctou.py). A tracer active at load -> anti-TOCTOU diverges (the
    genuine body never runs). Returns (stdout, hung)."""
    d = tempfile.gettempdir()
    mod = tempfile.NamedTemporaryFile("w", suffix="_vault_mod.py", dir=d, delete=False,
                                      encoding="utf-8")
    mod.write(launcher_text); mod.close()
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
        r = subprocess.run([sys.executable, hf.name], capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout, False
    except subprocess.TimeoutExpired:
        return "", True
    finally:
        os.unlink(mod.name); os.unlink(hf.name)


# detect_* API names the anti-debug surface uses; the vaulted launcher must hide ALL of them.
_DETECT_NAMES = ("gettrace", "settrace", "getprofile", "setprofile",
                 "addaudithook", "monitoring", "set_events", "breakpoint")


def test_launcher_const_archive_vault_runs_and_matches_plain():
    """Gate 1: the launcher with name_vault + name_vault_attrs + const_archive runs correctly,
    producing the SAME stdout as the build WITHOUT those flags (proves the collision is fixed)."""
    plain = obf_module(_SRC, _full_combo())
    vaulted = obf_module(_SRC, _full_combo(name_vault=True, name_vault_attrs=True,
                                           const_archive=True))

    out_plain, rc_plain, hung_plain = _run(plain)
    assert not hung_plain, "plain build hung (RULE #0 divergence)"
    assert rc_plain == 0, f"plain build exit {rc_plain}, stdout={out_plain!r}"
    assert out_plain.strip() == '{"ok": 1}'

    out_vault, rc_vault, hung_vault = _run(vaulted)
    assert not hung_vault, "vaulted build hung -> cross-pass collision NOT fixed (RULE #0)"
    assert rc_vault == 0, f"vaulted build exit {rc_vault}, stdout={out_vault!r}"
    assert out_vault.strip() == out_plain.strip()


def test_launcher_vault_no_temp_name_leak():
    """The final launcher text must contain NO monotonic temp names (_pyobf_g<digits>);
    every temp must have been renamed to a uniform _pyobf_<hex> by finalize_names."""
    import re
    vaulted = obf_module(_SRC, _full_combo(name_vault=True, name_vault_attrs=True,
                                           const_archive=True))
    leaks = re.findall(r"_pyobf_g\d+", vaulted)
    assert not leaks, f"temp names leaked into output: {sorted(set(leaks))[:10]}"


def test_launcher_vault_hides_detect_surface():
    """Gate 2: the vaulted launcher text must contain NONE of the anti-debug detect_* API names
    as plaintext. const_archive pools the attr-name strings (the
    sys.settrace/gettrace/monitoring.set_events/etc surface), so each must drop to 0 occurrences.
    This proves the vault is ACTIVE on the launcher."""
    vaulted = obf_module(_SRC, _full_combo(name_vault=True, name_vault_attrs=True,
                                           const_archive=True))
    present = {n: vaulted.count(n) for n in _DETECT_NAMES if n in vaulted}
    assert not present, f"detect_* surface leaked as plaintext in the vaulted launcher: {present}"


def test_launcher_vault_traced_diverges_to_decoy():
    """Gate 3: anti-TOCTOU must still fire with the full vault on the launcher. Running the vaulted
    launcher under sys.settrace must NOT print the genuine output (diverges to decoy / hangs /
    exits). RULE #0: a hang counts as diverged == PASS (killable subprocess)."""
    vaulted = obf_module(_SRC, _full_combo(name_vault=True, name_vault_attrs=True,
                                           const_archive=True))
    # sanity: the untraced genuine path produces the real output (so the divergence below is the
    # tracer's effect, not a broken build).
    out_clean, rc_clean, hung_clean = _run(vaulted)
    assert not hung_clean and rc_clean == 0 and out_clean.strip() == '{"ok": 1}', \
        f"vaulted genuine run broken: rc={rc_clean} hung={hung_clean} out={out_clean!r}"
    out_traced, hung_traced = _run_traced(vaulted)
    assert hung_traced or '{"ok": 1}' not in out_traced, \
        f"vaulted launcher did NOT diverge under trace (anti-TOCTOU broke): {out_traced!r}"


def test_launcher_vault_body_launcher_names_disjoint():
    """Gate 4 (the mechanism): the body and the launcher are finalized from DISJOINT namespace
    salts, so their module-level _pyobf_<hex> bindings cannot collide. We assert the two finalize
    RNG streams differ: finalize_names(seed, ns_salt=0) (launcher) vs the body's _BODY_NS_SALT must
    pick different first names for the same input. (Disjoint streams => the const_archive _get/_ks/
    _kdf functions the body injects can never overwrite the launcher's identically-named dispatcher
    variable -- the exact bug the disjoint-namespace fix addresses.)"""
    import ast
    from pyobfuscator.cff.rename import finalize_names
    from pyobfuscator.cff.names import Namer, _GEN_ISSUED
    from pyobfuscator.protect.core import _BODY_NS_SALT

    assert _BODY_NS_SALT != 0, "body salt must be non-zero so it is disjoint from the launcher's"

    def _first_final(ns_salt):
        # Mint one fresh temp name, finalize a tree that uses it, return its _pyobf_<hex> mapping.
        namer = Namer(7, set())
        t = namer.fresh("x")
        assert t in _GEN_ISSUED
        tree = ast.parse(f"{t} = 1\n")
        finalize_names(tree, 7, ns_salt=ns_salt)
        return ast.unparse(tree).split(" =", 1)[0].strip()

    launcher_name = _first_final(0)
    body_name = _first_final(_BODY_NS_SALT)
    assert launcher_name != body_name, \
        f"body and launcher finalize salts are NOT disjoint: both -> {launcher_name}"


def test_launcher_vault_deterministic():
    """Gate 5: the same full-vault build twice in one process is byte-identical (determinism comes
    from the seeded finalize rename, including the new ns_salt, not the global counter)."""
    opts = dict(name_vault=True, name_vault_attrs=True, const_archive=True)
    a = obf_module(_SRC, _full_combo(**opts))
    b = obf_module(_SRC, _full_combo(**opts))
    assert a == b, "full-vault launcher build is not deterministic"
