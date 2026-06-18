"""Anti-TOCTOU defenses: inner exec co_filename randomization, audit-hook tripwire, oracle
runtime-binding, and set-API neuter. These defenses close the gap where an audit hook on the
inner `exec` event (invisible to the anti-debug checklist) is installed before sys.settrace is
attached — after the launcher's one-time bootstrap checks have already passed.

Divergence is asserted via a KILLABLE SUBPROCESS (a wrong-state CFF dispatcher busy-loops forever).
In-process checks that run a launcher save/restore the process-wide trace APIs the set-API neuter
patches, so they cannot contaminate the rest of the suite.
"""
import os
import re
import subprocess
import sys
import tempfile

import pytest

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, ObfOptions


_LOOP = ("def main():\n    t = 0\n    for i in range(10):\n        t += i\n    print(t)\n"
         "\nif __name__ == '__main__':\n    main()\n")


def _build(src=_LOOP, **kw):
    base = dict(seed=1, min_blocks=1, pack_body=True, key_from_cff=True,
                integrity_selfcheck=True, output="text")
    base.update(kw)
    return obf_module(src, ModuleObfOptions(**base))


def _run_subprocess(launcher_text, argv1=None, settrace=False, timeout=20):
    """Run the launcher in a fresh subprocess (optionally under sys.settrace). Returns
    (stdout, hung). hung=True on timeout (a diverged dispatcher busy-loops)."""
    d = tempfile.gettempdir()
    mod = tempfile.NamedTemporaryFile("w", suffix="_toctou_mod.py", dir=d, delete=False, encoding="utf-8")
    mod.write(launcher_text); mod.close()
    if settrace:
        harness = (
            "import sys, runpy\n"
            "def _tr(f,e,a): return _tr\n"
            "sys.settrace(_tr)\n"
            "sys.argv=['x'%s]\n"
            "try: runpy.run_path(%r, run_name='__main__')\n"
            "except SystemExit: pass\n"
            "except BaseException as ex: print('EXC:', type(ex).__name__)\n"
            "finally: sys.settrace(None)\n"
        ) % ((", %r" % argv1) if argv1 is not None else "", mod.name)
        hf = tempfile.NamedTemporaryFile("w", suffix="_h.py", dir=d, delete=False, encoding="utf-8")
        hf.write(harness); hf.close()
        run_path = hf.name
    else:
        run_path = mod.name
    cmd = [sys.executable, run_path] + ([argv1] if (argv1 is not None and not settrace) else [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, False
    except subprocess.TimeoutExpired:
        return "", True
    finally:
        os.unlink(mod.name)
        if settrace:
            os.unlink(run_path)


# ---- inner exec co_filename randomization ----------------------------------
def test_b1_inner_filename_not_pyobf():
    t = _build()
    assert "<pyobf>" not in t
    # The inner code object's co_filename is randomized ('<8hex>'), passed to the compile call. Under
    # integrity_selfcheck that compile is the global-effective form `_G.get("compile", compile)(...)`, so
    # match on the randomized filename + 'exec' mode args rather than a literal `compile(` prefix.
    assert re.search(r"'<[0-9a-f]{8}>', 'exec'\)", t), "no randomized inner filename"


def test_b1_genuine_runs_text_and_pyc():
    out, hung = _run_subprocess(_build())
    assert not hung and out.strip() == "45"


def test_b1_filename_seed_dependent():
    f1 = re.search(r"'(<[0-9a-f]{8}>)'", _build(seed=1)).group(1)
    f2 = re.search(r"'(<[0-9a-f]{8}>)'", _build(seed=2)).group(1)
    assert f1 != f2
    # deterministic under a fixed seed
    assert _build(seed=1) == _build(seed=1)


# ---- audit-hook tripwire ---------------------------------------------------
def test_b2_audit_hook_emitted_when_on():
    t = _build(detect_audit=True, key_binds_env=True, pack_decoy=True)
    assert "addaudithook" in t
    assert "'sys.settrace'" in t and "'sys.setprofile'" in t


def test_b2_no_audit_hook_when_off():
    assert "addaudithook" not in _build(detect_trace=True, key_binds_env=True, pack_decoy=True)


# ---- oracle runtime-binding ------------------------------------------------
def _attest_kw(**extra):
    kw = dict(attest=True, attest_density=0.5)
    kw.update(extra)
    return kw


def test_b3_genuine_runs_and_is_behaviorally_unchanged():
    # signal == 0 in a clean env -> the runtime-bound oracle equals the pure oracle -> same result.
    bound, _ = _run_subprocess(_build(**_attest_kw(attest_runtime_bind=True, detect_audit=True)))
    pure, _ = _run_subprocess(_build(**_attest_kw()))
    assert bound.strip() == pure.strip() == "45"


def test_b3_traced_diverges():
    # any tracer active during the body -> oracle signal != 0 on the next gated goto -> divergence.
    t = _build(**_attest_kw(attest_runtime_bind=True, detect_audit=True))
    out, hung = _run_subprocess(t, settrace=True)
    assert hung or "45" not in out, "runtime-bound oracle did not diverge under trace"


def test_b3_oracle_folds_all_signals():
    t = _build(**_attest_kw(attest_runtime_bind=True, detect_audit=True))
    assert "gettrace" in t and "getprofile" in t and "''.join)" in t  # gt/gp + pow recheck (type(''.join))


# ---- neuter the debug set-APIs ---------------------------------------------
def _exec_launcher_capture_settrace(honeypot):
    """Exec a neuter-enabled launcher in-process; return (patched, none_ok, tracer_result). Saves/restores the
    process-wide trace APIs so the rest of the suite is unaffected."""
    import threading
    t = _build(anti_trace_neuter=True, anti_trace_neuter_honeypot=honeypot)
    sv = (sys.settrace, sys.setprofile, sys.addaudithook, threading.settrace, threading.setprofile)
    try:
        ns = {"__name__": "x"}
        exec(compile(t, "<o>", "exec"), ns)
        guard = sys.settrace
        patched = type(guard).__name__ == "function"
        none_ok = (guard(None) is None) and (sys.gettrace() is None)

        def _trc(*a):
            return _trc
        try:
            guard(_trc)
            res = ("blackhole", sys.gettrace())
        except SystemExit:
            res = ("SystemExit", sys.gettrace())
        return patched, none_ok, res
    finally:
        (sys.settrace, sys.setprofile, sys.addaudithook,
         threading.settrace, threading.setprofile) = sv
        sys.settrace(None)


def test_b5_blackhole_blocks_tracer_allows_none():
    patched, none_ok, (kind, gt_after) = _exec_launcher_capture_settrace(honeypot=False)
    assert patched and none_ok
    assert kind == "blackhole" and gt_after is None   # tracer install was swallowed


def test_b5_honeypot_raises_systemexit():
    patched, none_ok, (kind, _gt) = _exec_launcher_capture_settrace(honeypot=True)
    assert patched and none_ok and kind == "SystemExit"


# ---- options surface -----------------------------------------------------------
def test_new_flags_default_off_and_not_in_presets():
    d = ObfOptions()
    assert not (d.detect_audit or d.attest_runtime_bind or d.anti_trace_neuter
                or d.anti_trace_neuter_honeypot)
    full = ObfOptions(protect_level="full")
    assert not (full.detect_audit or full.attest_runtime_bind or full.anti_trace_neuter)


# ---- full stack: a flag-bearing program does not leak under the audit-TOCTOU attack ----
_FLAGSRC = ("import sys\n"
            "def check(g):\n    s = 0\n    for c in g:\n        s += ord(c)\n    return g == %r\n"
            "def main():\n    g = sys.argv[1] if len(sys.argv) > 1 else ''\n"
            "    print('Correct!' if check(g) else 'Nope')\n"
            "if __name__ == '__main__':\n    main()\n")
_SECRET = "{toctou-secret-9Q}"


def _attack(launcher_text, broad, timeout=20):
    d = tempfile.gettempdir()
    mod = tempfile.NamedTemporaryFile("w", suffix="_atk_mod.py", dir=d, delete=False, encoding="utf-8")
    mod.write(launcher_text); mod.close()
    arm = ("_co.co_filename.startswith('<') and 'importlib' not in _co.co_filename" if broad
           else "_co.co_filename == '<pyobf>'")
    probe = (
        "import sys, runpy, types\n"
        "H=[]; st={'a':False}\n"
        "def lt(f,e,a):\n"
        " try:\n"
        "  co=f.f_code\n"
        "  if co.co_filename.startswith('<') and 'importlib' not in co.co_filename:\n"
        "   for n,v in list(f.f_locals.items()):\n"
        "    if isinstance(v,(str,bytes,int)): H.append(repr(v)[:200])\n"
        " except Exception: pass\n"
        " return lt\n"
        "def hook(ev,args):\n"
        " if ev=='exec' and not st['a'] and args:\n"
        "  _co=args[0]\n"
        "  if isinstance(_co,types.CodeType) and (%s):\n"
        "   st['a']=True; sys.settrace(lt)\n"
        "sys.addaudithook(hook)\n"
        "sys.argv=[%r,'GUESS']\n"
        "try: runpy.run_path(%r, run_name='__main__')\n"
        "except SystemExit: pass\n"
        "except BaseException: pass\n"
        "finally: sys.settrace(None)\n"
        "sys.stdout.write('__H__'+repr(H))\n"
    ) % (arm, mod.name, mod.name)
    hf = tempfile.NamedTemporaryFile("w", suffix="_atk.py", dir=d, delete=False, encoding="utf-8")
    hf.write(probe); hf.close()
    try:
        r = subprocess.run([sys.executable, hf.name], capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""   # hung == diverged == no leak
    finally:
        os.unlink(mod.name); os.unlink(hf.name)


@pytest.mark.parametrize("broad", [False, True])
def test_full_stack_no_secret_leak_under_audit_toctou(broad):
    t = _build(_FLAGSRC % _SECRET, obf_strings=True, pack_decoy=True,
               decoy_src="def main():\n    print('Nope')\n",
               detect_trace=True, detect_tools=True, detect_env=True, key_binds_env=True,
               **_attest_kw(detect_audit=True, attest_runtime_bind=True, anti_trace_neuter=True))
    assert _SECRET not in t                       # not plaintext in the launcher
    harvest = _attack(t, broad=broad)
    assert _SECRET not in harvest                 # not harvested via the audit-TOCTOU trace
