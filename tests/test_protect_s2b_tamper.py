import sys, os, builtins
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

OPTS = dict(min_blocks=1, seed=7, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True)
SRC = "REALMARK = 555\ndef who():\n    return 'real'\n"

def _run(out):
    ns = {"__name__": "m"}; exec(compile(out, "<t>", "exec"), ns); return ns

def test_untampered_real_then_monkeypatch_sum_yields_decoy():
    out = obf_module(SRC, ModuleObfOptions(output="text", **OPTS))
    # untampered -> real
    ns = _run(out)
    assert ns.get("REALMARK") == 555 and "__pyobf_decoy__" not in ns
    # tamper: replace builtin sum with a python function -> builtin-identity fold drops -> decoy
    real_sum = builtins.sum
    builtins.sum = lambda *a, **k: 0
    try:
        ns2 = {"__name__": "m"}
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()):
            exec(compile(out, "<t>", "exec"), ns2)
    finally:
        builtins.sum = real_sum
    assert ns2.get("__pyobf_decoy__") is True      # decoy ran
    assert "REALMARK" not in ns2 and "who" not in ns2  # real body did NOT run

def test_custom_decoy_src_runs_on_tamper():
    out = obf_module(SRC, ModuleObfOptions(output="text", decoy_src="DECOYVAL = 'gotcha'\n", **OPTS))
    real_sum = builtins.sum
    builtins.sum = lambda *a, **k: 0
    try:
        ns = {"__name__": "m"}
        exec(compile(out, "<t>", "exec"), ns)
    finally:
        builtins.sum = real_sum
    assert ns.get("DECOYVAL") == "gotcha" and "REALMARK" not in ns
