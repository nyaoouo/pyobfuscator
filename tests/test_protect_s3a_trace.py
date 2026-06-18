import sys, os, io, contextlib
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

OPTS = dict(min_blocks=1, seed=7, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True, detect_trace=True, key_binds_env=True)
SRC = "RM = 555\ndef who():\n    return 'real'\n"

def _run(out):
    ns = {"__name__": "m"}
    with contextlib.redirect_stderr(io.StringIO()):
        exec(compile(out, "<t>", "exec"), ns)
    return ns

def test_untraced_real_traced_decoy():
    out = obf_module(SRC, ModuleObfOptions(output="text", **OPTS))
    # untraced -> real
    assert _run(out).get("RM") == 555
    # traced (exactly the _solve_capture.py attack: settrace installed before exec) -> decoy
    def tracer(frame, event, arg):
        return tracer
    sys.settrace(tracer)
    try:
        ns = {"__name__": "m"}
        with contextlib.redirect_stderr(io.StringIO()):
            exec(compile(out, "<t>", "exec"), ns)
    finally:
        sys.settrace(None)
    assert ns.get("__pyobf_decoy__") is True
    assert "RM" not in ns and "who" not in ns

def test_setprofile_also_triggers_decoy():
    out = obf_module(SRC, ModuleObfOptions(output="text", **OPTS))
    def prof(frame, event, arg):
        return None
    sys.setprofile(prof)
    try:
        ns = {"__name__": "m"}
        with contextlib.redirect_stderr(io.StringIO()):
            exec(compile(out, "<t>", "exec"), ns)
    finally:
        sys.setprofile(None)
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns
