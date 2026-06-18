import sys, os, io, contextlib, types
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

# base: packed + cff key + decoy + key_binds_env (so detectors fold into the selector)
BASE = dict(min_blocks=1, seed=4, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True, key_binds_env=True)
SRC = "RM = 321\ndef who():\n    return 'real'\n"


def _run(out):
    ns = {"__name__": "m"}
    with contextlib.redirect_stderr(io.StringIO()):
        exec(compile(out, "<t>", "exec"), ns)
    return ns


def test_detectors_registered():
    from pyobfuscator.protect import DETECTORS
    flags = {d.flag for d in DETECTORS}
    assert {"detect_trace", "detect_tools", "detect_env"} <= flags


def test_detect_tools_clean_real_then_injected_decoy():
    out = obf_module(SRC, ModuleObfOptions(output="text", detect_tools=True, **BASE))
    assert _run(out).get("RM") == 321                       # clean process -> real
    sys.modules["pydevd"] = types.ModuleType("pydevd")      # simulate a debugger present
    try:
        ns = _run(out)
    finally:
        del sys.modules["pydevd"]
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns


def test_detect_env_clean_real_then_breakpointhook_decoy():
    out = obf_module(SRC, ModuleObfOptions(output="text", detect_env=True, **BASE))
    assert _run(out).get("RM") == 321                       # clean -> real
    saved = sys.breakpointhook
    sys.breakpointhook = lambda *a, **k: None               # a debugger replaces this
    try:
        ns = _run(out)
    finally:
        sys.breakpointhook = saved
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns


def test_protect_level_full_arms_anti_trace():
    out = obf_module(SRC, ModuleObfOptions(output="text", seed=4, min_blocks=1, protect_level="full"))
    assert _run(out).get("RM") == 321                       # untraced -> real
    def tr(f, e, a):
        return tr
    sys.settrace(tr)
    try:
        ns = _run(out)
    finally:
        sys.settrace(None)
    assert ns.get("__pyobf_decoy__") is True                # full arms anti-trace -> decoy


def test_protect_level_light_is_debuggable():
    out = obf_module(SRC, ModuleObfOptions(output="text", seed=4, min_blocks=1, protect_level="light"))
    assert _run(out).get("RM") == 321                       # packed real, untraced
    def tr(f, e, a):
        return tr
    sys.settrace(tr)
    try:
        ns = _run(out)
    finally:
        sys.settrace(None)
    # light does NOT arm key_binds_env -> traced still runs the real body
    assert ns.get("RM") == 321 and "__pyobf_decoy__" not in ns


def test_protect_level_off_runs_real_unpacked():
    out = obf_module(SRC, ModuleObfOptions(output="text", seed=4, min_blocks=1, protect_level="off"))
    assert _run(out).get("RM") == 321                       # off = no packing -> plain obfuscation


def test_invalid_protect_level_raises():
    import pytest
    with pytest.raises(ValueError):
        ModuleObfOptions(protect_level="bogus")
