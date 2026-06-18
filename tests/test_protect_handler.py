"""User honeypot handler (build-input `handler_src`): reads M.<signal> detection vars, may set
M.POISON; POISON folds into the key selector -> decoy. The handler is the extensible policy layer
(custom logic; future FP-prone detectors route here instead of the key fold)."""
import sys, os, io, contextlib, types
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from pyobfuscator import obf_module, ModuleObfOptions

BASE = dict(min_blocks=1, seed=4, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True)
SRC = "RM = 321\ndef who():\n    return 'real'\n"


def _run(out):
    ns = {"__name__": "m"}
    with contextlib.redirect_stderr(io.StringIO()):
        exec(compile(out, "<t>", "exec"), ns)
    return ns


def test_handler_unconditional_poison_decoys():
    # handler always poisons -> decoy even on an otherwise-clean (untraced) run
    out = obf_module(SRC, ModuleObfOptions(output="text", handler_src="M.POISON = 1", **BASE))
    ns = _run(out)
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns


def test_handler_no_poison_runs_real():
    out = obf_module(SRC, ModuleObfOptions(output="text", handler_src="M.POISON = 0", **BASE))
    assert _run(out).get("RM") == 321 and "__pyobf_decoy__" not in _run(out)


def test_handler_strips_magic_import_and_reads_signal():
    # handler may `import` the magic namespace (stripped at build) and read a detection signal
    h = "from pyobfuscator.protect import magic as M\nif M.TOOLS:\n    M.POISON = 1\n"
    opts = lambda: ModuleObfOptions(output="text", handler_src=h, detect_tools=True,
                                    key_binds_env=True, **BASE)
    assert _run(obf_module(SRC, opts())).get("RM") == 321          # clean -> real
    out = obf_module(SRC, opts())
    sys.modules["pydevd"] = types.ModuleType("pydevd")             # debugger present -> M.TOOLS>0
    try:
        ns = _run(out)
    finally:
        del sys.modules["pydevd"]
    assert ns.get("__pyobf_decoy__") is True


def test_handler_unknown_magic_raises():
    with pytest.raises(ValueError):
        obf_module(SRC, ModuleObfOptions(output="text", handler_src="M.POISON = M.NOPE", **BASE))


def test_handler_custom_and_logic():
    # custom AND logic the fixed key-fold can't express on its own
    h = "M.POISON = 1 if (M.TRACE and M.TOOLS) else 0"
    opts = ModuleObfOptions(output="text", handler_src=h, detect_trace=True, detect_tools=True,
                            key_binds_env=True, seed=4, min_blocks=1, pack_body=True,
                            key_from_cff=True, integrity_selfcheck=True, pack_decoy=True)
    # NOTE: detect_trace/detect_tools are key_safe -> they ALSO fold into D; this test only
    # asserts the handler inlines + builds + runs real when clean.
    assert _run(obf_module(SRC, opts)).get("RM") == 321
