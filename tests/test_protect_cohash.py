"""co_code self-hash integrity (B): a non-flattened guard fn whose co_code is FNV-hashed into the
selector. The critical gate is `untraced -> real`: it proves the build-side hash equals the runtime
hash (guard co_code stable across the standalone build compile and the emitted launcher). Patching
the guard's *bytecode* (an operator, not just a constant) -> different co_code -> decoy."""
import sys, os, io, contextlib, marshal
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

BASE = dict(min_blocks=1, seed=4, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True, cohash_integrity=True)
SRC = "RM = 321\ndef who():\n    return 'real'\n"
GUARD_MUL = 2685821657736338717  # 0x2545F4914F6CDD1D, the guard multiplier


def _run_text(out):
    ns = {"__name__": "m"}
    with contextlib.redirect_stderr(io.StringIO()):
        exec(compile(out, "<t>", "exec"), ns)
    return ns


def test_cohash_untraced_real_text_and_pyc():
    t = obf_module(SRC, ModuleObfOptions(output="text", **BASE))
    assert _run_text(t).get("RM") == 321 and "__pyobf_decoy__" not in _run_text(t)
    p = obf_module(SRC, ModuleObfOptions(output="pyc", **BASE))
    ns = {"__name__": "m"}
    with contextlib.redirect_stderr(io.StringIO()):
        exec(marshal.loads(p[16:]), ns)
    assert ns.get("RM") == 321 and "__pyobf_decoy__" not in ns


def test_cohash_guard_bytecode_tamper_decoys():
    out = obf_module(SRC, ModuleObfOptions(output="text", **BASE))
    assert ("* %d" % GUARD_MUL) in out, "guard not located in output (template changed?)"
    tampered = out.replace("* %d" % GUARD_MUL, "+ %d" % GUARD_MUL, 1)  # mul->add changes co_code
    ns = _run_text(tampered)
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns


def test_cohash_full_stack_untraced_real():
    opts = dict(BASE)
    opts.update(obf_strings=True, obf_ints=True, shuffle_states=True, opaque_predicates=True,
                bogus_blocks=True, slot_vars=True, stack_calls=True, hide_external_args=True,
                split_calls=True, return_var=True, dedup=True, state_delta=True, dispatch_tree=True,
                junk_code=True, dict_indirect=True, detect_trace=True, key_binds_env=True,
                obf_imports=True)
    assert _run_text(obf_module(SRC, ModuleObfOptions(output="text", **opts))).get("RM") == 321
