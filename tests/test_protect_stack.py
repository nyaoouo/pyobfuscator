"""detect_stack is entry-only: it MUST be tested with a real subprocess, because an in-process
`exec(code, ...)` harness is exactly the foreign-caller case it flags (so it would always 'decoy'
in-process). Genuine `python file.py` -> real; foreign exec (even faking __main__) -> decoy."""
import sys, os, io, contextlib, subprocess
sys.path.insert(0, os.path.dirname(__file__))
from pyobfuscator import obf_module, ModuleObfOptions

OPTS = dict(min_blocks=1, seed=4, pack_body=True, key_from_cff=True,
            integrity_selfcheck=True, pack_decoy=True, key_binds_env=True, detect_stack=True)
SRC = ("RM = 321\n"
       "def who():\n    return 'real'\n"
       "if __name__ == '__main__':\n    print('REAL', RM)\n")


def test_detect_stack_genuine_entry_subprocess_real(tmp_path):
    out = obf_module(SRC, ModuleObfOptions(output="text", **OPTS))
    p = tmp_path / "entry.py"
    p.write_text(out, encoding="utf-8")
    r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True)
    # genuine `python entry.py`: module frame has no Python caller -> real body runs
    assert "REAL 321" in r.stdout, (r.returncode, r.stdout, r.stderr)


def test_detect_stack_foreign_exec_decoy_even_faking_main():
    out = obf_module(SRC, ModuleObfOptions(output="text", **OPTS))
    ns = {"__name__": "__main__"}   # the _solve_capture.py shape: exec with a faked __main__
    with contextlib.redirect_stderr(io.StringIO()):
        exec(compile(out, "<t>", "exec"), ns)
    assert ns.get("__pyobf_decoy__") is True and "RM" not in ns


def test_detect_stack_registered_and_entry_only():
    from pyobfuscator.protect import DETECTORS
    d = next(d for d in DETECTORS if d.flag == "detect_stack")
    assert d.entry_only is True
