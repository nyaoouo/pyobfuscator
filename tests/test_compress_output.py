"""compress_output — final distribution wrap: zlib + rolling-XOR + b85, optionally recursive, with a
no-op decoy head. Shrinks the file; payload runs identically. RULE #0: runs go through killable
subprocesses with a timeout.
"""
import random
import subprocess
import sys
import textwrap

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, OutputFormat
from pyobfuscator.protect.outerpack import outer_compress, outer_compress_text, decoy_head
from pyobfuscator.cff.emit import _to_pyc

SRC = textwrap.dedent('''
    def f(n):
        return sum(i * i for i in range(n))
    print(f(20))
''')

PACK = dict(pack_body=True, key_from_cff=True)


def _ref_stdout():
    return subprocess.run([sys.executable, "-c", SRC], capture_output=True, text=True, timeout=30).stdout


def _run_text(code, tmp_path, name="c.py"):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=120)


# ---- unit: the outer wrap is a correct, deterministic, no-giant-line round trip ----

def test_outerpack_roundtrip_and_determinism():
    launcher = "X = 1 + 2\nY = X * 10\n"
    w = outer_compress(launcher, _to_pyc, rounds=2, decoy=True, rng=random.Random(1))
    ns = {}
    exec(compile(w, "<t>", "exec"), ns)
    assert ns["X"] == 3 and ns["Y"] == 30
    w2 = outer_compress(launcher, _to_pyc, rounds=2, decoy=True, rng=random.Random(1))
    assert w == w2, "same rng/seed -> byte-identical"
    assert max(len(l) for l in w.splitlines()) < 8000, "no giant line"
    assert "_pyx_c := _pyx_b ^ _pyx_c ^ _pyx_k" in w, "rolling-XOR decode present"


def test_decoy_head_is_noop():
    ns = {"already": 1}
    exec(decoy_head(137), ns)           # decompresses to empty -> exec(compile(b'')) -> no-op
    assert ns["already"] == 1


def test_decoy_and_real_layer_look_identical():
    """The decoy head and a real compression round share ONE template (_layer_src), so they are
    byte-shape-identical: both use inline __import__, _pyx_k/_pyx_c, and compile+exec; neither uses the
    `import zlib, base64` statement. Only the carried blob differs (the decoy's is empty)."""
    real = outer_compress_text("X = 1\n", 137)
    decoy = decoy_head(137)
    for marker in ("_pyx_k = ", "_pyx_c = 0", "_pyx_c := _pyx_b ^ _pyx_c ^ _pyx_k",
                   "__import__('zlib').decompress", "__import__('base64').b85decode", "compile(", "'exec'"):
        assert marker in real and marker in decoy, marker
    assert "import zlib, base64" not in real and "import zlib, base64" not in decoy
    assert real.splitlines()[0].startswith("_pyx_k = ") and decoy.splitlines()[0].startswith("_pyx_k = ")


# ---- integration: compressed launcher runs identically + is smaller ----

def test_text_compress_runs_and_smaller(tmp_path):
    plain = obf_module(SRC, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, **PACK))
    comp = obf_module(SRC, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, compress_output=True, **PACK))
    assert len(comp.encode()) < len(plain.encode()), f"{len(comp)} !< {len(plain)}"
    r = _run_text(comp, tmp_path)
    assert r.returncode == 0, r.stderr
    assert r.stdout == _ref_stdout()


def test_recursive_rounds_run(tmp_path):
    comp = obf_module(SRC, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, compress_output=True,
                                            compress_rounds=3, **PACK))
    r = _run_text(comp, tmp_path, "c3.py")
    assert r.returncode == 0, r.stderr
    assert r.stdout == _ref_stdout()


def test_pyc_compress_runs(tmp_path):
    comp = obf_module(SRC, ModuleObfOptions(output=OutputFormat.PYC, seed=5, compress_output=True, **PACK))
    p = tmp_path / "c.pyc"
    p.write_bytes(comp)
    r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert r.stdout == _ref_stdout()


def test_off_is_plain_launcher():
    a = obf_module(SRC, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, **PACK))
    assert "_pyx_k" not in a, "compress_output off -> no outer wrapper"


def test_deterministic_across_builds():
    o = dict(output=OutputFormat.TEXT, seed=9, compress_output=True, compress_rounds=2, **PACK)
    assert obf_module(SRC, ModuleObfOptions(**o)) == obf_module(SRC, ModuleObfOptions(**o))


def _detect_stack_build(rounds):
    src = "print('REAL-OK')\n"
    return obf_module(src, ModuleObfOptions(output=OutputFormat.TEXT, seed=5, pack_body=True,
                                            key_from_cff=True, key_binds_env=True, detect_stack=True,
                                            compress_output=True, compress_rounds=rounds))


def test_detect_stack_adapts_to_wrapper_frames(tmp_path):
    # detect_stack folds into the key: genuine `python file.py` must accept (frame-depth = rounds+1),
    # a foreign `exec(open(file).read())` adds another frame -> detected -> wrong key -> not REAL.
    for rounds in (1, 2):
        out = _detect_stack_build(rounds)
        g = tmp_path / ("g%d.py" % rounds)
        g.write_text(out, encoding="utf-8")
        genuine = subprocess.run([sys.executable, str(g)], capture_output=True, text=True, timeout=120)
        assert genuine.returncode == 0 and "REAL-OK" in genuine.stdout, (
            rounds, genuine.stdout, genuine.stderr)
        h = tmp_path / ("h%d.py" % rounds)
        h.write_text("exec(open(%r).read())\n" % str(g), encoding="utf-8")
        foreign = subprocess.run([sys.executable, str(h)], capture_output=True, text=True, timeout=120)
        assert "REAL-OK" not in foreign.stdout, ("foreign exec leaked real flag", rounds, foreign.stdout)


def test_detect_stack_shallow_stack_triggers_without_crash():
    # The compress-aware detect_stack uses a DUAL-depth probe: frame[rounds+1] is None AND
    # frame[rounds] is not None (chain EXACTLY `rounds` deep). It walks via getattr-default, so a
    # SHALLOW stack never hits `None.f_back` -> AttributeError (crash + traceback leak). A shallow
    # stack means the launcher was peeled out of its compress wrappers and run with fewer than
    # `rounds` frames above it (a peel-and-exec attack), so it must read as TRIGGERED (>0), NOT
    # clean: the `frame[rounds] is None` term fires. Previously a single fixed-depth point-probe
    # read this clean, which a shallow exec bypassed to reach the real body.
    import ast as _ast
    from pyobfuscator.protect.detectors import StackDetector, _Ctx
    ctx = _Ctx(None)
    ctx.sys = "sys"
    ctx.compress_output = True
    ctx.compress_rounds = 5            # depth 6, far deeper than a top-level (shallow) stack
    term = _ast.unparse(StackDetector().term(ctx))
    r = subprocess.run([sys.executable, "-c", "import sys\nprint(%s)" % term],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, "shallow stack must not crash; got:\n" + r.stderr
    assert r.stdout.strip() == "1", "shallow (peeled launcher) must read TRIGGERED, got: " + r.stdout
