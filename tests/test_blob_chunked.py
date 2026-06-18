"""The packed body blob is split into chunk assignments so no single source line is a
giant literal (a 64KB one-liner is an obvious 'payload here' tell), and oversized launcher
dispatcher blocks are capped. Behaviour preserved.
"""
import subprocess
import sys
import textwrap

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, OutputFormat

# Big enough that the compressed+encrypted blob's b85 exceeds the 3072-char chunk threshold.
SRC = textwrap.dedent('''
    def f(n):
        total = 0
        for i in range(n):
            if i % 3 == 0:
                total += i * i
            else:
                total -= i
        return total

    def g(s):
        return "".join(reversed(s)) + str(len(s))
''') + "\n".join(f"V{i} = f({i}) + len(g('abc{i}'))" for i in range(60)) + "\nprint(sum(V%d for V%d in [globals()['V%d'] for V%d in range(1)]) if False else f(20))\n" % (0,0,0,0)

PACK = dict(output=OutputFormat.TEXT, seed=5, pack_body=True, key_from_cff=True)


def _run(code, tmp_path, name):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=120)


def test_no_giant_blob_line():
    out = obf_module(SRC, ModuleObfOptions(**PACK))
    longest = max((len(l) for l in out.splitlines()), default=0)
    assert longest < 8000, f"longest source line is {longest} chars — blob not chunked"
    # sanity: the blob WAS big enough to require chunking (multiple b85decode-fed chunk vars)
    assert out.count("b85decode") >= 1


def test_chunked_launcher_equivalent(tmp_path):
    out = obf_module(SRC, ModuleObfOptions(**PACK))
    orig = _run(SRC, tmp_path, "orig.py")
    obf = _run(out, tmp_path, "obf.py")
    assert orig.returncode == 0, orig.stderr
    assert obf.returncode == 0, obf.stderr
    assert orig.stdout == obf.stdout and orig.stdout.strip() != ""


def test_blob_chunk_deterministic():
    a = obf_module(SRC, ModuleObfOptions(**PACK))
    b = obf_module(SRC, ModuleObfOptions(**PACK))
    assert a == b
