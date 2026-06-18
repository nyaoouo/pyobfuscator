"""Body payload + body map emitted by the packer.

With pack_body on, the body is finalized + serialized inside pack_module; emit_sourcemap surfaces the
readable body payload (`body_src`) and the body-layer map into the sink. The map is a pure side
channel: the launcher stays byte-identical, and still decrypts+runs == the original.
RULE #0: any launcher run goes through a KILLABLE subprocess with a timeout.
"""
import ast
import re
import subprocess
import sys
import textwrap

from pyobfuscator import obf_module
from pyobfuscator.options import ModuleObfOptions, OutputFormat

SRC = textwrap.dedent('''
    def fib(n):
        a, b = 0, 1
        for _ in range(n):
            a, b = b, a + b
        return a

    def main():
        print(sum(fib(i) for i in range(10)))

    if __name__ == "__main__":
        main()
''')

PACK = dict(output=OutputFormat.TEXT, seed=7, pack_body=True, key_from_cff=True)
_HEX = re.compile(r"(?<![\w])_pyobf_[0-9a-f]+(?![\w])")


def _run(code, tmp_path, name):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=90)


def test_map_is_pure_side_channel():
    base = obf_module(SRC, ModuleObfOptions(**PACK))
    sink: dict = {}
    out = obf_module(SRC, ModuleObfOptions(**PACK, emit_sourcemap=True), sourcemap_out=sink)
    assert base == out, "sourcemap must not change the launcher bytes"


def test_sink_has_body_and_launcher():
    sink: dict = {}
    obf_module(SRC, ModuleObfOptions(**PACK, emit_sourcemap=True), sourcemap_out=sink)
    assert {"body", "body_src", "launcher"} <= set(sink)
    assert sink["body"]["layer"] == "body"
    assert sink["launcher"]["layer"] == "launcher"


def test_body_payload_parses_and_maps():
    sink: dict = {}
    obf_module(SRC, ModuleObfOptions(**PACK, emit_sourcemap=True), sourcemap_out=sink)
    ast.parse(sink["body_src"])                          # the payload is valid Python
    used = set(_HEX.findall(sink["body_src"]))
    assert used, "obfuscated body has generated names"
    assert used <= set(sink["body"]["names"]), "every body hex name is mapped"


def test_body_and_launcher_namespaces_disjoint():
    # The body and launcher are finalized with DISJOINT salts; their hex name sets must not overlap
    # (a shared module-level name would let the body overwrite a launcher dispatcher var).
    sink: dict = {}
    obf_module(SRC, ModuleObfOptions(**PACK, emit_sourcemap=True), sourcemap_out=sink)
    body_names = set(sink["body"]["names"])
    launcher_names = set(sink["launcher"]["names"])
    assert body_names and launcher_names
    assert body_names.isdisjoint(launcher_names)


def test_launcher_runs_equivalent(tmp_path):
    sink: dict = {}
    out = obf_module(SRC, ModuleObfOptions(**PACK, emit_sourcemap=True), sourcemap_out=sink)
    orig = _run(SRC, tmp_path, "orig.py")
    obf = _run(out, tmp_path, "obf.py")
    assert orig.returncode == 0, orig.stderr
    assert obf.returncode == 0, obf.stderr
    assert orig.stdout == obf.stdout and orig.stdout.strip() != ""
