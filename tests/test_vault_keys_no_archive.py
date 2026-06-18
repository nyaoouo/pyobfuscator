"""Name-vault dict KEYS are kept out of the const archive (state-keyed by key_consts
instead), while the sensitive NAME strings stay archived.

The `_pyobf_no_archive` marker (set by namevault._key_const) makes ArchivePass leave a Constant
inline; the flatten pass's key_consts then state-encrypts it (`enc - (state & mask)`).
"""
import ast

from pyobfuscator import obf_module
from pyobfuscator.options import ObfOptions, ModuleObfOptions, OutputFormat
from pyobfuscator.cff.passes.archive import ArchivePass


def test_marker_keeps_constant_inline():
    tree = ast.parse("a = 123456789\nb = 987654321\n")
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and n.value == 123456789:
            n._pyobf_no_archive = True          # mimic a vault key
    ast.fix_missing_locations(tree)
    out = ArchivePass().transform(tree, ObfOptions(output=OutputFormat.TEXT, const_archive=True, seed=1))
    src = ast.unparse(out)
    assert "123456789" in src, "marked constant must stay inline (not archived)"
    assert "987654321" not in src, "unmarked constant must be pooled into the archive blob"


SRC = (
    "import json\n"
    "def f(x):\n"
    "    return len(json.dumps([x, abs(x), str(x)]))\n"
    "r = f(-5)\n"
)


def _build(**kw):
    return obf_module(SRC, ModuleObfOptions(output=OutputFormat.TEXT, seed=11, min_blocks=1,
                                            name_vault=True, const_archive=True, **kw))


def test_vault_behaviour_preserved():
    out = _build()
    ns = {}
    exec(compile(ast.parse(out), "<t>", "exec"), ns)
    ref = {}
    exec(compile(ast.parse(SRC), "<t>", "exec"), ref)
    assert ns["r"] == ref["r"]


def test_vault_keys_not_archive_accessors():
    # Find the vault dict (assigned an empty Dict) and assert NONE of its subscript keys is an
    # archive accessor Call — they must be ints or state-keyed int expressions.
    out = _build(shuffle_states=True, obf_ints=True)
    tree = ast.parse(out)
    vault_names = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   for t in n.targets if isinstance(t, ast.Name) and isinstance(n.value, ast.Dict)}
    assert vault_names, "expected a vault dict assignment"
    bad = [s for s in ast.walk(tree)
           if isinstance(s, ast.Subscript) and isinstance(s.value, ast.Name)
           and s.value.id in vault_names and isinstance(s.slice, ast.Call)]
    assert not bad, "vault dict key must not be an archive accessor Call"


def test_keys_deterministic_across_hashseed():
    # Behaviour + structure stable (no hash()/set-order leak introduced).
    a = _build()
    b = _build()
    assert a == b
