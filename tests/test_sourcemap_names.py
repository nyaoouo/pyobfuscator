"""Name provenance capture in cff/names.py.

`Namer.fresh(hint, *, orig, scope, kind)` records the role (hint) and any known original
identifier OUT OF BAND in `_GEN_META` (never embedded in the emitted name), so the sourcemap
assembler can join finalize_names' temp->hex `out_map` with temp->meta to produce hex->meta.
"""
import ast

from pyobfuscator.cff.names import Namer, name_meta
from pyobfuscator.cff.rename import finalize_names


def test_fresh_records_role_from_hint():
    t = Namer().fresh("state")
    m = name_meta(t)
    assert m is not None
    assert m["role"] == "state"
    assert m["orig"] is None and m["scope"] is None and m["kind"] == "var"


def test_fresh_records_optional_fields():
    t = Namer().fresh("local", orig="each_size", scope="test_key", kind="var")
    assert name_meta(t) == {"role": "local", "orig": "each_size", "scope": "test_key", "kind": "var"}


def test_default_hint_recorded():
    assert name_meta(Namer().fresh())["role"] == "v"


def test_fresh_uniqueness_preserved():
    n = Namer()
    names = {n.fresh("x") for _ in range(200)}
    assert len(names) == 200


def test_hint_not_embedded_in_name():
    # The role must NOT leak into the emitted identifier.
    t = Namer().fresh("push")
    assert "push" not in t
    assert t.startswith("_pyobf_g")


def test_finalize_out_map_joins_to_meta():
    t = Namer().fresh("get", kind="func")
    tree = ast.parse(f"def {t}(x):\n    return x\n")
    om: dict = {}
    finalize_names(tree, seed=7, out_map=om)
    assert t in om                       # temp -> hex recorded by finalize
    hexname = om[t]
    meta = name_meta(t)                  # temp -> provenance recorded by fresh
    assert meta["role"] == "get" and meta["kind"] == "func"
    assert hexname in ast.unparse(tree)  # the hex actually replaced the temp
