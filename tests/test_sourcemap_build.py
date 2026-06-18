"""Sourcemap assembler (cff/sourcemap.py).

Drives a flattened function through finalize_names (capturing out_map) and asserts the assembled
map: schema shape, name completeness (every _pyobf_<hex> in the output is mapped), per-scope states
with dead-state list, dispatch BST navigation, and JSON round-trip.
"""
import ast
import json
import random
import re

from pyobfuscator.cff.names import Namer
from pyobfuscator.cff.cfg import flatten_function
from pyobfuscator.cff.rename import finalize_names
from pyobfuscator.cff.sourcemap import build_sourcemap, dump_sourcemap

SRC = (
    "def f(x):\n"
    "    y = 0\n"
    "    if x > 1:\n"
    "        y = x * 2\n"
    "    else:\n"
    "        y = -x\n"
    "    z = y + 1\n"
    "    return z\n"
)

# whole-identifier _pyobf_<hex>, excluding double-underscore attest names and temp _pyobf_g<n>
_HEX = re.compile(r"(?<![\w])_pyobf_[0-9a-f]+(?![\w])")


def _build(seed=9, tree=True):
    fn = ast.parse(SRC).body[0]
    flatten_function(fn, Namer(), min_blocks=1, state_rng=random.Random(1),
                     bogus_rng=random.Random(2), junk_rng=random.Random(3),
                     tree_rng=random.Random(4) if tree else None)
    mod = ast.Module(body=[fn], type_ignores=[])
    ast.fix_missing_locations(mod)
    om: dict = {}
    finalize_names(mod, seed=seed, out_map=om)
    smap = build_sourcemap(mod, om, layer="body", seed=seed, source="x.py", artifact="x_obf.py")
    return smap, mod, om


def test_schema_shape():
    smap, _, _ = _build()
    for k in ("format", "_warning", "artifact", "layer", "seed", "source",
              "names", "scopes", "dead_states", "stats"):
        assert k in smap, f"missing key {k}"
    assert smap["format"] == "pyobfuscator-sourcemap/1"
    assert smap["layer"] == "body"
    assert "DEOBFUSCATION KEY" in smap["_warning"]


def test_name_completeness():
    smap, mod, _ = _build()
    out_src = ast.unparse(mod)
    used = set(_HEX.findall(out_src))
    assert used, "sanity: output has _pyobf_<hex> names"
    missing = used - set(smap["names"])
    assert not missing, f"hex names absent from map: {missing}"


def test_states_and_dead():
    smap, _, _ = _build()
    assert smap["scopes"], "at least one flattened scope"
    (scope_key, scope), = smap["scopes"].items()
    assert scope["states"]
    roles = {v["role"] for v in scope["states"].values()}
    assert "real" in roles and "bogus" in roles and "junk" in roles
    dead = set(smap["dead_states"].get(scope_key, []))
    # dead_states == exactly the bogus+junk states
    bogus_junk = {int(sid) for sid, v in scope["states"].items() if v["role"] in ("bogus", "junk")}
    assert dead == bogus_junk and dead


def test_dispatch_tree_leaves_resolve():
    smap, _, _ = _build(tree=True)
    (_, scope), = smap["scopes"].items()
    dt = scope["dispatch_tree"]
    assert dt is not None
    leaves = []

    def walk(n):
        if "state" in n:
            leaves.append(n["state"])
        else:
            walk(n["ge"]); walk(n["lt"])

    walk(dt)
    # every BST leaf state has a states entry (string-keyed)
    assert leaves and all(str(s) in scope["states"] for s in leaves)


def test_no_dispatch_tree_when_off():
    smap, _, _ = _build(tree=False)
    (_, scope), = smap["scopes"].items()
    assert "dispatch_tree" not in scope  # only present when dispatch_tree ran


def test_json_roundtrip(tmp_path):
    smap, _, _ = _build()
    p = tmp_path / "x_obf.map.json"
    dump_sourcemap(smap, p)
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert loaded["format"] == "pyobfuscator-sourcemap/1"
    assert loaded["names"] == smap["names"]


def test_stats_counts_match():
    smap, _, _ = _build()
    assert smap["stats"]["names"] == len(smap["names"])
    total_states = sum(len(s["states"]) for s in smap["scopes"].values())
    assert sum(smap["stats"]["states"].values()) == total_states
