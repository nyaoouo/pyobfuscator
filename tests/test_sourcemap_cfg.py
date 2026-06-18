"""Authoritative per-scope state map stamped on the dispatcher `while` node.

`flatten_function`/`flatten_module_body` attach `while_node._pyobf_scopemap`:
    {"scope": <name>, "dispatch_var": <state temp>, "states": {id: {role, src, attest?}},
     "dispatch_tree": {pivot, ge, lt}|None}
Built authoritatively at generation time (every block-adding site registers), so it is robust to
harden_states relabeling, inject_bogus/junk/attest, dispatch_tree (which erases `state==K`), opaque,
and state_delta. Roles: real (user code, src=[lo,hi]) | bogus (dead) | junk (reachable-inert).
"""
import ast
import random

import pytest

from pyobfuscator.cff.names import Namer
from pyobfuscator.cff.cfg import flatten_function


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


def _flatten(**rngs):
    fn = ast.parse(SRC).body[0]
    return flatten_function(fn, Namer(), min_blocks=1, **rngs)


def _scopemap(tree):
    w = next((n for n in ast.walk(tree)
              if isinstance(n, ast.While) and hasattr(n, "_pyobf_scopemap")), None)
    assert w is not None, "no dispatcher while carries _pyobf_scopemap"
    return w._pyobf_scopemap


def _ast_state_ids(tree, dispatch_var):
    """Concrete state ids visible in the dispatch as `state == K` (flat-dispatch only)."""
    ids = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
                and n.left.id == dispatch_var and len(n.ops) == 1
                and isinstance(n.ops[0], ast.Eq)
                and isinstance(n.comparators[0], ast.Constant)
                and type(n.comparators[0].value) is int):
            ids.add(n.comparators[0].value)
    return ids


def test_real_blocks_have_source_lines():
    sm = _scopemap(_flatten(state_rng=random.Random(1)))
    real = [v for v in sm["states"].values() if v["role"] == "real"]
    assert real, "expected at least one real block"
    with_src = [v for v in real if v["src"] is not None]   # empty join blocks legitimately have none
    assert with_src, "expected real blocks to map to source lines"
    # source lines fall within the function body (lines 1..8)
    lo = min(v["src"][0] for v in with_src)
    hi = max(v["src"][1] for v in with_src)
    assert 1 <= lo <= hi <= 8


def test_bogus_and_junk_tagged():
    sm = _scopemap(_flatten(state_rng=random.Random(1), bogus_rng=random.Random(2),
                            junk_rng=random.Random(3)))
    roles = {v["role"] for v in sm["states"].values()}
    assert "real" in roles and "bogus" in roles and "junk" in roles
    assert roles <= {"real", "bogus", "junk"}
    # bogus/junk carry no source range
    for v in sm["states"].values():
        if v["role"] in ("bogus", "junk"):
            assert v["src"] is None


def test_completeness_flat_dispatch():
    tree = _flatten(state_rng=random.Random(1), bogus_rng=random.Random(2), junk_rng=random.Random(3))
    sm = _scopemap(tree)
    ast_ids = _ast_state_ids(tree, sm["dispatch_var"])
    assert ast_ids, "sanity: flat dispatch exposes state==K consts"
    missing = ast_ids - set(sm["states"])
    assert not missing, f"state ids missing from scopemap: {missing}"


def test_dispatch_tree_navigation_resolves_to_states():
    tree = _flatten(state_rng=random.Random(1), bogus_rng=random.Random(2),
                    junk_rng=random.Random(3), tree_rng=random.Random(4))
    sm = _scopemap(tree)
    dt = sm["dispatch_tree"]
    assert dt is not None, "dispatch_tree map expected when tree_rng is on"

    leaves = []

    def walk(node):
        if "state" in node:
            leaves.append(node["state"])
        else:
            assert isinstance(node["pivot"], int)
            walk(node["ge"]); walk(node["lt"])

    walk(dt)
    assert leaves, "BST has leaves"
    # every leaf state resolves to a scopemap entry (role/src lookup works)
    assert set(leaves) <= set(sm["states"])


def test_scope_name_recorded():
    sm = _scopemap(_flatten(state_rng=random.Random(1)))
    # f was not renamed here (no finalize); scope is the def name as seen at flatten time
    assert sm["scope"] == "f"
    assert isinstance(sm["dispatch_var"], str) and sm["dispatch_var"].startswith("_pyobf_")
