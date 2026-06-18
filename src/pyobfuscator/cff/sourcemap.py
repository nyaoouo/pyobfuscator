"""Sourcemap assembler — turn an obfuscated AST (post finalize_names) plus its temp->hex `out_map`
into a JSON deobfuscation map: obf-name -> {orig, role, scope, kind}; per dispatcher scope the
state-value -> {role, src, attest}; the dispatch BST (when dispatch_tree ran); and a dead-state list.

The map is a COMPLETE deobfuscation key — opt-in only, written to a SEPARATE file, never embedded
in the artifact (see options.emit_sourcemap, the `_warning` header, and the build wiring).

Inputs come from two side channels populated during obfuscation:
  - cff.names._GEN_META: temp-name -> {role(hint), orig, scope, kind}, recorded at fresh() time.
  - cfg._render et al.: `while_node._pyobf_scopemap` = {scope, dispatch_var, states, dispatch_tree}.
The temp->hex join uses the `out_map` returned by cff.rename.finalize_names for THAT tree.
"""
from __future__ import annotations

import ast
import json

from .names import name_meta

FORMAT = "pyobfuscator-sourcemap/1"
_WARNING = "DEOBFUSCATION KEY — do not distribute with the obfuscated artifact."


def _xlate(name, out_map):
    """A stored temp name -> its final hex (if finalize renamed it), else the name unchanged
    (user/builtin names and '<module>' pass through)."""
    return out_map.get(name, name)


def build_sourcemap(tree, out_map, *, layer, seed, source, artifact) -> dict:
    """Assemble the sourcemap dict for one finalized tree.

    layer: "launcher" | "body". out_map: temp->hex from finalize_names(tree, seed, out_map=...).
    Every hex in `out_map` appears in `tree` (finalize renames in place), so `names` covers every
    generated identifier in the output by construction (completeness)."""
    # names: temp -> hex joined with temp -> provenance
    names: dict = {}
    for temp, hexn in out_map.items():
        m = name_meta(temp) or {}
        names[hexn] = {
            "orig": m.get("orig"),
            "role": m.get("role", "?"),
            "scope": _xlate(m["scope"], out_map) if m.get("scope") else m.get("scope"),
            "kind": m.get("kind", "var"),
        }

    scopes: dict = {}
    dead: dict = {}
    role_counts: dict = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.While) and hasattr(node, "_pyobf_scopemap")):
            continue
        sm = node._pyobf_scopemap
        skey = _xlate(sm["scope"], out_map)
        states: dict = {}
        deadlist: list = []
        for sid, info in sorted(sm["states"].items()):
            role = info.get("role", "real")
            states[str(sid)] = {"role": role, "src": info.get("src"),
                                "attest": bool(info.get("attest", False))}
            role_counts[role] = role_counts.get(role, 0) + 1
            if role in ("bogus", "junk"):
                deadlist.append(sid)
        entry = {"dispatch_var": _xlate(sm["dispatch_var"], out_map), "states": states}
        if sm.get("dispatch_tree") is not None:
            entry["dispatch_tree"] = sm["dispatch_tree"]   # pure ints/dicts (pivot/ge/lt/state)
        scopes[skey] = entry
        if deadlist:
            dead[skey] = sorted(deadlist)

    return {
        "format": FORMAT,
        "_warning": _WARNING,
        "artifact": artifact,
        "layer": layer,
        "seed": seed,
        "source": source,
        "names": names,
        "scopes": scopes,
        "dead_states": dead,
        "stats": {"names": len(names), "states": role_counts},
    }


def dump_sourcemap(d: dict, path) -> None:
    """Write the map as UTF-8 JSON (indent=2). `_warning` sits near the top of the object."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
        f.write("\n")
