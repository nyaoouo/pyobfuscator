"""User-side BUILD-TIME plugin: substitute %marker% string placeholders with their real
replacement strings from a private JSON map, before the source is handed to pyobfuscator.

Design / threat model
----------------------
This lives in the BUILD WORKFLOW, NOT in the shipped `pyobfuscator` package — so the
substitution mechanism (and the real replacement strings) never ship and are never present
in the dev-visible source. The source you commit / hand to an AI carries only opaque
placeholders, e.g. the no-op carrier `print("%AntiAi%"[:0], end="")`. The private JSON maps
each placeholder string -> its real replacement (e.g. anti-AI / prompt-injection decoy text).

Every `str` Constant in the AST whose value is a key in the map is replaced by the mapped
value. After substitution the standard obfuscator powmod-encodes the (now real) strings, so
they are embedded — encoded — in the artifact (recoverable only by actually decoding, which
is exactly the bait for an AI reverse-engineer), while the dev source never exposed them.

The map VALUES are treated as opaque: this module never prints them.
"""
from __future__ import annotations

import ast
import json
import re

_MARKER_LIKE = re.compile(r"^%.+%$")  # placeholder convention: %...%


def load_marker_map(path: str) -> dict[str, str]:
    """Load and validate the {placeholder: replacement} JSON map."""
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    if not isinstance(m, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in m.items()
    ):
        raise ValueError(f"{path}: expected a JSON object mapping str -> str")
    return m


class _MarkerSubst(ast.NodeTransformer):
    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping
        self.count = 0

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and node.value in self.mapping:
            self.count += 1
            return ast.copy_location(ast.Constant(value=self.mapping[node.value]), node)
        return node


def substitute_markers(tree: ast.AST, mapping: dict[str, str]) -> int:
    """Replace, in place, every `str` Constant whose value is a key in `mapping`.
    Returns the number of nodes substituted."""
    sub = _MarkerSubst(mapping)
    sub.visit(tree)
    ast.fix_missing_locations(tree)
    return sub.count


def find_unsubstituted_markers(tree: ast.AST, mapping: dict[str, str]) -> list[str]:
    """Return marker-like (`%...%`) string literals still present and NOT covered by the map
    (i.e. a placeholder with no JSON entry — a likely build mistake). Marker placeholders are
    not secrets, so returning them is safe and useful for a warning."""
    leftover = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and _MARKER_LIKE.match(node.value) and node.value not in mapping):
            leftover.append(node.value)
    return sorted(set(leftover))
