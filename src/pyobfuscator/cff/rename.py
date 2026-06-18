"""Final pass: rename the monotonic temp names (_pyobf_g<n>, from Namer.fresh) to uniform
random _pyobf_<hex> names. Runs LAST, once per emitted tree. Determinism: temp names are collected
in ast.walk first-appearance order and assigned seeded-random finals — so two builds of the same
input+seed produce byte-identical output regardless of the global counter's absolute values.

Only names in `_GEN_ISSUED` (handed out by Namer.fresh) are touched. Attest names
(`__pyobf_oracle_*__`, `__pyobf_corr_*__`, `__pyobf_o_*__`, `__pyobf_c`) are double-underscore and
NOT in `_GEN_ISSUED`, so the body<->launcher oracle-name agreement is never disturbed. An imported
module's real name (`alias.name`) is never rewritten — only a temp `asname`.
"""
from __future__ import annotations
import ast
import random
from .names import _GEN_ISSUED, collect_names


def finalize_names(tree: ast.AST, seed, out_map: dict | None = None, ns_salt: int = 0) -> ast.AST:
    # Returns `tree` (mutated in place). If `out_map` is given, it is populated with the
    # temp-name -> final-name mapping (used by the visualizer to translate the dispatcher's state
    # var name into its renamed form). Returning the tree keeps the common call form
    # `tree = finalize_names(tree, seed)` working.
    # `ns_salt` (default 0) shifts the seeded RNG stream into a disjoint namespace: two trees that
    # share runtime globals (the packed body is exec'd in the launcher's globals) must NOT draw the
    # same _pyobf_<hex> names for module-level bindings, or the body's injected functions overwrite
    # the launcher's identically-named dispatcher variable. The launcher uses the default salt 0;
    # the body uses protect.core._BODY_NS_SALT. ns_salt=0 keeps every other caller byte-identical.
    # 1. collect temp names actually present in this tree (∩ issued), first-appearance order
    order = []
    seen = set()
    for n in ast.walk(tree):
        for ident in _idents(n):
            if ident in _GEN_ISSUED and ident not in seen:
                seen.add(ident); order.append(ident)
    if not order:
        return tree
    # 2. assign seeded-random finals, avoiding ALL existing non-temp names + each other
    rng = random.Random((seed or 0) ^ 0xF1A11 ^ ns_salt)
    avoid = collect_names(tree) - seen
    mapping = {}
    for t in order:
        while True:
            cand = f"_pyobf_{rng.randrange(1 << 48):x}"
            if cand not in avoid and cand not in mapping.values():
                mapping[t] = cand; break
    # 3. comprehensive rewrite of every identifier-bearing field
    _Rewriter(mapping).visit(tree)
    ast.fix_missing_locations(tree)
    if out_map is not None:
        out_map.update(mapping)
    return tree


def _idents(n):
    if isinstance(n, ast.Name): yield n.id
    elif isinstance(n, ast.arg): yield n.arg
    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): yield n.name
    elif isinstance(n, ast.alias): yield (n.asname or n.name)
    elif isinstance(n, ast.ExceptHandler) and n.name: yield n.name
    elif isinstance(n, ast.Global):
        for x in n.names: yield x
    elif isinstance(n, ast.Nonlocal):
        for x in n.names: yield x


class _Rewriter(ast.NodeTransformer):
    def __init__(self, m): self.m = m
    def visit_Name(self, node):
        if node.id in self.m: node.id = self.m[node.id]
        return node
    def visit_arg(self, node):
        if node.arg in self.m: node.arg = self.m[node.arg]
        return node
    def _rename_def(self, node):
        if node.name in self.m: node.name = self.m[node.name]
        self.generic_visit(node); return node
    visit_FunctionDef = _rename_def
    visit_AsyncFunctionDef = _rename_def
    visit_ClassDef = _rename_def
    def visit_ExceptHandler(self, node):
        if node.name and node.name in self.m: node.name = self.m[node.name]
        self.generic_visit(node); return node
    def visit_Global(self, node):
        node.names = [self.m.get(x, x) for x in node.names]; return node
    def visit_Nonlocal(self, node):
        node.names = [self.m.get(x, x) for x in node.names]; return node
    def visit_alias(self, node):
        # only rename a temp asname; never rewrite the imported module 'name'
        if node.asname and node.asname in self.m: node.asname = self.m[node.asname]
        return node
