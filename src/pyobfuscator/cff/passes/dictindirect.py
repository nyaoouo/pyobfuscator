"""DictIndirectPass — route every reference to a non-export internal function through
a per-scope dict `_D[key]`, where key is a plain int Constant (encrypted later by the
obf_ints / state-keyed-const pass when that option is on).

Per-scope design (re-entrancy correctness):
  - Module scope: a module-level dict (global, shared across the module).
  - Function scope: a LOCAL dict created fresh on every call (prevents clobbering by
    recursive / re-entrant nested calls).

Reference resolution follows Python's normal lexical scoping: same-scope = local,
enclosing scope = closure/free var, module = global.

Eligibility (ALL must hold):
  1. Bound by EXACTLY ONE FunctionDef/AsyncFunctionDef in the whole tree (unique binding).
  2. NOT an export (module-level non-`_`-prefixed names treated as exports; `_`-prefixed
     or nested treated as internal). Mirrors StackCall's `_eligible` privacy heuristic.
  3. NOT defined directly in a class body (methods are descriptor-invoked).
  4. Only Name(id=foo, ctx=Load) occurrences rewritten; def name + registration RHS left.

Pipeline position: registered SECOND (right after LocalCallPass, before NormalizePass).
Running before StackCall means helper functions don't exist yet → never indirected.
"""
from __future__ import annotations

import ast
from typing import NamedTuple

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from .flatten import FLATTEN_ALLOWED
from .normalize import _MATCH_NODES as _NM_NODES


# ---------------------------------------------------------------------------
# Binding-uniqueness scan — reuse the same approach as LocalCallPass
# ---------------------------------------------------------------------------

class _BindingScan(ast.NodeVisitor):
    """Count every name-binding occurrence across the whole AST."""

    def __init__(self):
        self.bound_names: dict[str, int] = {}

    def _add(self, name: str):
        self.bound_names[name] = self.bound_names.get(name, 0) + 1

    def _target(self, node):
        if isinstance(node, ast.Name):
            self._add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._target(elt)
        elif isinstance(node, ast.Starred):
            self._target(node.value)

    def visit_FunctionDef(self, node):
        self._add(node.name)
        self._visit_args(node.args)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._add(node.name)
        self.generic_visit(node)

    def _visit_args(self, args: ast.arguments):
        for a in args.posonlyargs + args.args + args.kwonlyargs:
            self._add(a.arg)
        if args.vararg:
            self._add(args.vararg.arg)
        if args.kwarg:
            self._add(args.kwarg.arg)

    def visit_Assign(self, node):
        for t in node.targets:
            self._target(t)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        if node.target:
            self._target(node.target)
        if node.value:
            self.visit(node.value)

    def visit_AugAssign(self, node):
        self._target(node.target)
        self.visit(node.value)

    def visit_NamedExpr(self, node):
        self._target(node.target)
        self.visit(node.value)

    def visit_For(self, node):
        self._target(node.target)
        for child in node.body + node.orelse:
            self.visit(child)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self._target(item.optional_vars)
        for child in node.body:
            self.visit(child)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._add(node.name)
        self.generic_visit(node)

    def visit_comprehension(self, node):
        self._target(node.target)
        self.visit(node.iter)
        for cond in node.ifs:
            self.visit(cond)

    def visit_Global(self, node):
        for name in node.names:
            self._add(name)

    def visit_Nonlocal(self, node):
        for name in node.names:
            self._add(name)

    def visit_Import(self, node):
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name.split(".")[0]
            self._add(bound)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name
            if bound != "*":
                self._add(bound)


# ---------------------------------------------------------------------------
# Scope tree building — find which FunctionDef is directly in which scope
# ---------------------------------------------------------------------------

class _ScopeInfo(NamedTuple):
    """Information about a scope (Module or function)."""
    node: ast.AST            # the Module or FunctionDef/AsyncFunctionDef node
    body: list               # the statement list of this scope
    direct_funcdefs: list    # FunctionDef/AsyncFunctionDef nodes directly in this scope


def _collect_direct_funcdefs(body: list) -> list:
    """Walk a statement list (WITHOUT descending into nested function/class bodies)
    and collect all FunctionDef/AsyncFunctionDef nodes that appear at ANY block depth
    in the same scope (same as _child_scopes for functions, but filtered to funcdefs only).
    """
    found = []

    def _visit_stmts(stmts):
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append(stmt)
                # Do NOT recurse into the function body — it's a nested scope
            elif isinstance(stmt, ast.ClassDef):
                # Do NOT recurse — class body is a separate scope, methods excluded by design
                pass
            elif isinstance(stmt, ast.If):
                _visit_stmts(stmt.body)
                _visit_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.While)):
                _visit_stmts(stmt.body)
                _visit_stmts(stmt.orelse)
            elif isinstance(stmt, ast.With):
                _visit_stmts(stmt.body)
            elif isinstance(stmt, ast.Try):
                _visit_stmts(stmt.body)
                for h in stmt.handlers:
                    _visit_stmts(h.body)
                _visit_stmts(stmt.orelse)
                _visit_stmts(stmt.finalbody)

    _visit_stmts(body)
    return found


def _build_scope_tree(tree: ast.AST) -> list[_ScopeInfo]:
    """Return a flat list of all scopes (Module + all FunctionDef/AsyncFunctionDef),
    each with its direct FunctionDef children."""
    scopes: list[_ScopeInfo] = []

    def _process_scope(node, body):
        direct = _collect_direct_funcdefs(body)
        scopes.append(_ScopeInfo(node=node, body=body, direct_funcdefs=direct))
        # Recurse into nested function scopes (NOT into class bodies — methods excluded)
        for stmt in direct:
            _process_scope(stmt, stmt.body)

    if isinstance(tree, ast.Module):
        _process_scope(tree, tree.body)
    elif isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _process_scope(tree, tree.body)
    else:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _process_scope(node, node.body)

    return scopes


def _collect_method_names(tree: ast.AST) -> set[str]:
    """Collect names of functions defined DIRECTLY in any ClassDef body."""
    method_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_names.add(stmt.name)
    return method_names


def _collect_deleted_names(tree) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Delete):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.add(t.id)
    return out


def _collect_classdef_names(tree) -> set[str]:
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}


def _collect_eligible_globals(tree, bound_names, funcdef_names, classdef_names,
                               deleted, export_names) -> dict[str, ast.Assign]:
    """Return {global_name -> its single module-level Assign node} for the conservative-safe subset."""
    if not isinstance(tree, ast.Module):
        return {}
    out: dict[str, ast.Assign] = {}
    for stmt in tree.body:                         # DIRECT module.body only (unconditional)
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)):
            continue
        name = stmt.targets[0].id
        if name in funcdef_names or name in classdef_names:
            continue
        if name in deleted:
            continue
        if name.startswith("__") and name.endswith("__"):
            continue
        if bound_names.get(name, 0) != 1:          # any other binding → reassigned/mutated → skip
            continue
        # export heuristic (mirror the function logic)
        is_private = name.startswith("_")
        if name in export_names:
            continue
        if not is_private and not export_names:
            continue                                # no explicit exports → non-_ treated as export
        if not is_private and export_names:
            # explicit export list present: keep only if it's actually exported elsewhere?
            # conservative: a non-_ name not in export_names is still likely public → skip
            continue
        out[name] = stmt
    return out


# ---------------------------------------------------------------------------
# Rewriter — NodeTransformer that inserts dict setup and rewrites Name loads
# ---------------------------------------------------------------------------

class _DictRewriter(ast.NodeTransformer):
    """Rewrite the AST:
    1. In each owning scope's body: insert `<dict_var> = {}` at the top.
    2. Immediately AFTER each indirectable `def foo`, insert `<dict_var>[key] = foo`.
    3. Replace every other Name(foo, Load) with Subscript(Name(dict_var), Constant(key)).

    Registration stmts (`_D[key] = foo`) use Name(foo, Load) — we must NOT rewrite those.
    The `def foo` name itself is NOT a Name node (it's an attribute of FunctionDef) — safe.
    """

    def __init__(self, func_info: dict[str, tuple[str, int]], scope_dict_names: dict[int, str],
                 global_info: dict[str, tuple[str, int]] | None = None):
        """
        func_info: {func_name -> (dict_var_name, key)}
        scope_dict_names: {id(scope_node) -> dict_var_name}  (for inserting `_D = {}`)
        global_info: {global_name -> (dict_var_name, key)}  (eligible module globals)
        """
        self._func_info = func_info           # func_name -> (dict_var, key)
        self._global_info: dict[str, tuple[str, int]] = global_info or {}
        self._ref_info: dict[str, tuple[str, int]] = {**func_info, **self._global_info}
        self._scope_dict_names = scope_dict_names  # id(scope) -> dict_var
        self._skip_name_rewrite: set[int] = set()  # id() of Name nodes NOT to rewrite

    def _make_dict_init(self, dict_var: str) -> ast.Assign:
        return ast.Assign(
            targets=[ast.Name(id=dict_var, ctx=ast.Store())],
            value=ast.Dict(keys=[], values=[]),
            lineno=0, col_offset=0,
        )

    def _make_registration(self, dict_var: str, key: int, func_name: str) -> ast.Assign:
        """_D[key] = foo — the Name(foo) here must NOT be rewritten."""
        rhs = ast.Name(id=func_name, ctx=ast.Load())
        self._skip_name_rewrite.add(id(rhs))
        return ast.Assign(
            targets=[ast.Subscript(
                value=ast.Name(id=dict_var, ctx=ast.Load()),
                slice=ast.Constant(value=key),
                ctx=ast.Store(),
            )],
            value=rhs,
            lineno=0, col_offset=0,
        )

    def _make_subscript_load(self, dict_var: str, key: int) -> ast.Subscript:
        return ast.Subscript(
            value=ast.Name(id=dict_var, ctx=ast.Load()),
            slice=ast.Constant(value=key),
            ctx=ast.Load(),
        )

    def _process_body(self, body: list, scope_node) -> list:
        """Insert `_D = {}` at the top and `_D[key] = foo` after each eligible def."""
        dict_var = self._scope_dict_names.get(id(scope_node))
        if dict_var is None:
            return body  # no eligible funcs in this scope

        # Find the insertion point for _D = {} (after leading docstring)
        insert_at = 0
        if (body and isinstance(body[0], ast.Expr) and
                isinstance(body[0].value, ast.Constant) and
                isinstance(body[0].value.value, str)):
            insert_at = 1

        new_body = list(body[:insert_at]) + [self._make_dict_init(dict_var)] + list(body[insert_at:])

        # Now insert registrations after each eligible def; rewrite global binding targets
        result = []
        for stmt in new_body:
            # rewrite `g = expr` -> `dict_var[key] = expr` for eligible globals defined in this scope
            if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)):
                ginfo = self._global_info.get(stmt.targets[0].id)
                if ginfo is not None and ginfo[0] == dict_var:
                    g_dvar, g_key = ginfo
                    stmt.targets[0] = ast.Subscript(
                        value=ast.Name(id=g_dvar, ctx=ast.Load()),
                        slice=ast.Constant(value=g_key), ctx=ast.Store())
            result.append(stmt)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = self._func_info.get(stmt.name)
                if info is not None:
                    d_var, key = info
                    if d_var == dict_var:  # defined in this scope
                        result.append(self._make_registration(d_var, key, stmt.name))
        return result

    def visit_Module(self, node: ast.Module):
        # First recursively transform children
        self.generic_visit(node)
        node.body = self._process_body(node.body, node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Recursively transform children first
        self.generic_visit(node)
        node.body = self._process_body(node.body, node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node: ast.Name):
        # Don't rewrite registration RHS names
        if id(node) in self._skip_name_rewrite:
            return node
        # Only rewrite Load context
        if not isinstance(node.ctx, ast.Load):
            return node
        info = self._ref_info.get(node.id)
        if info is None:
            return node
        dict_var, key = info
        return self._make_subscript_load(dict_var, key)


# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------

class DictIndirectPass:
    name = "dictindirect"

    def supports(self) -> SupportSet:
        # Must accept everything that could appear before NormalizePass (same as LocalCallPass)
        return SupportSet(allowed=FLATTEN_ALLOWED | _NM_NODES)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.dict_indirect:
            return tree  # no-op when flag is off

        # --- Step 1: binding-uniqueness scan ---
        scanner = _BindingScan()
        scanner.visit(tree)
        bound_names = scanner.bound_names

        # A name is "uniquely a function" iff its ONLY binding is exactly ONE FunctionDef/
        # AsyncFunctionDef. We need to track which names come from FunctionDef specifically.
        funcdef_names: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcdef_names[node.name] = funcdef_names.get(node.name, 0) + 1

        # Unique function names: bound exactly once and that binding is a funcdef
        unique_funcs: set[str] = {
            name for name, cnt in funcdef_names.items()
            if cnt == 1 and bound_names.get(name, 0) == 1
        }

        # --- Step 2: exclude methods (names defined directly in a class body) ---
        method_names = _collect_method_names(tree)
        unique_funcs -= method_names

        # --- Step 3: determine eligibility based on scope (exports heuristic) ---
        # For Module top-level: non-_-prefixed names are exports → NOT eligible.
        # For ModuleObfOptions, also check options.exports / __all__.
        # Nested (function-scope) funcs: `_`-prefixed or any nested func → eligible.

        # Collect module-top-level funcdef names
        module_toplevel_funcs: set[str] = set()
        if isinstance(tree, ast.Module):
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    module_toplevel_funcs.add(stmt.name)

        # Determine which module-level funcs are exports (must keep)
        export_names: set[str] = set()
        from ...options import ModuleObfOptions
        if isinstance(options, ModuleObfOptions) and options.exports:
            export_names.update(options.exports)
        if isinstance(options, ModuleObfOptions) and options.exports_from_all:
            # Check for __all__ in module body
            if isinstance(tree, ast.Module):
                for stmt in tree.body:
                    if (isinstance(stmt, ast.Assign) and
                            len(stmt.targets) == 1 and
                            isinstance(stmt.targets[0], ast.Name) and
                            stmt.targets[0].id == "__all__" and
                            isinstance(stmt.value, (ast.List, ast.Tuple))):
                        for elt in stmt.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                export_names.add(elt.value)

        # Apply export filtering to module-level funcs
        # (nested funcs are always internal → eligible if unique & non-method)
        for name in list(unique_funcs):
            if name in module_toplevel_funcs:
                # Module-level: eligible only if _-prefixed OR explicitly not an export
                is_private = name.startswith("_")
                explicitly_exported = name in export_names
                if explicitly_exported:
                    unique_funcs.discard(name)
                elif not is_private and not export_names:
                    # Conservative: no explicit export list → treat non-_-prefixed as export
                    unique_funcs.discard(name)
                # else: _-prefixed → internal (keep in eligible set)

        # --- Step 3b: compute eligible globals ---
        classdef_names = _collect_classdef_names(tree)
        deleted = _collect_deleted_names(tree)
        eligible_globals = _collect_eligible_globals(tree, bound_names, funcdef_names,
                                                     classdef_names, deleted, export_names)

        if not unique_funcs and not eligible_globals:
            return tree  # no-op fast path

        # --- Step 4: build scope tree and allocate per-scope dicts + keys ---
        scopes = _build_scope_tree(tree)
        namer = Namer(options.seed, collect_names(tree))

        # scope_dict_names: id(scope_node) -> dict_var_name  (only for scopes with eligible funcs)
        scope_dict_names: dict[int, str] = {}
        # func_info: func_name -> (dict_var_name, key)
        func_info: dict[str, tuple[str, int]] = {}

        key_counter = 0
        for scope_info in scopes:
            eligible_in_scope = [
                fd for fd in scope_info.direct_funcdefs
                if fd.name in unique_funcs
            ]
            if not eligible_in_scope:
                continue

            # Allocate a fresh dict name for this scope
            dict_var = namer.fresh("D")
            scope_dict_names[id(scope_info.node)] = dict_var

            # Assign keys to each eligible function in this scope
            for fd in eligible_in_scope:
                func_info[fd.name] = (dict_var, key_counter)
                key_counter += 1

        # --- Step 4b: allocate module dict for eligible globals ---
        global_info: dict[str, tuple[str, int]] = {}
        module_scope = next((s for s in scopes if isinstance(s.node, ast.Module)), None)
        if eligible_globals and module_scope is not None:
            mod_dict = scope_dict_names.get(id(module_scope.node))
            if mod_dict is None:
                mod_dict = namer.fresh("D")
                scope_dict_names[id(module_scope.node)] = mod_dict
            for gname in eligible_globals:
                global_info[gname] = (mod_dict, key_counter)
                key_counter += 1

        if not func_info and not global_info:
            return tree  # no eligible funcs or globals after all

        # --- Step 5: rewrite the tree ---
        rewriter = _DictRewriter(func_info, scope_dict_names, global_info)
        tree = rewriter.visit(tree)
        ast.fix_missing_locations(tree)
        return tree
