"""LocalCallPass — obfuscate @local_call-decorated functions.

Actions (in order):
1. Strip the @local_call decorator from every decorated function.
2. If a decorated function is inline-eligible (single bare-Expr call site, non-recursive,
   no return/yield, simple positional params, same scope) -> inline it with alpha-renaming
   of locals to prevent capture.
3. Else if its name is uniquely bound in the whole tree (no shadowing) -> rename to a fresh
   opaque name.
4. Remove dead `from pyobfuscator import local_call` imports.

The pass is a no-op when there are no @local_call decorators.
"""
from __future__ import annotations

import ast
import copy
from typing import NamedTuple

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from .flatten import FLATTEN_ALLOWED
from .normalize import _MATCH_NODES as _NM_NODES


# ---------------------------------------------------------------------------
# Helper: detect the marker decorator
# ---------------------------------------------------------------------------

def _is_marker(dec) -> bool:
    """True for @local_call or @pkg.local_call."""
    return (isinstance(dec, ast.Name) and dec.id == "local_call") or \
           (isinstance(dec, ast.Attribute) and dec.attr == "local_call")


# ---------------------------------------------------------------------------
# Binding scan — count every binding of each name in the whole tree
# ---------------------------------------------------------------------------

class _BindingScan(ast.NodeVisitor):
    """Count every name-binding occurrence across the whole AST.

    Binding forms counted:
      - FunctionDef / AsyncFunctionDef / ClassDef names
      - arguments: args, posonlyargs, kwonlyargs, vararg, kwarg
      - Assign / AnnAssign / AugAssign / NamedExpr targets (recursively via _target)
      - For target, comprehension target, with-item as-variable, except-as alias
      - global / nonlocal declared names
      - import / importfrom aliases (bound name = asname if present, else first component)
    """

    def __init__(self):
        self.bound_names: dict[str, int] = {}

    def _add(self, name: str):
        self.bound_names[name] = self.bound_names.get(name, 0) + 1

    def _target(self, node):
        """Recursively extract bound names from an assignment target."""
        if isinstance(node, ast.Name):
            self._add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._target(elt)
        elif isinstance(node, ast.Starred):
            self._target(node.value)
        # Attribute/Subscript targets don't bind a local name

    def visit_FunctionDef(self, node):
        self._add(node.name)
        self._visit_args(node.args)
        # Recurse into the body (we count ALL bindings across the whole tree)
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
        # AugAssign target must be Name/Subscript/Attribute; only Name is a binding
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
# Collect marked function defs with parent context
# ---------------------------------------------------------------------------

class _MarkedInfo(NamedTuple):
    node: ast.FunctionDef  # the marked FunctionDef/AsyncFunctionDef
    parent_list: list       # the list containing node (so we can splice/remove)
    scope_body: list | None # the stmt list of the immediate enclosing scope (for same-scope check)


def _collect_marked(tree: ast.AST) -> list[_MarkedInfo]:
    """Walk the tree and collect all FunctionDef/AsyncFunctionDef nodes that have a
    @local_call decorator, along with their parent statement list and scope body."""
    result: list[_MarkedInfo] = []

    def _walk_stmts(stmts: list, scope_body: list | None):
        for node in stmts:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(_is_marker(d) for d in node.decorator_list):
                    result.append(_MarkedInfo(node=node, parent_list=stmts, scope_body=scope_body))
                # Recurse into function body (the function body is its own scope)
                _walk_stmts(node.body, node.body)
                # Also walk decorators for any nested marked funcs? No — decorators are exprs
            elif isinstance(node, ast.ClassDef):
                _walk_stmts(node.body, node.body)
            elif isinstance(node, ast.If):
                _walk_stmts(node.body, scope_body)
                _walk_stmts(node.orelse, scope_body)
            elif isinstance(node, (ast.For, ast.While)):
                _walk_stmts(node.body, scope_body)
                _walk_stmts(node.orelse, scope_body)
            elif isinstance(node, ast.With):
                _walk_stmts(node.body, scope_body)
            elif isinstance(node, ast.Try):
                _walk_stmts(node.body, scope_body)
                for h in node.handlers:
                    _walk_stmts(h.body, scope_body)
                _walk_stmts(node.orelse, scope_body)
                _walk_stmts(node.finalbody, scope_body)

    if isinstance(tree, ast.Module):
        _walk_stmts(tree.body, tree.body)
    elif isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _walk_stmts(tree.body, tree.body)
    else:
        # Generic walk — treat all statement lists
        for node in ast.walk(tree):
            for field_name, value in ast.iter_fields(node):
                if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                    _walk_stmts(value, value)

    return result


# ---------------------------------------------------------------------------
# Inline eligibility checks
# ---------------------------------------------------------------------------

class _HasReturnYield(ast.NodeVisitor):
    """Check whether a function body contains return or yield/yield-from,
    NOT descending into nested FunctionDef/AsyncFunctionDef/Lambda/ClassDef."""

    def __init__(self):
        self.found = False

    def visit_Return(self, node):
        self.found = True

    def visit_Yield(self, node):
        self.found = True

    def visit_YieldFrom(self, node):
        self.found = True

    # Do NOT descend into nested scopes
    def visit_FunctionDef(self, node):
        pass

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_ClassDef(self, node):
        pass


def _body_has_return_yield(stmts: list) -> bool:
    v = _HasReturnYield()
    for s in stmts:
        v.visit(s)
        if v.found:
            return True
    return False


def _simple_params(args: ast.arguments) -> list[str] | None:
    """Return list of param names if args are simple positional-only
    (no defaults, no *args, no **kwargs, no kwonly args). Else None."""
    if (args.vararg or args.kwarg or args.kwonlyargs or args.kw_defaults or
            args.defaults or args.posonlyargs):
        return None
    return [a.arg for a in args.args]


def _find_calls_to(name: str, tree: ast.AST) -> list[ast.Call]:
    """Find all ast.Call nodes whose func is Name(id=name)."""
    calls = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Name) and
                node.func.id == name):
            calls.append(node)
    return calls


def _is_bare_expr_call(node: ast.stmt, name: str) -> bool:
    """True if node is `Expr(Call(Name(name), ...))` — return value discarded."""
    return (isinstance(node, ast.Expr) and
            isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Name) and
            node.value.func.id == name)


def _find_bare_expr_call_in_stmts(stmts: list, name: str):
    """Return (index, stmt) of the first bare-Expr call in stmts, or None."""
    for i, s in enumerate(stmts):
        if _is_bare_expr_call(s, name):
            return i, s
    return None


def _is_recursive(func_node, name: str) -> bool:
    """True if any call to `name` exists inside func_node's body (not descending
    into nested scopes)."""
    class _RecCheck(ast.NodeVisitor):
        def __init__(self):
            self.found = False

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == name:
                self.found = True
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            pass  # don't descend

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_Lambda = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

    v = _RecCheck()
    for s in func_node.body:
        v.visit(s)
        if v.found:
            return True
    return False


def _resolve_positional(params: list[str], call: ast.Call) -> list | None:
    """Resolve call args to params. All positional, no */**. Returns list of exprs or None."""
    if call.keywords or any(isinstance(a, ast.Starred) for a in call.args):
        return None
    if len(call.args) != len(params):
        return None
    return list(call.args)


# ---------------------------------------------------------------------------
# Alpha-renaming transformer for inlining
# ---------------------------------------------------------------------------

class _AlphaRenamer(ast.NodeTransformer):
    """Rename a set of local names to fresh names. Does NOT descend into nested
    FunctionDef/AsyncFunctionDef/Lambda/ClassDef bodies."""

    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping

    def visit_Name(self, node):
        new_id = self.mapping.get(node.id)
        if new_id is not None:
            return ast.Name(id=new_id, ctx=node.ctx)
        return node

    def visit_arg(self, node):
        new_id = self.mapping.get(node.arg)
        if new_id is not None:
            return ast.arg(arg=new_id, annotation=node.annotation)
        return node

    def visit_FunctionDef(self, node):
        # Don't recurse into nested function bodies — only rename in the outer scope
        return node

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef


def _collect_local_bindings(func_body: list, params: list[str],
                             global_nonlocal: set[str]) -> set[str]:
    """Collect names locally bound in func_body (Assign/AnnAssign/AugAssign/NamedExpr/for/with/
    except-as/comprehension targets), plus params, excluding global/nonlocal-declared names.
    Does NOT descend into nested scopes."""

    bound: set[str] = set(params)

    class _LocalBind(ast.NodeVisitor):
        def _target(self, node):
            if isinstance(node, ast.Name) and node.id not in global_nonlocal:
                bound.add(node.id)
            elif isinstance(node, (ast.Tuple, ast.List)):
                for e in node.elts:
                    self._target(e)
            elif isinstance(node, ast.Starred):
                self._target(node.value)

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
            for s in node.body + node.orelse:
                self.visit(s)

        def visit_With(self, node):
            for item in node.items:
                if item.optional_vars is not None:
                    self._target(item.optional_vars)
            for s in node.body:
                self.visit(s)

        def visit_ExceptHandler(self, node):
            if node.name and node.name not in global_nonlocal:
                bound.add(node.name)
            self.generic_visit(node)

        def visit_comprehension(self, node):
            self._target(node.target)
            self.visit(node.iter)
            for c in node.ifs:
                self.visit(c)

        def visit_Global(self, node):
            pass  # don't add global names

        def visit_Nonlocal(self, node):
            pass  # don't add nonlocal names

        # Don't descend into nested scopes
        def visit_FunctionDef(self, node):
            pass

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_Lambda = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

    v = _LocalBind()
    for s in func_body:
        v.visit(s)

    return bound


def _collect_global_nonlocal(func_body: list) -> set[str]:
    """Collect names declared global or nonlocal directly in func_body (not descending
    into nested scopes)."""
    gn: set[str] = set()

    class _GNCollect(ast.NodeVisitor):
        def visit_Global(self, node):
            gn.update(node.names)

        def visit_Nonlocal(self, node):
            gn.update(node.names)

        def visit_FunctionDef(self, node):
            pass

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_Lambda = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

    v = _GNCollect()
    for s in func_body:
        v.visit(s)
    return gn


# ---------------------------------------------------------------------------
# Whole-tree renaming transformer
# ---------------------------------------------------------------------------

class _WholeTreeRenamer(ast.NodeTransformer):
    """Rename every Name(id=old) and FunctionDef/AsyncFunctionDef named `old` to `new`."""

    def __init__(self, old: str, new: str):
        self.old = old
        self.new = new

    def visit_Name(self, node):
        if node.id == self.old:
            return ast.Name(id=self.new, ctx=node.ctx)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if node.name == self.old:
            node.name = self.new
        return node

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        if node.name == self.old:
            node.name = self.new
        return node


# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------

class LocalCallPass:
    name = "localcall"

    def supports(self) -> SupportSet:
        # Must accept everything that could appear before NormalizePass (which runs after us),
        # including Match nodes that NormalizePass desugars.
        return SupportSet(allowed=FLATTEN_ALLOWED | _NM_NODES)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        # --- Step 1: collect all marked defs ---
        marked = _collect_marked(tree)
        if not marked:
            return tree  # no-op fast path

        # --- Step 2: strip marker decorators ---
        for info in marked:
            info.node.decorator_list = [
                d for d in info.node.decorator_list if not _is_marker(d)
            ]

        # --- Step 3: build binding counts across whole tree ---
        scanner = _BindingScan()
        scanner.visit(tree)
        bound_names = scanner.bound_names

        # --- Set up a single Namer for all fresh names ---
        namer = Namer(options.seed, collect_names(tree))

        # --- Step 4: for each marked def, try inline then rename ---
        marked_ids = {id(info.node) for info in marked}

        for info in marked:
            func = info.node
            old_name = func.name
            parent_list = info.parent_list
            scope_body = info.scope_body  # the scope body that contains this def

            # --- Check inline eligibility ---
            params = _simple_params(func.args)
            inlined = False

            if params is not None and scope_body is not None:
                # Find all calls to this name in the whole tree
                all_calls = _find_calls_to(old_name, tree)

                if len(all_calls) == 1:
                    # Find a bare-Expr call in scope_body (same scope)
                    bare = _find_bare_expr_call_in_stmts(scope_body, old_name)

                    if bare is not None:
                        call_idx, call_stmt = bare
                        call = call_stmt.value  # the ast.Call node

                        # Non-recursive?
                        if not _is_recursive(func, old_name):
                            # No return/yield in body?
                            if not _body_has_return_yield(func.body):
                                # Resolve args
                                resolved = _resolve_positional(params, call)
                                if resolved is not None:
                                    # --- Inline it ---
                                    # Alpha-rename locals to avoid capture
                                    gn = _collect_global_nonlocal(func.body)
                                    local_names = _collect_local_bindings(func.body, params, gn)
                                    alpha_map = {n: namer.fresh("in") for n in local_names}

                                    # Deep-copy the body so we don't mutate the original func
                                    body_copy = copy.deepcopy(func.body)
                                    renamed_body = _AlphaRenamer(alpha_map).visit(
                                        ast.Module(body=body_copy, type_ignores=[])
                                    ).body

                                    # Build param-bind assignments
                                    binds = []
                                    for p, val in zip(params, resolved):
                                        p_new = alpha_map[p]
                                        binds.append(ast.Assign(
                                            targets=[ast.Name(id=p_new, ctx=ast.Store())],
                                            value=val,
                                            lineno=func.lineno,
                                            col_offset=func.col_offset,
                                        ))

                                    # Splice: replace the bare-Expr call with binds + body
                                    replacement = binds + renamed_body
                                    scope_body[call_idx:call_idx + 1] = replacement

                                    # Remove the function def from parent_list
                                    if func in parent_list:
                                        parent_list.remove(func)

                                    inlined = True

            if not inlined:
                # --- Check rename eligibility: name uniquely bound by this one def ---
                count = bound_names.get(old_name, 0)
                if count == 1:
                    # Rename throughout the tree
                    new_name = namer.fresh("lc")
                    _WholeTreeRenamer(old_name, new_name).visit(tree)
                # else: name is bound elsewhere -> skip rename (fail-safe), decorator already stripped

        # --- Step 5: remove dead `from pyobfuscator import local_call` ---
        _remove_dead_marker_import(tree)

        ast.fix_missing_locations(tree)
        return tree


def _remove_dead_marker_import(tree: ast.AST):
    """For every ImportFrom with module='pyobfuscator', drop the 'local_call' alias.
    If that leaves the ImportFrom with no aliases, remove the whole statement."""
    for node in ast.walk(tree):
        stmts = None
        if isinstance(node, ast.Module):
            stmts = node.body
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stmts = node.body
        elif isinstance(node, ast.If):
            # handle if/else bodies
            stmts = None  # handled via walk
        if stmts is not None:
            _clean_imports_in_list(stmts)

    # Also handle any nested stmt lists (try/for/while/with/etc.)
    for node in ast.walk(tree):
        for field_name, value in ast.iter_fields(node):
            if isinstance(value, list) and value:
                _clean_imports_in_list(value)


def _clean_imports_in_list(stmts: list):
    """Remove local_call aliases from pyobfuscator ImportFrom stmts in a stmt list."""
    to_remove = []
    for i, stmt in enumerate(stmts):
        if not (isinstance(stmt, ast.ImportFrom) and stmt.module == "pyobfuscator"):
            continue
        new_names = [a for a in stmt.names if a.name != "local_call"]
        if not new_names:
            to_remove.append(i)
        else:
            stmt.names = new_names

    for i in reversed(to_remove):
        stmts.pop(i)
