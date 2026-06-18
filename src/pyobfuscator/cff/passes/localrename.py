"""LocalRenamePass — scope-aware rename of USER-CODE function parameters, local variables, and
comprehension / for-loop target variables to fresh obfuscator names, so no user identifier survives
in the obfuscated output. Behaviour-preserving (no flag; always on).

Why this exists: the rest of the pipeline renames GENERATED names and function NAMES, and `slot_vars`
(when on) maps a function's *plain local assignments* to `_slots[i]` — but it deliberately leaves
PARAMETERS and for/comprehension TARGETS as plaintext (those cannot become `_slots[i]` subscripts).
So a user param `key` or a loop var `ch` survives verbatim. This pass closes that gap by renaming the
identifiers themselves, upstream of slot_vars/flatten, so downstream passes see only fresh names.

Decision (locked) — "locals + SAFE params":
  * SKIP an ENTIRE function's local scope if its body uses `locals()`/`vars()`/`exec`/`eval` (as a
    called Name), a `global` statement, a `nonlocal` statement, or has a `**kwargs` parameter.
  * For a safe function: SKIP an INDIVIDUAL parameter whose name is passed BY KEYWORD anywhere in the
    module (`f(name=...)`), since keyword call sites cannot be safely rewritten in general. Renaming a
    param needs NO change at positional call sites.
  * NEVER rename self/cls, dunder names, or names declared global/nonlocal.
  * Closures: a nested function's free variable that binds in an enclosing function is renamed
    CONSISTENTLY with that binding. Comprehensions/genexps own their target scope (rename targets +
    uses within the comprehension only). The walrus target inside a comprehension leaks to the
    enclosing function (PEP 572) and is bound/renamed there; the outermost comprehension iterable is
    evaluated in the enclosing scope.

Implementation: pure AST scope analysis (version-stable, preserves node identity — no symtable
unparse round-trip). Two phases:
  1. Build the scope tree (module/class/function/comprehension), recording each scope's DIRECT
     bindings, plus per-function safety facts and the module-wide keyword-call-site name set.
  2. Decide a per-scope rename map (orig -> fresh) for function & comprehension scopes, then rewrite
     every Name/arg by resolving it to the nearest enclosing scope that binds it (skipping class
     scopes for non-class users), applying that scope's map.

Determinism: only Namer.fresh (process-global monotonic counter) mints names; the final seeded
rename (cff/rename.finalize_names) makes output deterministic. We iterate binding sets via sorted()
so the fresh-name assignment order is stable regardless of set iteration order / PYTHONHASHSEED.
"""
from __future__ import annotations

import ast

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from .flatten import FLATTEN_ALLOWED

_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMP = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

# Names that hard-disable renaming a whole function scope when CALLED as a bare Name in its body.
_UNSAFE_CALLS = frozenset({"locals", "vars", "exec", "eval"})


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _param_arg_nodes(fn):
    """All ast.arg nodes of a function's signature (posonly/args/kwonly/vararg/kwarg)."""
    a = fn.args
    for grp in (a.posonlyargs, a.args, a.kwonlyargs):
        for arg in grp:
            yield arg
    if a.vararg is not None:
        yield a.vararg
    if a.kwarg is not None:
        yield a.kwarg


# --------------------------------------------------------------------------- scope tree

class _Scope:
    __slots__ = ("node", "kind", "parent", "bindings", "globals", "nonlocals",
                 "unsafe", "rename", "nested_names")

    def __init__(self, node, kind, parent):
        self.node = node
        self.kind = kind          # "module" | "class" | "function" | "comp"
        self.parent = parent
        self.bindings: set[str] = set()   # names bound DIRECTLY in this scope
        self.globals: set[str] = set()    # names declared `global` here
        self.nonlocals: set[str] = set()  # names declared `nonlocal` here
        # names of nested def/class statements bound here: kept in `bindings` (so inner-scope
        # references resolve correctly) but NEVER renamed by THIS pass — function/class NAMES are
        # renamed elsewhere in the pipeline. Renaming the reference but not the definition (or vice
        # versa) would desync them (NameError). Excluded from rename candidates in _decide_renames.
        self.nested_names: set[str] = set()
        self.unsafe = False               # function: skip whole scope (locals/exec/global/.../kwargs)
        self.rename: dict[str, str] = {}  # orig -> fresh (only function/comp)


def _collect_target_names(target, out: set[str]) -> None:
    """Names bound by an assignment/for/with target (Name, Starred, Tuple, List)."""
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, ast.Starred):
        _collect_target_names(target.value, out)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            _collect_target_names(e, out)
    # Attribute / Subscript targets bind nothing local (obj.x = / obj[i] =)


def _bindings_in_function_body(scope: _Scope) -> None:
    """Fill scope.bindings/globals/nonlocals for a function scope by scanning its body WITHOUT
    descending into nested function/class/comprehension scopes (those are their own scopes)."""
    fn = scope.node
    # parameters
    for arg in _param_arg_nodes(fn):
        scope.bindings.add(arg.arg)

    def walk_stmts(stmts):
        for s in stmts:
            walk(s)

    def walk(node):
        # do not descend into nested scopes
        if isinstance(node, _FUNC):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope.bindings.add(node.name)
                scope.nested_names.add(node.name)  # bound here, but NOT renamed by this pass
            return
        if isinstance(node, ast.ClassDef):
            scope.bindings.add(node.name)
            scope.nested_names.add(node.name)
            return
        if isinstance(node, _COMP):
            # A comprehension is its own scope; its targets do NOT bind here. BUT a walrus (:=)
            # inside a comprehension binds in THIS (the enclosing function) scope. Scan only the
            # comprehension's expression parts for NamedExpr targets; skip its `for` targets.
            _collect_walrus_from_comp(node, scope.bindings)
            return
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _collect_target_names(t, scope.bindings)
            walk(node.value)
            return
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                scope.bindings.add(node.target.id)
            walk(node.value)
            return
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                scope.bindings.add(node.target.id)
            if node.value is not None:
                walk(node.value)
            # do not walk the annotation for bindings
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            _collect_target_names(node.target, scope.bindings)
            walk(node.iter)
            walk_stmts(node.body)
            walk_stmts(node.orelse)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                walk(item.context_expr)
                if item.optional_vars is not None:
                    _collect_target_names(item.optional_vars, scope.bindings)
            walk_stmts(node.body)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.name:
                scope.bindings.add(node.name)
            if node.type is not None:
                walk(node.type)
            walk_stmts(node.body)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                scope.bindings.add((alias.asname or alias.name).split(".")[0])
            return
        if isinstance(node, ast.Global):
            scope.globals.update(node.names)
            return
        if isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
            return
        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                scope.bindings.add(node.target.id)
            walk(node.value)
            return
        for child in ast.iter_child_nodes(node):
            walk(child)

    if isinstance(fn, ast.Lambda):
        # A lambda's body is a single expression (not a statement list). Its only bindings are its
        # params (added above) plus any walrus targets that occur in the body expression but NOT
        # inside a nested comprehension/lambda (those have their own scope). `walk` already stops at
        # nested scopes and records NamedExpr targets, so reuse it on the single expression.
        walk(fn.body)
    else:
        walk_stmts(fn.body)


def _collect_walrus_from_comp(comp, out: set[str]) -> None:
    """Collect NamedExpr (walrus) target names that occur inside a comprehension's expression
    parts (element/key/value/conditions/iterables) — these leak to the enclosing function scope.
    The comprehension's own `for` targets are NOT collected here."""
    parts = []
    if isinstance(comp, ast.DictComp):
        parts += [comp.key, comp.value]
    else:
        parts += [comp.elt]
    for gen in comp.generators:
        parts += list(gen.ifs)
        parts.append(gen.iter)
    for p in parts:
        for n in ast.walk(p):
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                out.add(n.target.id)


def _comp_targets(comp) -> set[str]:
    """The `for` target names bound by a comprehension (its own scope)."""
    out: set[str] = set()
    for gen in comp.generators:
        _collect_target_names(gen.target, out)
    return out


def _function_is_unsafe(fn) -> bool:
    """True if the whole function scope must be skipped (no rename of its locals/params)."""
    if fn.args.kwarg is not None:           # **kwargs forwarding is undetectable-safe -> skip
        return True

    def walk(node):
        if isinstance(node, _FUNC) and node is not fn:
            return False  # nested function: its own pass handles it; doesn't affect fn's safety
        if isinstance(node, ast.ClassDef):
            return False
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in _UNSAFE_CALLS:
            return True
        # eval/exec/locals/vars also unsafe if merely referenced as a bare Name (e.g. aliased) —
        # be conservative: any Load of these names disables the scope.
        if isinstance(node, ast.Name) and node.id in _UNSAFE_CALLS:
            return True
        for child in ast.iter_child_nodes(node):
            if walk(child):
                return True
        return False

    # scan the function body (and signature defaults are in the enclosing scope, ignore)
    body = fn.body if isinstance(fn.body, list) else [fn.body]
    for s in body:
        if walk(s):
            return True
    return False


def _build_scope_tree(tree) -> tuple[_Scope, dict]:
    """Build the scope tree. Returns (root_module_scope, node_id -> _Scope for every scope node)."""
    root = _Scope(tree, "module", None)
    by_node = {id(tree): root}

    def make(node, kind, parent):
        sc = _Scope(node, kind, parent)
        by_node[id(node)] = sc
        return sc

    def descend(node, scope):
        """Visit children of `node` (a scope's defining node), creating child scopes and routing
        non-scope subtrees so we discover nested scopes at any depth."""
        for child in ast.iter_child_nodes(node):
            _route(child, scope)

    def _route(node, scope):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sc = make(node, "function", scope)
            _bindings_in_function_body(sc)
            sc.unsafe = _function_is_unsafe(node)
            # descend into the body to find nested scopes
            for s in node.body:
                _route(s, sc)
            # decorators / default exprs / annotations belong to the ENCLOSING scope
            for dec in node.decorator_list:
                _route(dec, scope)
            for d in (node.args.defaults + [k for k in node.args.kw_defaults if k is not None]):
                _route(d, scope)
            return
        if isinstance(node, ast.Lambda):
            sc = make(node, "function", scope)
            _bindings_in_function_body(sc)
            sc.unsafe = _function_is_unsafe(node)
            _route(node.body, sc)
            for d in (node.args.defaults + [k for k in node.args.kw_defaults if k is not None]):
                _route(d, scope)
            return
        if isinstance(node, ast.ClassDef):
            sc = make(node, "class", scope)
            # class body names are attributes -> not renamed; still a scope boundary.
            for s in node.body:
                _route(s, sc)
            for dec in node.decorator_list:
                _route(dec, scope)
            for b in node.bases:
                _route(b, scope)
            for kw in node.keywords:
                _route(kw.value, scope)
            return
        if isinstance(node, _COMP):
            sc = make(node, "comp", scope)
            sc.bindings = _comp_targets(node)
            # The outermost generator's iterable is evaluated in the ENCLOSING scope.
            gens = node.generators
            if gens:
                _route(gens[0].iter, scope)        # outermost iterable -> enclosing
                for g in gens:
                    for cond in g.ifs:
                        _route(cond, sc)
                for g in gens[1:]:
                    _route(g.iter, sc)             # inner iterables -> comp scope
            # element/key/value evaluated in comp scope
            if isinstance(node, ast.DictComp):
                _route(node.key, sc)
                _route(node.value, sc)
            else:
                _route(node.elt, sc)
            return
        # not a scope node: keep walking within the current scope
        descend(node, scope)

    for child in ast.iter_child_nodes(tree):
        _route(child, root)
    return root, by_node


# --------------------------------------------------------------------------- keyword call sites

def _keyword_call_names(tree) -> set[str]:
    """Every parameter name used at a keyword call site anywhere in the module: `f(name=...)`.
    `**d` splat keywords have arg==None and are ignored (they don't pin a specific name)."""
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.keyword) and n.arg is not None:
            out.add(n.arg)
    return out


# --------------------------------------------------------------------------- rename decisions

def _qualname(scope: _Scope) -> str:
    """A readable scope path for sourcemap provenance (best-effort)."""
    parts = []
    cur = scope
    while cur is not None and cur.kind != "module":
        node = cur.node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parts.append(node.name)
        elif isinstance(node, ast.Lambda):
            parts.append("<lambda>")
        elif cur.kind == "comp":
            parts.append("<comp>")
        cur = cur.parent
    if not parts:
        return "<module>"
    return ".".join(reversed(parts))


def _compute_pinned(by_node: dict) -> dict:
    """node_id(scope) -> set of names that scope must NOT rename because a DESCENDANT scope binds
    them by that exact string via `nonlocal`. A skipped (unsafe) descendant with `nonlocal x` keeps
    `x` plaintext and writes through to the enclosing binding; if the enclosing scope renamed `x` the
    `nonlocal x` would dangle (SyntaxError / new variable). So pin `x` in the nearest enclosing
    FUNCTION scope above the declaring scope that binds `x`."""
    pinned: dict = {}
    for sc in by_node.values():
        for name in sc.nonlocals:
            cur = sc.parent
            while cur is not None and cur.kind != "module":
                if cur.kind == "function" and name in cur.bindings:
                    pinned.setdefault(id(cur.node), set()).add(name)
                    break
                cur = cur.parent
    return pinned


def _decide_renames(by_node: dict, namer: Namer, keyword_names: set[str]) -> None:
    """Populate scope.rename for every function/comp scope, applying the skip rules."""
    pinned = _compute_pinned(by_node)
    for sc in by_node.values():
        if sc.kind == "function":
            if sc.unsafe:
                continue
            fn = sc.node
            param_set = {a.arg for a in _param_arg_nodes(fn)}
            qn = _qualname(sc)
            # candidate names = direct bindings minus self/cls/dunders, minus global/nonlocal names,
            # minus names a descendant pins via `nonlocal`, minus nested def/class names (renamed by
            # another pass — renaming them here would desync definition vs reference).
            skip = ({"self", "cls"} | sc.globals | sc.nonlocals | sc.nested_names
                    | pinned.get(id(sc.node), set()))
            for name in sorted(sc.bindings):
                if name in skip or _is_dunder(name):
                    continue
                if name in param_set:
                    if name in keyword_names:
                        continue   # SAFE-param rule: keyword call site somewhere -> skip this param
                    sc.rename[name] = namer.fresh("arg", orig=name, scope=qn, kind="arg")
                else:
                    sc.rename[name] = namer.fresh("local", orig=name, scope=qn, kind="local")
        elif sc.kind == "comp":
            qn = _qualname(sc)
            for name in sorted(sc.bindings):
                if _is_dunder(name):
                    continue
                sc.rename[name] = namer.fresh("local", orig=name, scope=qn, kind="local")


# --------------------------------------------------------------------------- rewrite

class _Rewriter:
    """Rewrite identifiers by resolving each to the nearest enclosing scope that binds it. Drives
    the same scope tree built in phase 1 (by node identity)."""

    def __init__(self, by_node: dict):
        self.by_node = by_node

    def run(self, tree, root: _Scope):
        # We re-walk the AST mirroring _build_scope_tree's scope descent, carrying a scope chain.
        self._route(tree, [root])

    def _resolve(self, name: str, chain: list[_Scope]) -> str | None:
        """Return the fresh name for `name` given the active scope chain (innermost last), honoring
        Python's resolution (skip class scopes unless the using scope itself is that class)."""
        for i in range(len(chain) - 1, -1, -1):
            sc = chain[i]
            innermost = (i == len(chain) - 1)
            if sc.kind == "class" and not innermost:
                continue  # nested functions/comps do not close over class-body names
            if name in sc.bindings:
                return sc.rename.get(name)  # may be None if scope chose not to rename it
        return None

    def _rw_name(self, node, chain):
        if isinstance(node, ast.Name):
            new = self._resolve(node.id, chain)
            if new is not None:
                node.id = new
        elif isinstance(node, ast.arg):
            new = self._resolve(node.arg, chain)
            if new is not None:
                node.arg = new

    def _route(self, node, chain):
        scope = chain[-1]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # decorators / defaults / annotations are evaluated in the ENCLOSING scope
            for dec in node.decorator_list:
                self._route(dec, chain)
            for d in node.args.defaults:
                self._route(d, chain)
            for d in node.args.kw_defaults:
                if d is not None:
                    self._route(d, chain)
            self._route_annotations(node.args, chain)
            if node.returns is not None:
                self._route(node.returns, chain)
            # the function NAME binds in the enclosing scope
            self._rw_name_str_target(node, "name", chain)
            sc = self.by_node[id(node)]
            inner = chain + [sc]
            # rename the params (arg nodes) within the function scope
            for arg in _param_arg_nodes(node):
                self._rw_name(arg, inner)
            for s in node.body:
                self._route(s, inner)
            return
        if isinstance(node, ast.Lambda):
            for d in node.args.defaults:
                self._route(d, chain)
            for d in node.args.kw_defaults:
                if d is not None:
                    self._route(d, chain)
            sc = self.by_node[id(node)]
            inner = chain + [sc]
            for arg in _param_arg_nodes(node):
                self._rw_name(arg, inner)
            self._route(node.body, inner)
            return
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                self._route(dec, chain)
            for b in node.bases:
                self._route(b, chain)
            for kw in node.keywords:
                self._route(kw.value, chain)
            sc = self.by_node[id(node)]
            inner = chain + [sc]
            for s in node.body:
                self._route(s, inner)
            return
        if isinstance(node, _COMP):
            sc = self.by_node[id(node)]
            inner = chain + [sc]
            gens = node.generators
            if gens:
                self._route(gens[0].iter, chain)   # outermost iterable in enclosing scope
                # targets bind in comp scope -> rewrite via inner
                for g in gens:
                    self._route_target(g.target, inner)
                    for cond in g.ifs:
                        self._route(cond, inner)
                for g in gens[1:]:
                    self._route(g.iter, inner)
            if isinstance(node, ast.DictComp):
                self._route(node.key, inner)
                self._route(node.value, inner)
            else:
                self._route(node.elt, inner)
            return
        if isinstance(node, ast.Name):
            self._rw_name(node, chain)
            return
        if isinstance(node, ast.Global):
            return  # never rename declared-global names
        if isinstance(node, ast.Nonlocal):
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._route_import(node, chain)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.type is not None:
                self._route(node.type, chain)
            # the except name binds in the current scope -> rename if mapped
            if node.name is not None:
                new = self._resolve(node.name, chain)
                if new is not None:
                    node.name = new
            for s in node.body:
                self._route(s, chain)
            return
        # generic: recurse into children within the same scope
        for child in ast.iter_child_nodes(node):
            self._route(child, chain)

    def _route_target(self, target, chain):
        """Rewrite a binding target (Name/Starred/Tuple/List) in `chain`'s innermost scope."""
        if isinstance(target, ast.Name):
            self._rw_name(target, chain)
        elif isinstance(target, ast.Starred):
            self._route_target(target.value, chain)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self._route_target(e, chain)
        else:
            # Attribute/Subscript target: its sub-expressions are normal Loads in this scope
            self._route(target, chain)

    def _route_annotations(self, args, chain):
        for grp in (args.posonlyargs, args.args, args.kwonlyargs):
            for a in grp:
                if a.annotation is not None:
                    self._route(a.annotation, chain)
        if args.vararg is not None and args.vararg.annotation is not None:
            self._route(args.vararg.annotation, chain)
        if args.kwarg is not None and args.kwarg.annotation is not None:
            self._route(args.kwarg.annotation, chain)

    def _route_import(self, node, chain):
        # An import binds `(asname or name.split('.')[0])` in the current scope. If that bound name
        # was selected for rename, rewrite the asname. We never touch the real module `name`. If the
        # binding is via the bare module name (no asname) and it was renamed, we MUST add an asname
        # so the binding takes the fresh name while the import target stays correct.
        for alias in node.names:
            bound = (alias.asname or alias.name).split(".")[0]
            new = self._resolve(bound, chain)
            if new is None:
                continue
            if alias.asname is not None:
                alias.asname = new
            else:
                # `import a.b.c` binds `a`; renaming it requires `import a.b.c as <new>` only when
                # name has no dots (a dotted import binds the head package, which a plain asname
                # can't express without changing semantics). For the head-only case set an asname.
                if "." not in alias.name:
                    alias.asname = new
                # else: dotted import bound to head package — leave as-is (head names are rarely
                # renameable locals; conservative no-op preserves behaviour).

    def _rw_name_str_target(self, node, attr, chain):
        cur = getattr(node, attr)
        new = self._resolve(cur, chain)
        if new is not None:
            setattr(node, attr, new)


# --------------------------------------------------------------------------- pass

def _has_dispatcher(fn) -> bool:
    """True if a function body is a flattened CFF dispatcher (a top-level `while True`)."""
    body = getattr(fn, "body", None)
    if not isinstance(body, list):
        return False                              # lambda (expr body) — not flattened
    for s in body:
        if isinstance(s, ast.While) and isinstance(s.test, ast.Constant) and s.test.value is True:
            return True
    return False


def rename_simple_helper_locals(tree: ast.AST, namer: Namer = None) -> ast.AST:
    """LATE companion to LocalRenamePass: rename the params/locals of NON-flattened (simple) functions
    — the generated runtime helpers (const-archive `_ks`/`_kdf`/`_get`, `_dec`, the attest oracle, the
    call-stack push helper, lifted-lambda defs, ...) that are injected AFTER LocalRenamePass ran in the
    pipeline, so they still carry plaintext param names (`s`, `off`, `sz`, `data`, `key`, ...). Reuses
    the same proven scope machinery + safety guards; flattened USER functions (top-level `while True`)
    are skipped (already handled early). Run before finalize_names so the fresh names finalize +
    appear in the sourcemap (with `orig`)."""
    if namer is None:
        namer = Namer(taken=collect_names(tree))
    keyword_names = _keyword_call_names(tree)
    root, by_node = _build_scope_tree(tree)
    for sc in by_node.values():
        if sc.kind == "function" and _has_dispatcher(sc.node):
            sc.unsafe = True                      # flattened user code -> skip (handled by the early pass)
    _decide_renames(by_node, namer, keyword_names)
    if not any(sc.rename for sc in by_node.values()):
        return tree
    _Rewriter(by_node).run(tree, root)
    ast.fix_missing_locations(tree)
    return tree


class LocalRenamePass:
    name = "localrename"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        namer = Namer(options.seed, collect_names(tree))
        keyword_names = _keyword_call_names(tree)
        root, by_node = _build_scope_tree(tree)
        _decide_renames(by_node, namer, keyword_names)
        # nothing to do if no scope chose any rename
        if not any(sc.rename for sc in by_node.values()):
            return tree
        _Rewriter(by_node).run(tree, root)
        ast.fix_missing_locations(tree)
        return tree
