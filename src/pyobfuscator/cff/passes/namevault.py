"""NameVaultPass — route referenced builtins through a per-module vault _D[k], registered from a
single charcode-bootstrapped root (__import__('builtins').getattr). The builtin NAME strings end
up as literals in the registrations, which ArchivePass (running after) pools into the encrypted
blob. Keys are random ints, state-keyed later by the flatten pass's key_consts.

Layered/acyclic: __import__ (root) -> _bi/_g -> _D registrations. The vault is built with _g, never
with itself. Phase 2 routes builtins + simple top-level imports. Phase 3 (name_vault_attrs) also
rewrites attribute READS obj.attr -> _g(obj, "attr") reusing the bootstrap getattr _g, so the
attr-name string literal is pooled by ArchivePass; only ctx=Load is handled (Store/Del are later),
and decorator-position attributes (@a.b) are kept bare.

Note: builtins (and routed imports) are resolved EAGERLY at scope entry — registered once / hoisted
to the boot block — vs CPython's lazy per-use builtin lookup and in-place import. Equivalent for
normal code: imports are only routed when their bound name is bound exactly once, so nothing reads
the name before its single binding. It only diverges under an adversarial runtime that deletes a
standard builtin referenced on a never-taken path. `_BUILTIN_NAMES` is snapshotted from the build
interpreter, so build and target Python must be the same major version (already a project assumption).
"""
from __future__ import annotations

import ast
import builtins as _builtins
import random

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from ..attest import name_to_charcode_expr
from .flatten import FLATTEN_ALLOWED
from .dictindirect import _BindingScan

# Builtins we route, minus names that must stay lexical. `super` is excluded because CPython
# synthesizes the implicit `__class__` closure cell ONLY when it sees the bare textual name
# `super` in a method body; rewriting `super` -> _D[k] drops that cell and zero-arg `super()`
# raises RuntimeError. (Exhaustively checked: `super` is the sole builtin with this property.)
_NEVER_ROUTE = {"super"}
_BUILTIN_NAMES = {n for n in dir(_builtins) if not n.startswith("__")} - _NEVER_ROUTE


def _key_const(value: int) -> ast.Constant:
    """A vault-key Constant MARKED so ArchivePass leaves it INLINE (not pooled into the encrypted
    blob). The random dict keys are meant to be state-keyed by the flatten pass's key_consts
    (`enc - (state & mask)`), per this module's design (see header) — pooling them into the const
    archive wastes archive space AND defeats that state-keying. Only the integer KEYS are excluded;
    the NAME strings stay archived (they are the sensitive part)."""
    c = ast.Constant(value=value)
    c._pyobf_no_archive = True
    return c


def _decorator_exempt_ids(tree) -> set:
    """id()s of Name AND Attribute nodes in any decorator_list — these positions are kept lexical.
    Defensive on two fronts:
      - Names: routing a decorator @name -> @_D[k] requires PEP 614 (3.9+) and would obscure
        descriptor decorators like @property/@staticmethod for no real obfuscation gain.
      - Attributes: a decorator @a.b must NOT become @_g(a,"b") — same PEP-614 concern, and it
        would defeat descriptor decorators reached via attribute (e.g. @functools.wraps). Keeping
        @a.b bare is consistent with the Name exemption."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                for n in ast.walk(dec):
                    if isinstance(n, (ast.Name, ast.Attribute)):
                        out.add(id(n))
    return out


def _has_rewritable_attr_load(tree, exempt: set) -> bool:
    """True if the tree contains >=1 attribute READ (ctx=Load) not in a decorator position.
    Used to decide whether the vault bootstrap must be emitted for an attrs-only module."""
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and id(node) not in exempt):
            return True
    return False


def _is_attr_store_target(node) -> bool:
    """A single `ast.Attribute` Store target — the Assign/AnnAssign target form 3.2 rewrites."""
    return isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)


def _is_attr_del_target(node) -> bool:
    """A single `ast.Attribute` Del target — `del obj.attr` builds the Attribute with ctx=Del
    (NOT Store), so the delete form needs its own check distinct from the write form."""
    return isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Del)


def _has_rewritable_attr_store_del(tree) -> bool:
    """True if the tree contains >=1 attribute WRITE or DELETE that 3.2 rewrites (single-Attribute
    Assign target, AnnAssign-with-value Attribute target, or single-Attribute Delete target). Used so
    a module whose ONLY routable construct is a write/delete still gets the _bi/_g/_s/_dl bootstrap.
    Decorator positions never produce these forms (decorators are Load), so no exempt check needed."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and _is_attr_store_target(node.targets[0]):
                return True
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None and _is_attr_store_target(node.target):
                return True
        elif isinstance(node, ast.Delete):
            if len(node.targets) == 1 and _is_attr_del_target(node.targets[0]):
                return True
    return False


def _routable_imports(tree, bound, avoid):
    """Top-level single-alias imports safe to route via __import__.
    Returns (routed, drop_ids, preamble_names): routed = list of (bound_name, module_str);
    drop_ids = id()s of the ast.Import statements to remove from the module body; preamble_names =
    the subset of routed bound-names whose source Import carries `_pyobf_stack_preamble` (the
    StackCall pass-1 `import threading` infrastructure import). The post_vault StackCall pass must
    NOT route those registrations through the arg-stack (bootstrap-ordering hazard), so NameVault
    excludes them from the `_pyobf_stackroute` mark.

    Only forms where __import__(module_str) returns the object the import binds are routed:
      - `import X`            (dot-free)        -> bind X, __import__("X") == X.
      - `import X.Y.Z`        (dotted, no `as`) -> bind top X, __import__("X.Y.Z") == X.
      - `import X as C`       (dot-free + as)   -> bind C to X, __import__("X") == X.
    Skipped (left as a normal import):
      - `import X.Y as C`     (dotted + as): __import__("X.Y") returns X (top), NOT X.Y -> wrong.
      - `from ... import ...` (ImportFrom): different binding semantics.
      - multi-alias `import a, b` (len(names) != 1).
      - imports nested below the direct module body (conditional/scoped) -> avoid reordering.
      - bound name bound more than once in the whole tree (reassigned / re-imported).
      - bound name used in a decorator position (`avoid`) -> the decorator keeps the bare name
        (decorator positions are exempt from rewriting), so the binding would be lost when dropped.
    """
    if not isinstance(tree, ast.Module):
        return [], set(), set()
    routed, drop, preamble_names = [], set(), set()
    for stmt in tree.body:                       # DIRECT module body only (not nested)
        if not isinstance(stmt, ast.Import) or len(stmt.names) != 1:
            continue
        alias = stmt.names[0]
        mod = alias.name
        if alias.asname:
            if "." in mod:                       # dotted + as -> __import__(mod) != submodule; skip
                continue
            bn = alias.asname
        else:
            bn = mod.split(".")[0]
        if bound.get(bn, 0) != 1:                # reassigned / multiply-bound -> skip
            continue
        if bn in avoid:                          # used in a decorator (stays lexical) -> keep import
            continue
        routed.append((bn, mod))
        drop.add(id(stmt))
        if getattr(stmt, "_pyobf_stack_preamble", False):
            preamble_names.add(bn)               # StackCall infra import -> exclude from routing mark
    return routed, drop, preamble_names


class _BuiltinCollector(ast.NodeVisitor):
    def __init__(self, bound: dict, exempt: set):
        self.bound = bound
        self.exempt = exempt
        self.nodes = []      # Name(Load) nodes to route
        self.names = []      # unique builtin names, order-preserving
        self._seen = set()

    def visit_Name(self, node):
        if (isinstance(node.ctx, ast.Load) and id(node) not in self.exempt
                and node.id in _BUILTIN_NAMES and self.bound.get(node.id, 0) == 0):
            self.nodes.append(node)
            if node.id not in self._seen:
                self._seen.add(node.id)
                self.names.append(node.id)


class NameVaultPass:
    name = "namevault"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    @staticmethod
    def _build_boot(n_bi, n_g, n_vault, builtin_names, import_names, import_mod, key_of,
                    n_s=None, n_dl=None, used_setattr=False, used_delattr=False,
                    mark_route=False, mark_exclude=frozenset()):
        """Build the vault bootstrap statement list, in dependency order:
          _bi = __import__(<charcode 'builtins'>)        # root, charcode-hidden
          _g  = _bi.getattr                              # bootstrap getattr (also used by attrs)
          _s  = _bi.setattr                              # bootstrap setattr (only if attr WRITES used)
          _dl = _bi.delattr                              # bootstrap delattr (only if attr DELETES used)
          _D  = {}                                       # vault dict   (only if there are regs)
          _D[k] = _g(_bi, "<builtin>")  / __import__("<mod>")   # registrations
        `_g`/`_bi` are ALWAYS emitted (attribute READ rewriting reuses `_g`); `_s`/`_dl` only when the
        attribute write/delete rewrite actually emitted a setattr/delattr; the `_D` dict and its
        registrations are emitted only when there are builtins/imports to route. Built AFTER the
        user-tree rewrite so the bare `_bi.getattr`/`_bi.setattr`/`_bi.delattr` attributes here are
        themselves never rewritten (they would otherwise self-route to _g(_bi, "...") infinitely).

        `mark_route` (set only when call-hiding `hide_external_args` is active): tag the synthesized
        IMPORT REGISTRATION calls — `__import__("<mod>")` — with `_pyobf_stackroute = True`, the SAME
        marker seam ArchivePass uses on its `_get(...)` accessor. The SECOND (post_vault) StackCall
        pass then routes ONLY these marked registration calls (at their `_D[k] = __import__(...)`
        Assign-to-Subscript statement position) through the hidden push/invoke arg-stack, so the
        `__import__(...)` call no longer appears at the call site.

        Surgically safe: ONLY the `__import__(...)` registration call nodes built HERE are marked.
        Deliberately NOT marked (the safe subset):
          * the bootstrap `_bi = __import__('builtins')` — its arg-stack is not yet live at the
            registration site, and its arg is a charcode expr;
          * the getattr builtin registrations `_D[k] = _g(_bi, "<builtin>")` — routing these is the
            riskier case (the attribute-READ rewrites also emit `_g(obj, "attr")` calls including
            closures that share that shape, so the second pass is constrained to a no-op when the
            only marked candidates are vault getattr scaffold). They are left for a later phase;
            the builtin NAME is already hidden by the archive (`_g(_bi, _get(...))`), so the
            security delta of routing them is small.
        The attribute-READ rewrites' `_g(obj, "attr")` calls and the first pass's push-helper
        `_D[k](...)` vault call are DIFFERENT, unmarked node objects, so none of them is ever
        routed."""
        boot = [
            ast.Assign(targets=[ast.Name(id=n_bi, ctx=ast.Store())],
                       value=ast.Call(func=ast.Name(id="__import__", ctx=ast.Load()),
                                      args=[name_to_charcode_expr("builtins")], keywords=[])),
            ast.Assign(targets=[ast.Name(id=n_g, ctx=ast.Store())],
                       value=ast.Attribute(value=ast.Name(id=n_bi, ctx=ast.Load()),
                                           attr="getattr", ctx=ast.Load())),
        ]
        if used_setattr:
            boot.append(ast.Assign(targets=[ast.Name(id=n_s, ctx=ast.Store())],
                                   value=ast.Attribute(value=ast.Name(id=n_bi, ctx=ast.Load()),
                                                       attr="setattr", ctx=ast.Load())))
        if used_delattr:
            boot.append(ast.Assign(targets=[ast.Name(id=n_dl, ctx=ast.Store())],
                                   value=ast.Attribute(value=ast.Name(id=n_bi, ctx=ast.Load()),
                                                       attr="delattr", ctx=ast.Load())))
        if not builtin_names and not import_names:
            return boot  # attrs-only: no vault dict, just _bi/_g (+ _s/_dl if used)
        boot.append(ast.Assign(targets=[ast.Name(id=n_vault, ctx=ast.Store())],
                               value=ast.Dict(keys=[], values=[])))
        for nm in builtin_names:
            # Getattr builtin registrations are NOT marked (left for a later phase — see docstring).
            boot.append(ast.Assign(
                targets=[ast.Subscript(value=ast.Name(id=n_vault, ctx=ast.Load()),
                                       slice=_key_const(key_of[nm]), ctx=ast.Store())],
                value=ast.Call(func=ast.Name(id=n_g, ctx=ast.Load()),
                               args=[ast.Name(id=n_bi, ctx=ast.Load()), ast.Constant(value=nm)],
                               keywords=[])))
        for bn in import_names:
            # Import registration `_D[k] = __import__("<mod>")`: mark for post_vault routing when
            # call-hiding is on, so the bare `__import__(...)` call site is replaced by an invoke(...).
            # EXCLUDE names in `mark_exclude` — the StackCall pass-1 `import threading` infrastructure
            # import (routing the FIRST arg-stack's own backing import through the SECOND arg-stack is
            # a bootstrap-ordering hazard, and a routable-statement no-op invariant depends on it).
            reg = ast.Call(func=ast.Name(id="__import__", ctx=ast.Load()),
                           args=[ast.Constant(value=import_mod[bn])], keywords=[])
            if mark_route and bn not in mark_exclude:
                reg._pyobf_stackroute = True
            boot.append(ast.Assign(
                targets=[ast.Subscript(value=ast.Name(id=n_vault, ctx=ast.Load()),
                                       slice=_key_const(key_of[bn]), ctx=ast.Store())],
                value=reg))
        return boot

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.name_vault:
            return tree
        route_attrs = bool(options.name_vault_attrs)

        scan = _BindingScan()
        scan.visit(tree)
        bound = scan.bound_names
        exempt = _decorator_exempt_ids(tree)

        # --- What to route: builtins (bare names resolving to a builtin, not shadowed) ---
        col = _BuiltinCollector(bound, exempt)
        col.visit(tree)

        # --- What to route: simple top-level imports ---
        # Names occurring in a decorator position stay lexically bound (decorator positions are
        # exempt from rewriting), so an import bound to such a name must NOT be dropped.
        avoid = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and id(n) in exempt}
        imp_routed, imp_drop, imp_preamble = _routable_imports(tree, bound, avoid)
        import_names = [bn for bn, _ in imp_routed]
        import_mod = {bn: mod for bn, mod in imp_routed}

        # --- What to route: attribute READs obj.attr + WRITES/DELETES ---
        # The actual node selection happens in _Rw; here we only need to know whether ANY rewritable
        # attribute exists, to decide if the bootstrap must be emitted. A module whose only routable
        # construct is an attribute write/delete (no Load, no builtin, no import) still needs the
        # _bi/_g (and _s/_dl) scaffold, so check Store/Del too.
        has_attr = route_attrs and (_has_rewritable_attr_load(tree, exempt)
                                    or _has_rewritable_attr_store_del(tree))

        if not col.names and not import_names and not has_attr:
            return tree  # nothing routable -> no scaffold, no-op

        # Load occurrences of routed import names (exempt decorator positions).
        imp_name_set = set(import_names)
        imp_nodes = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                     and n.id in imp_name_set and id(n) not in exempt]

        seed = options.seed if options.seed is not None else 0
        rng = random.Random(seed ^ 0x5A17BEE)
        namer = Namer(seed, collect_names(tree))
        n_bi, n_g, n_vault = namer.fresh("bi"), namer.fresh("g"), namer.fresh("D")
        # setattr/delattr helper names are minted unconditionally (cheap; keeps the name pool stable);
        # the bindings are only EMITTED if the rewrite actually uses them (used_setattr/used_delattr).
        n_s, n_dl = namer.fresh("s"), namer.fresh("dl")

        # One key map covering BOTH builtin names and import bound names (keyed by name).
        # builtin and import name sets are disjoint: import bound names are in `bound`, so the
        # builtin collector skips them (it requires bound==0) -> no name collides across the two.
        key_of, used = {}, set()
        for nm in list(col.names) + import_names:
            while True:
                k = rng.randrange(1, 1 << 31)
                if k not in used:
                    used.add(k); key_of[nm] = k; break

        route_ids = {id(n) for n in col.nodes} | {id(n) for n in imp_nodes}

        class _Rw(ast.NodeTransformer):
            def __init__(self):
                # Set when an attribute write/delete is actually rewritten, so the boot block knows
                # whether to emit the `_s = _bi.setattr` / `_dl = _bi.delattr` bindings.
                self.used_setattr = False
                self.used_delattr = False

            def visit_Name(self, node):
                if id(node) in route_ids:
                    return ast.copy_location(ast.Subscript(
                        value=ast.Name(id=n_vault, ctx=ast.Load()),
                        slice=_key_const(key_of[node.id]), ctx=ast.Load()), node)
                return node

            def visit_Attribute(self, node):
                # Rewrite only attribute READS, and never a decorator-position attribute.
                if not (route_attrs and isinstance(node.ctx, ast.Load) and id(node) not in exempt):
                    self.generic_visit(node)   # Store/Del/exempt: recurse, keep node shape
                    return node
                # Rewrite the value subtree FIRST (bottom-up): handles nested a.b.c and a value
                # that is itself a routed builtin/import Name -> _g(_D[k], "attr"). Then wrap.
                self.generic_visit(node)
                return ast.copy_location(ast.Call(
                    func=ast.Name(id=n_g, ctx=ast.Load()),
                    args=[node.value, ast.Constant(value=node.attr)], keywords=[]), node)

            def _rewrite_attr_store(self, obj, attr, value, anchor):
                """Build `[_t = <value>; _s(<obj>, "attr", _t)]` preserving eval order.
                Python evaluates an assignment's RHS BEFORE its target object; a naive
                `_s(obj, "attr", value)` would instead evaluate `obj` first. The temp `_t = value`
                forces value-first, then `_s` evaluates `obj`. `obj`/`value` are the ALREADY
                Load-rewritten subtrees (generic_visit ran on the parent before this is called).
                A fresh temp name per call avoids clobbering across multiple writes."""
                self.used_setattr = True
                t = namer.fresh("t")
                assign = ast.Assign(targets=[ast.Name(id=t, ctx=ast.Store())], value=value)
                call = ast.Expr(value=ast.Call(
                    func=ast.Name(id=n_s, ctx=ast.Load()),
                    args=[obj, ast.Constant(value=attr), ast.Name(id=t, ctx=ast.Load())],
                    keywords=[]))
                return [ast.copy_location(assign, anchor), ast.copy_location(call, anchor)]

            def visit_Assign(self, node):
                # Rewrite the value + the target's `.value` Load parts first (3.1 getattr routing).
                self.generic_visit(node)
                if (route_attrs and len(node.targets) == 1
                        and _is_attr_store_target(node.targets[0])):
                    tgt = node.targets[0]
                    return self._rewrite_attr_store(tgt.value, tgt.attr, node.value, node)
                return node   # multi-target / tuple / Name / Subscript targets: leave as-is

            def visit_AnnAssign(self, node):
                self.generic_visit(node)
                # `obj.attr: T = value` -> `_t = value; _s(obj,"attr",_t)` (annotation dropped; it is
                # not evaluated for an attribute target beyond the value assignment). Bare annotation
                # `obj.attr: T` (value is None) is a runtime no-op -> leave untouched.
                if (route_attrs and node.value is not None
                        and _is_attr_store_target(node.target)):
                    return self._rewrite_attr_store(node.target.value, node.target.attr,
                                                    node.value, node)
                return node

            def visit_Delete(self, node):
                self.generic_visit(node)
                # `del obj.attr` -> `_dl(obj, "attr")` (single object eval, no eval-order subtlety).
                # Multi-target `del a.x, b.y` and non-Attribute targets are left untouched.
                if (route_attrs and len(node.targets) == 1
                        and _is_attr_del_target(node.targets[0])):
                    tgt = node.targets[0]
                    self.used_delattr = True
                    return ast.copy_location(ast.Expr(value=ast.Call(
                        func=ast.Name(id=n_dl, ctx=ast.Load()),
                        args=[tgt.value, ast.Constant(value=tgt.attr)], keywords=[])), node)
                return node

        _rw = _Rw()
        tree = _rw.visit(tree)

        # Bootstrap + registrations are built AFTER the rewrite, so the bare `_bi.getattr` /
        # `_bi.setattr` / `_bi.delattr` attributes inside the bootstrap are themselves never
        # rewritten. ArchivePass (runs after) pools the literal attr-name / module-name /
        # builtin-name strings into the encrypted blob. `_s`/`_dl` are emitted only if actually used.
        # `mark_route` is gated on the SAME `hide_external_args` flag as the StackCall passes: when
        # call-hiding is on, tag the synthesized registration calls so the post_vault StackCall pass
        # routes them through the hidden arg-stack (the bootstrap is left unmarked — see _build_boot).
        boot = self._build_boot(n_bi, n_g, n_vault, col.names, import_names, import_mod, key_of,
                                n_s, n_dl, _rw.used_setattr, _rw.used_delattr,
                                mark_route=bool(options.hide_external_args),
                                mark_exclude=imp_preamble)

        # Remove the handled `import` statements. _Rw returns Import stmts unchanged (same object
        # ids), so imp_drop ids remain valid. Filter AFTER the rewrite, BEFORE splicing boot.
        if imp_drop:
            tree.body = [s for s in tree.body if id(s) not in imp_drop]

        body = tree.body if isinstance(tree, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if body is not None:
            pos = 0
            while pos < len(body) and (
                (isinstance(body[pos], ast.Expr) and isinstance(body[pos].value, ast.Constant)
                 and isinstance(body[pos].value.value, str))
                or (isinstance(body[pos], ast.ImportFrom) and body[pos].module == "__future__")):
                pos += 1
            body[pos:pos] = boot
        ast.fix_missing_locations(tree)
        return tree
