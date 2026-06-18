from __future__ import annotations

import ast

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from .flatten import FLATTEN_ALLOWED


def _resolve_call(call: ast.Call, params: list) -> list | None:
    """Positional value-expr list for `call` against `params` (param-name list), or None if the
    call is not safely resolvable in order (extra/missing/out-of-order kwargs, * / ** unpack)."""
    if any(isinstance(a, ast.Starred) for a in call.args):
        return None
    if len(call.args) > len(params):
        return None
    vals = list(call.args)                       # positionals fill the first params
    rest = params[len(call.args):]
    kw = {k.arg: k.value for k in call.keywords}
    if any(k.arg is None for k in call.keywords):  # **kwargs unpack
        return None
    # keywords must name exactly the remaining params, in order
    if [k.arg for k in call.keywords] != rest:
        return None
    if set(kw) != set(rest):
        return None
    vals += [kw[name] for name in rest]
    return vals if len(vals) == len(params) else None


def _simple_params(fn: ast.FunctionDef):
    a = fn.args
    if a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg or a.defaults or a.kw_defaults:
        return None
    return [arg.arg for arg in a.args]


class _Scan(ast.NodeVisitor):
    """Collect, per function name: its defs, whether it is nested, and whether the name is ever
    used as a non-call value (which disqualifies it)."""
    def __init__(self):
        self.defs = {}          # name -> list[(FunctionDef, nested_bool)]
        self.value_use = set()  # names used as a value (not a direct call func)
        self.bound_other = set()  # names assigned / global / nonlocal / etc.
        self.methods = set()    # functions defined DIRECTLY in a class body (invoked via descriptor)
        self._fn_depth = 0

    def visit_FunctionDef(self, node):
        self.defs.setdefault(node.name, []).append((node, self._fn_depth > 0))
        self._fn_depth += 1
        self.generic_visit(node)
        self._fn_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        # functions defined directly in the class body are methods/staticmethods/properties —
        # they are invoked via attribute/descriptor protocol (obj.m(), Cls.m(), property get),
        # NEVER via a bare `m(...)` call, so their calling convention must NOT be stack-routed.
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.methods.add(stmt.name)
        self._fn_depth += 1
        self.generic_visit(node)
        self._fn_depth -= 1

    def visit_Call(self, node):
        # the call's own func Name is OK as a direct call; visit args/keywords normally
        if isinstance(node.func, ast.Name):
            for a in node.args:
                self.visit(a)
            for k in node.keywords:
                self.visit(k.value)
        else:
            self.generic_visit(node)

    def visit_Name(self, node):
        # any Name reached here (not via the direct-call shortcut) is a value use
        self.value_use.add(node.id)

    def visit_Assign(self, node):
        for t in node.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    self.bound_other.add(n.id)
        self.visit(node.value)

    def visit_AugAssign(self, node):
        for n in ast.walk(node.target):
            if isinstance(n, ast.Name):
                self.bound_other.add(n.id)
        self.visit(node.value)

    def visit_Global(self, node):
        self.bound_other.update(node.names)

    def visit_Nonlocal(self, node):
        self.bound_other.update(node.names)


def _eligible(tree) -> dict:
    """name -> param-list for each eligible function."""
    scan = _Scan()
    scan.visit(tree)
    elig = {}
    for name, defs in scan.defs.items():
        if len(defs) != 1:
            continue
        fn, nested = defs[0]
        if name in scan.methods:
            continue  # class methods are descriptor-invoked, not bare-name callable
        if isinstance(fn, ast.AsyncFunctionDef):
            continue
        params = _simple_params(fn)
        if params is None:
            continue
        if not (nested or name.startswith("_")):
            continue
        if name in scan.value_use or name in scan.bound_other:
            continue
        # every call site must resolve in order
        ok = True
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == name):
                if _resolve_call(node, params) is None:
                    ok = False
                    break
        if ok:
            elig[name] = params
    return elig


def _build_preamble(thmod: str, tls: str, push: str, pop: str, invoke: str) -> list:
    """Build the threading.local helper preamble as AST nodes.

    Equivalent source:
        import threading as <thmod>
        <tls> = <thmod>.local()
        def <push>(v):
            s = getattr(<tls>, "s", None)
            if s is None:
                s = []
                <tls>.s = s
            s.append(v)
        def <pop>():
            return <tls>.s.pop()
        def <invoke>(n):
            s = <tls>.s
            args = [s.pop() for _ in range(n)]
            args.reverse()
            fn = s.pop()
            return fn(*args)
    """
    # import threading as <thmod>
    import_node = ast.Import(names=[ast.alias(name="threading", asname=thmod)])
    # Tag this preamble import: it is StackCall infrastructure (backs the arg-stack `tls`), NOT a
    # user import. If NameVault later routes it into the vault (`_D[k] = __import__("threading")`),
    # the post_vault pass must NOT route THAT registration through the arg-stack — doing so would
    # make the FIRST arg-stack's own `threading` depend on the SECOND arg-stack at module-init time
    # (a bootstrap-ordering hazard). NameVault propagates this tag to exclude the name from marking.
    import_node._pyobf_stack_preamble = True

    # <tls> = <thmod>.local()
    tls_assign = ast.Assign(
        targets=[ast.Name(id=tls, ctx=ast.Store())],
        value=ast.Call(
            func=ast.Attribute(value=ast.Name(id=thmod, ctx=ast.Load()), attr="local", ctx=ast.Load()),
            args=[], keywords=[]))

    # def <push>(v):
    #     s = getattr(<tls>, "s", None)
    #     if s is None:
    #         s = []
    #         <tls>.s = s
    #     s.append(v)
    push_def = ast.FunctionDef(
        name=push,
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="v")], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=[
            # s = getattr(<tls>, "s", None)
            ast.Assign(
                targets=[ast.Name(id="s", ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="getattr", ctx=ast.Load()),
                    args=[ast.Name(id=tls, ctx=ast.Load()),
                          ast.Constant(value="s"),
                          ast.Constant(value=None)],
                    keywords=[])),
            # if s is None:
            #     s = []
            #     <tls>.s = s
            ast.If(
                test=ast.Compare(
                    left=ast.Name(id="s", ctx=ast.Load()),
                    ops=[ast.Is()],
                    comparators=[ast.Constant(value=None)]),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id="s", ctx=ast.Store())],
                        value=ast.List(elts=[], ctx=ast.Load())),
                    ast.Assign(
                        targets=[ast.Attribute(value=ast.Name(id=tls, ctx=ast.Load()),
                                               attr="s", ctx=ast.Store())],
                        value=ast.Name(id="s", ctx=ast.Load())),
                ],
                orelse=[]),
            # s.append(v)
            ast.Expr(value=ast.Call(
                func=ast.Attribute(value=ast.Name(id="s", ctx=ast.Load()),
                                   attr="append", ctx=ast.Load()),
                args=[ast.Name(id="v", ctx=ast.Load())],
                keywords=[])),
        ],
        decorator_list=[],
        returns=None)

    # def <pop>():
    #     return <tls>.s.pop()
    pop_def = ast.FunctionDef(
        name=pop,
        args=ast.arguments(posonlyargs=[], args=[], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=[
            ast.Return(value=ast.Call(
                func=ast.Attribute(
                    value=ast.Attribute(value=ast.Name(id=tls, ctx=ast.Load()),
                                        attr="s", ctx=ast.Load()),
                    attr="pop", ctx=ast.Load()),
                args=[], keywords=[])),
        ],
        decorator_list=[],
        returns=None)

    # def <invoke>(n):
    #     s = <tls>.s
    #     args = [s.pop() for _ in range(n)]
    #     args.reverse()
    #     fn = s.pop()
    #     return fn(*args)
    invoke_def = ast.FunctionDef(
        name=invoke,
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="n")], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=[
            # s = <tls>.s
            ast.Assign(
                targets=[ast.Name(id="s", ctx=ast.Store())],
                value=ast.Attribute(value=ast.Name(id=tls, ctx=ast.Load()),
                                    attr="s", ctx=ast.Load())),
            # args = [s.pop() for _ in range(n)]
            ast.Assign(
                targets=[ast.Name(id="args", ctx=ast.Store())],
                value=ast.ListComp(
                    elt=ast.Call(
                        func=ast.Attribute(value=ast.Name(id="s", ctx=ast.Load()),
                                           attr="pop", ctx=ast.Load()),
                        args=[], keywords=[]),
                    generators=[ast.comprehension(
                        target=ast.Name(id="_", ctx=ast.Store()),
                        iter=ast.Call(
                            func=ast.Name(id="range", ctx=ast.Load()),
                            args=[ast.Name(id="n", ctx=ast.Load())],
                            keywords=[]),
                        ifs=[],
                        is_async=0)])),
            # args.reverse()
            ast.Expr(value=ast.Call(
                func=ast.Attribute(value=ast.Name(id="args", ctx=ast.Load()),
                                   attr="reverse", ctx=ast.Load()),
                args=[], keywords=[])),
            # fn = s.pop()
            ast.Assign(
                targets=[ast.Name(id="fn", ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id="s", ctx=ast.Load()),
                                       attr="pop", ctx=ast.Load()),
                    args=[], keywords=[])),
            # return fn(*args)
            ast.Return(value=ast.Call(
                func=ast.Name(id="fn", ctx=ast.Load()),
                args=[ast.Starred(value=ast.Name(id="args", ctx=ast.Load()), ctx=ast.Load())],
                keywords=[])),
        ],
        decorator_list=[],
        returns=None)

    # At injection: rename the helpers' literal params/locals (v/n/s/args/fn/_) to fresh obfuscator
    # names; the free `<tls>` and builtins are left intact (scope-aware). Runs before FlattenPass.
    from .localrename import rename_simple_helper_locals
    rename_simple_helper_locals(ast.Module(body=[push_def, pop_def, invoke_def], type_ignores=[]))
    return [import_node, tls_assign, push_def, pop_def, invoke_def]


def _marker():
    """Return a bare Ellipsis expression-statement used as a block-boundary marker."""
    return ast.Expr(value=ast.Constant(value=Ellipsis))


class _Rewriter(ast.NodeTransformer):
    def __init__(self, push: str, pop: str, invoke: str, elig: dict, hide_external: bool, split: bool = False):
        self.push = push
        self.pop = pop
        self.invoke = invoke
        self.elig = elig
        self.hide_external = hide_external
        self.split = split
        self.rewrote = False
        self._no_external = False  # reentrant guard: True inside decorators/defaults/annotations

    def _push_call(self, val_node: ast.expr) -> ast.expr:
        """<push>(val_node)"""
        return ast.Call(
            func=ast.Name(id=self.push, ctx=ast.Load()),
            args=[val_node], keywords=[])

    def _pop_call(self) -> ast.expr:
        """<pop>()"""
        return ast.Call(
            func=ast.Name(id=self.pop, ctx=ast.Load()),
            args=[], keywords=[])

    def _invoke_call(self, n: int) -> ast.expr:
        """<invoke>(n)"""
        return ast.Call(
            func=ast.Name(id=self.invoke, ctx=ast.Load()),
            args=[ast.Constant(value=n)], keywords=[])

    def _visit_no_external(self, node: ast.AST) -> ast.AST:
        """Visit a subtree with external-routing disabled."""
        old = self._no_external
        self._no_external = True
        result = self.visit(node)
        self._no_external = old
        return result

    def _visit_list_no_external(self, nodes: list) -> list:
        """Visit a list of nodes with external-routing disabled."""
        old = self._no_external
        self._no_external = True
        result = [self.visit(n) for n in nodes]
        self._no_external = old
        return result

    def visit_FunctionDef(self, node):
        # Visit decorator_list, defaults/kw_defaults, annotations with external routing DISABLED.
        # Visit body normally (with external routing enabled).

        # 1. Visit decorators with external routing off
        node.decorator_list = self._visit_list_no_external(node.decorator_list)

        # 2. Visit argument defaults/kw_defaults/annotations with external routing off
        args = node.args
        args.defaults = self._visit_list_no_external(args.defaults)
        args.kw_defaults = [self._visit_no_external(d) if d is not None else None
                             for d in args.kw_defaults]
        # Visit argument annotations
        for arg in args.posonlyargs + args.args + args.kwonlyargs:
            if arg.annotation is not None:
                arg.annotation = self._visit_no_external(arg.annotation)
        if args.vararg and args.vararg.annotation:
            args.vararg.annotation = self._visit_no_external(args.vararg.annotation)
        if args.kwarg and args.kwarg.annotation:
            args.kwarg.annotation = self._visit_no_external(args.kwarg.annotation)
        # Visit return annotation
        if node.returns is not None:
            node.returns = self._visit_no_external(node.returns)

        # 3. Visit body normally
        node.body = [self.visit(stmt) for stmt in node.body]

        # 4. Rewrite internal eligible def: replace params with pop() calls
        if node.name in self.elig:
            params = self.elig[node.name]
            pops = [ast.Assign(
                        targets=[ast.Name(id=p, ctx=ast.Store())],
                        value=self._pop_call())
                    for p in reversed(params)]
            node.args = ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                                      kw_defaults=[], kwarg=None, defaults=[])
            body = node.body
            head = []
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                head = [body[0]]; body = body[1:]
            # When split mode is on and there are >=2 pops, interleave markers between them
            if self.split and len(pops) >= 2:
                interleaved = []
                for i, p in enumerate(pops):
                    interleaved.append(p)
                    if i != len(pops) - 1:
                        interleaved.append(_marker())
                pops = interleaved
            node.body = head + pops + body
            self.rewrote = True

        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        # Visit decorator_list with external routing off; visit body normally
        node.decorator_list = self._visit_list_no_external(node.decorator_list)
        # Visit bases/keywords normally (they're runtime expressions, fair game)
        node.bases = [self.visit(b) for b in node.bases]
        node.keywords = [self.visit(k) for k in node.keywords]
        node.body = [self.visit(stmt) for stmt in node.body]
        return node

    def visit_Call(self, node):
        self.generic_visit(node)  # rewrite nested calls first (bottom-up)

        # --- Internal eligible call ---
        if isinstance(node.func, ast.Name) and node.func.id in self.elig:
            vals = _resolve_call(node, self.elig[node.func.id])
            if vals is not None:
                pushes = [self._push_call(v) for v in vals]
                bare = ast.Call(func=ast.Name(id=node.func.id, ctx=ast.Load()), args=[], keywords=[])
                tup = ast.Tuple(elts=pushes + [bare], ctx=ast.Load())
                self.rewrote = True
                sub = ast.Subscript(value=tup, slice=ast.Constant(value=-1), ctx=ast.Load())
                sub._pyobf_pushn = len(pushes)  # number of push elements (for split_calls)
                return sub

        # --- External routing (only if hide_external is on and not in guard zone) ---
        if self.hide_external and not self._no_external:
            func = node.func
            # func must be a Name NOT in elig, OR an Attribute
            is_external_name = (isinstance(func, ast.Name) and func.id not in self.elig)
            is_attribute = isinstance(func, ast.Attribute)
            if is_external_name or is_attribute:
                # Must have >=1 positional arg, no keywords, no Starred
                n = len(node.args)
                if (n >= 1
                        and not node.keywords
                        and not any(isinstance(a, ast.Starred) for a in node.args)):
                    # Push func first, then args left-to-right, then invoke(n)
                    elts = ([self._push_call(func)]
                            + [self._push_call(a) for a in node.args]
                            + [self._invoke_call(n)])
                    tup = ast.Tuple(elts=elts, ctx=ast.Load())
                    self.rewrote = True
                    sub = ast.Subscript(value=tup, slice=ast.Constant(value=-1), ctx=ast.Load())
                    sub._pyobf_pushn = len(elts) - 1  # number of push elements (len(elts)-1, last is invoke)
                    return sub

        return node


class _StmtSplitter(ast.NodeTransformer):
    """Post-rewrite pass: expand splittable hidden-call statements into push/marker/call sequences.

    A statement is splittable when its VALUE is a tagged hidden-call Subscript
    (_pyobf_pushn >= 1) AND the statement is Expr / Assign-to-single-Name / Return.
    Calls nested in larger expressions or conditions are NOT split.
    """

    def _split_value(self, v, stmt):
        """If `v` is a splittable hidden-call Subscript, expand and return the list; else None.

        Threshold is `_pyobf_pushn >= 1` so SINGLE-push/single-arg calls split too (flat cuttable
        form is the default for hidden calls). For n==1 this emits `push; <marker>; res=call`."""
        if not (isinstance(v, ast.Subscript) and getattr(v, "_pyobf_pushn", 0) >= 1
                and isinstance(v.value, ast.Tuple)):
            return None
        elts = v.value.elts
        pushes = elts[:-1]
        call = elts[-1]
        out = []
        for pe in pushes:
            out.append(ast.Expr(value=pe))
            out.append(_marker())
        # rebuild the final statement with just the call value
        if isinstance(stmt, ast.Expr):
            out.append(ast.Expr(value=call))
        elif isinstance(stmt, ast.Assign):
            out.append(ast.Assign(targets=stmt.targets, value=call))
        elif isinstance(stmt, ast.Return):
            out.append(ast.Return(value=call))
        else:
            return None
        return out

    def visit_Expr(self, node):
        self.generic_visit(node)
        result = self._split_value(node.value, node)
        return result if result is not None else node

    def visit_Assign(self, node):
        self.generic_visit(node)
        if not (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            return node
        result = self._split_value(node.value, node)
        return result if result is not None else node

    def visit_Return(self, node):
        self.generic_visit(node)
        if node.value is None:
            return node
        result = self._split_value(node.value, node)
        return result if result is not None else node


def _is_routable_marked_call(node: ast.expr) -> bool:
    """True if `node` is a CALL the second (post_vault) pass should route: it carries the
    `_pyobf_stackroute` marker AND it passes the usual arg guards (>=1 positional arg, no keywords,
    no `*args`/`**kw`). The marker is the ONLY eligibility signal — bare Name/Attribute calls are the
    FIRST StackCall's job (it already ran), so the second pass never touches a helper-internal
    `pow`/`range`/`getattr`/`int.from_bytes`/`.join` call (all unmarked Name/Attribute calls).

    Marked call sites (the only things routed here):
      * ArchivePass `_get(off,sz,c,cast)` accessor calls (the const-archive literal sites);
      * NameVault IMPORT-REGISTRATION calls — `_D[k] = __import__("<mod>")` — the top-level scaffold
        assignments that register a routed import. Tagged in NameVault._build_boot when
        `hide_external_args` is on (only the safe `__import__` subset is marked, see below).

    NOT marked (deliberately excluded from routing):
      * vault `_D[k](...)` CALLS (the vault dict used as a callable) — routing them would corrupt
        the helper that uses the vault internally;
      * getattr builtin registrations `_D[k] = _g(_bi, "<builtin>")` — the attribute-READ rewrites
        also emit `_g(obj, "attr")` calls, and routing the getattr scaffold is a riskier later-phase
        change;
      * the bootstrap `_bi = __import__('builtins')` — its arg-stack is not yet live at the
        registration site.
    The archive `_get(...)` accessor has no helper hazard: it is created AFTER NameVault, never
    appears as a bare statement value inside any helper (only nested as a call argument)."""
    if not isinstance(node, ast.Call):
        return False
    if not getattr(node, "_pyobf_stackroute", False):
        return False
    return (len(node.args) >= 1
            and not node.keywords
            and not any(isinstance(a, ast.Starred) for a in node.args))


class _PostVaultRewriter(ast.NodeTransformer):
    """Second-pass STATEMENT-LEVEL router for the marked const-archive `_get(...)` accessor sites
    and the marked NameVault vault-registration calls.

    Unlike the first StackCall's `_Rewriter` (which routes bundled calls anywhere via `visit_Call`),
    this rewriter ONLY touches a marked routable call when it is the DIRECT value of a top-level
    `Expr` / `Assign`-to-single-`Name` / `Assign`-to-single-`Subscript` / `Return` statement. It
    rewrites that value into the same `(push(func), push(arg), ..., invoke(n))[-1]` tagged Subscript
    the first pass emits, so the shared `_StmtSplitter` then flattens it into push/marker/.../call
    statements.

    The `Assign`-to-`Subscript` shape exists precisely for the vault IMPORT registration
    `_D[k] = __import__(...)`: the assignment TARGET is a `_D[k]` Subscript, and the marked CALL is
    the RHS value. Routing the RHS replaces the bare `__import__(...)` call with an `invoke(...)`
    (func + arg pushed), so the call site no longer exposes the `__import__` call. (The getattr
    registrations `_D[k] = _g(_bi, ...)` are unmarked and so flow through untouched.)

    Why statement-level only: every marked `_get(...)` call that lives INSIDE a helper body (the
    archive `_ks`/`_kdf`/`_get` helpers, the dataobf `_dec` helper, the first pass's push/pop/invoke
    helpers whose string literals Archive pooled) is ALWAYS nested inside another expression —
    never the bare value of one of these statement shapes. Restricting to statement values therefore
    provably never descends into a helper body, so helper internals stay byte-identical. The vault
    registrations ARE such statement values (top-level scaffold), so they are routed; the bootstrap
    `_bi = __import__('builtins')` is unmarked and so is skipped even though it is an Assign-to-Name
    statement value. Nested user calls also stay bundled — same limitation as the first pass's
    splitter."""

    def __init__(self, push: str, invoke: str):
        self.push = push
        self.invoke = invoke
        self.rewrote = False

    def _bundle(self, call: ast.Call) -> ast.expr:
        """Build the `(push(func), push(arg)..., invoke(n))[-1]` tagged Subscript for `call`."""
        n = len(call.args)
        elts = ([ast.Call(func=ast.Name(id=self.push, ctx=ast.Load()),
                          args=[call.func], keywords=[])]
                + [ast.Call(func=ast.Name(id=self.push, ctx=ast.Load()),
                            args=[a], keywords=[]) for a in call.args]
                + [ast.Call(func=ast.Name(id=self.invoke, ctx=ast.Load()),
                            args=[ast.Constant(value=n)], keywords=[])])
        tup = ast.Tuple(elts=elts, ctx=ast.Load())
        sub = ast.Subscript(value=tup, slice=ast.Constant(value=-1), ctx=ast.Load())
        sub._pyobf_pushn = len(elts) - 1   # push count (last elt is invoke) — drives _StmtSplitter
        self.rewrote = True
        return ast.copy_location(sub, call)

    def _maybe(self, value):
        """Return the bundled Subscript if `value` is a routable marked call, else None.
        NOTE: does NOT recurse — only the DIRECT statement value is considered (nested marked calls,
        i.e. all helper/boot ones, are deliberately left untouched)."""
        return self._bundle(value) if _is_routable_marked_call(value) else None

    def visit_Expr(self, node):
        new = self._maybe(node.value)
        if new is not None:
            node.value = new
        return node

    def visit_Assign(self, node):
        # Route the RHS of a single-target Assign to a Name (`x = <marked call>`) OR to a Subscript
        # (`_D[k] = <marked call>`, the vault registration form). Both are top-level scaffold
        # statement values; only a marked RHS call is touched (see _is_routable_marked_call).
        if len(node.targets) == 1 and isinstance(node.targets[0], (ast.Name, ast.Subscript)):
            new = self._maybe(node.value)
            if new is not None:
                node.value = new
        return node

    def visit_Return(self, node):
        if node.value is not None:
            new = self._maybe(node.value)
            if new is not None:
                node.value = new
        return node


class StackCallPass:
    name = "stackcall"

    def __init__(self, phase: str = "main"):
        # phase="main"  -> the original behavior (internal + bare external routing, first pass).
        # phase="post_vault" -> the SECOND, targeted pass: route ONLY the marked vault/archive call
        #   sites (statement-level), inject its OWN fresh preamble, never touch helper internals.
        self.phase = phase

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if self.phase == "post_vault":
            return self._transform_post_vault(tree, options)

        if not options.stack_calls and not options.hide_external_args:
            return tree

        # Compute eligible internal functions (only when stack_calls is on)
        elig = _eligible(tree) if options.stack_calls else {}

        namer = Namer(options.seed, collect_names(tree))
        thmod = namer.fresh("th")
        tls = namer.fresh("tls")
        push = namer.fresh("push")
        pop = namer.fresh("pop")
        invoke = namer.fresh("invoke")

        # `split_calls` drives the callee-side pop interleaving (markers between `param = pop()`
        # statements in an eligible def body). Kept opt-in for back-compat.
        split = options.split_calls
        rewriter = _Rewriter(push=push, pop=pop, invoke=invoke,
                             elig=elig, hide_external=options.hide_external_args,
                             split=split)
        rewriter.visit(tree)

            # The flat, cuttable call form is the DEFAULT for hidden calls. Run the
        # call-site splitter whenever call-hiding is active (NOT gated on split_calls), so call
        # arguments scatter into separate push/marker/call statements (and thus across dispatcher
        # blocks). `split_calls` is now effectively an alias that additionally interleaves the
        # callee-side pops; the call-site splitting happens regardless.
        if rewriter.rewrote and (options.stack_calls or options.hide_external_args):
            _StmtSplitter().visit(tree)

        # Only inject preamble if at least one rewrite happened
        if not rewriter.rewrote:
            return tree

        # Build the preamble AFTER the rewrite pass so helpers' own .append/.pop/fn(*args)
        # are NOT themselves rewritten (avoids infinite recursion under hide_external_args).
        preamble = _build_preamble(thmod, tls, push, pop, invoke)
        if not self._inject_preamble(tree, preamble):
            return tree
        ast.fix_missing_locations(tree)
        return tree

    @staticmethod
    def _inject_preamble(tree, preamble) -> bool:
        """Splice `preamble` into the module/function body after any docstring + __future__ imports.
        Returns False (no-op) for a tree shape that has no spliceable body."""
        if isinstance(tree, (ast.Module, ast.FunctionDef)):
            body = tree.body
        else:
            return False
        pos = 0
        while pos < len(body) and (
            (isinstance(body[pos], ast.Expr) and isinstance(body[pos].value, ast.Constant)
             and isinstance(body[pos].value.value, str))
            or (isinstance(body[pos], ast.ImportFrom) and body[pos].module == "__future__")):
            pos += 1
        for node in reversed(preamble):
            body.insert(pos, node)
        return True

    def _transform_post_vault(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        """SECOND, targeted external-routing pass (runs AFTER DataObf, BEFORE Flatten).

        Gated on the SAME `hide_external_args` flag as the first pass — only active when arg-hiding
        is requested. Routes ONLY the marked vault/archive call sites (the `_get(...)` accessor
        ArchivePass marks, and vault `_D[k](...)` calls NameVault tags) and ONLY at top-level
        Expr/Assign-to-Name/Return statement positions, so it provably never rewrites a helper-
        internal or boot call (those marked calls are always nested in another expression). It
        injects its OWN fresh push/pop/invoke preamble and reuses `_StmtSplitter` for the flat,
        cuttable push/marker/.../invoke form."""
        if not options.hide_external_args:
            return tree  # inert unless arg-hiding is requested (mirrors the first pass's gate)

        namer = Namer(options.seed, collect_names(tree))
        thmod = namer.fresh("th")
        tls = namer.fresh("tls")
        push = namer.fresh("push")
        pop = namer.fresh("pop")
        invoke = namer.fresh("invoke")

        rewriter = _PostVaultRewriter(push=push, invoke=invoke)
        rewriter.visit(tree)
        if not rewriter.rewrote:
            return tree  # nothing marked at a routable statement position -> no preamble, no-op

        # Flatten the bundled `(push,...,invoke)[-1]` Subscripts into push/marker/.../call statements.
        # Because the rewriter only wraps DIRECT statement values, every bundled node here is
        # statement-eligible and is fully expanded (no bundled form survives -> helpers untouched).
        _StmtSplitter().visit(tree)

        # Fresh preamble built AFTER the rewrite so its own getattr/append/pop/fn(*args) are never
        # re-routed (and it never could be: this pass only routes marked statement values).
        preamble = _build_preamble(thmod, tls, push, pop, invoke)
        if not self._inject_preamble(tree, preamble):
            return tree
        ast.fix_missing_locations(tree)
        return tree
