from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .names import Namer
from .diagnostics import Diagnostic, UnsupportedConstructError

_GOTO, _RET, _RAISE = 0, 1, 2  # full-flatten finally continuation action tags


# ---- terminators ---------------------------------------------------------
@dataclass
class Goto:
    target: int


@dataclass
class CondGoto:
    test: ast.expr
    then: int
    orelse: int


@dataclass
class Ret:
    value: ast.expr | None


@dataclass
class RaiseTerm:
    exc: ast.expr | None   # None => bare re-raise (raise _exc)
    cause: ast.expr | None


@dataclass
class HandlerDispatch:
    handlers: list  # [(type_expr_or_None, handler_state_id), ...]


@dataclass
class SubExit:
    """Normal completion of a sub-region dispatcher (try/finally hybrid): render as
    `break` so control leaves the nested `while True` and the enclosing REAL
    try/finally statement completes (then the parent dispatcher resumes). This is NOT
    a function return — `Ret` still renders a real `return` so CPython runs finally."""


@dataclass
class PopK:
    """Finally-body exit (full-flatten): pop the _k continuation and perform its action."""


@dataclass
class Block:
    id: int
    stmts: list = field(default_factory=list)
    term: object = None
    role: str = "real"   # "real" (user code) | "junk" (reachable-inert) — for the opt-in sourcemap


# ---- helper names --------------------------------------------------------
@dataclass
class Names:
    state: str
    sentinel: str
    exc: str
    exc_stack: str
    caught: str
    opq: str
    junk: str
    k: str
    kd: str
    act: str


def alloc_names(namer: Namer) -> Names:
    return Names(
        state=namer.fresh("state"), sentinel=namer.fresh("sent"),
        exc=namer.fresh("exc"), exc_stack=namer.fresh("estk"), caught=namer.fresh("caught"),
        opq=namer.fresh("opq"), junk=namer.fresh("junk"),
        k=namer.fresh("k"), kd=namer.fresh("kd"), act=namer.fresh("act"),
    )


# ---- small AST helpers ---------------------------------------------------
def _load(name: str) -> ast.Name:
    return ast.Name(id=name, ctx=ast.Load())


def _assign(name: str, value: ast.expr) -> ast.Assign:
    return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value)


def _call(fn: str, args: list) -> ast.Call:
    return ast.Call(func=_load(fn), args=args, keywords=[])


def _method(obj: str, meth: str, args: list) -> ast.Expr:
    return ast.Expr(value=ast.Call(
        func=ast.Attribute(value=_load(obj), attr=meth, ctx=ast.Load()),
        args=args, keywords=[]))


def _kpush(names: Names, value: ast.expr) -> ast.Expr:
    return _method(names.k, "append", [value])


def _kd_push(names: Names) -> ast.Expr:
    # _kd.append(len(_k))
    return _method(names.kd, "append", [_call("len", [_load(names.k)])])


def _pop(names: str) -> ast.Expr:
    return _method(names, "pop", [])


def _act_goto(sid: int) -> ast.Tuple:
    return ast.Tuple(elts=[ast.Constant(value=_GOTO), ast.Constant(value=sid)], ctx=ast.Load())


# ---- `with` desugaring (PEP 343) ----------------------------------------
class _WithDesugar(ast.NodeTransformer):
    """Rewrite `with` into its PEP-343 try/except/finally expansion so the finally
    machinery handles context managers. Does NOT descend into nested function/class/
    lambda scopes (each is desugared when it is itself flattened)."""

    def __init__(self, namer: Namer):
        self.namer = namer

    def visit_FunctionDef(self, node):
        return node  # nested scope: leave for its own flatten pass

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_With(self, node):
        self.generic_visit(node)  # desugar nested `with` inside the body first
        stmts = node.body
        for item in reversed(node.items):
            stmts = self._expand(item, stmts)
        return stmts  # list splices in to replace the With node

    def _expand(self, item, body):
        mgr = self.namer.fresh("mgr")
        ex = self.namer.fresh("exit")
        val = self.namer.fresh("val")
        hit = self.namer.fresh("hit")
        e = self.namer.fresh("e")
        try_body = []
        if item.optional_vars is not None:
            try_body.append(ast.Assign(targets=[item.optional_vars], value=_load(val)))
        try_body.extend(body)
        exit_exc = ast.Call(func=_load(ex), args=[
            _load(mgr), _call("type", [_load(e)]), _load(e),
            ast.Attribute(value=_load(e), attr="__traceback__", ctx=ast.Load())],
            keywords=[])
        handler = ast.ExceptHandler(type=_load("BaseException"), name=e, body=[
            _assign(hit, ast.Constant(value=True)),
            ast.If(test=ast.UnaryOp(op=ast.Not(), operand=exit_exc),
                   body=[ast.Raise(exc=None, cause=None)], orelse=[])])
        exit_norm = ast.Expr(value=ast.Call(func=_load(ex), args=[
            _load(mgr), ast.Constant(value=None), ast.Constant(value=None),
            ast.Constant(value=None)], keywords=[]))
        final_if = ast.If(test=ast.UnaryOp(op=ast.Not(), operand=_load(hit)),
                          body=[exit_norm], orelse=[])
        return [
            _assign(mgr, item.context_expr),
            _assign(ex, ast.Attribute(value=_call("type", [_load(mgr)]),
                                      attr="__exit__", ctx=ast.Load())),
            _assign(val, ast.Call(
                func=ast.Attribute(value=_call("type", [_load(mgr)]),
                                   attr="__enter__", ctx=ast.Load()),
                args=[_load(mgr)], keywords=[])),
            _assign(hit, ast.Constant(value=False)),
            ast.Try(body=try_body, handlers=[handler], orelse=[], finalbody=[final_if]),
        ]


def desugar_with(funcdef, namer: Namer) -> None:
    """In-place: expand all `with` in funcdef's own body (not nested scopes)."""
    _WithDesugar(namer).generic_visit(funcdef)  # generic_visit = visit children, not funcdef
    ast.fix_missing_locations(funcdef)


# ---- lowering ------------------------------------------------------------
class Lowerer:
    def __init__(self, namer: Namer, names: Names, safe_mode: bool = True, split_markers: bool = False):
        self.blocks: list[Block] = []
        self.ctx: list = []  # markers: ('loop', cont_id, brk_id) | ('try',) | ('x', kind, fin_or_None)
        self.namer = namer
        self.names = names
        self.safe_mode = safe_mode
        self.split_markers = split_markers
        self.needs_sentinel = False
        self.needs_exc = False
        self.needs_k = False

    def new_block(self) -> Block:
        b = Block(id=len(self.blocks))
        self.blocks.append(b)
        return b

    def _seal(self, block: Block, term) -> None:
        if block.term is None:
            block.term = term

    def lower_seq(self, stmts, start: Block):
        cur = start
        for s in stmts:
            if cur is None:
                break
            cur = self.lower_stmt(s, cur)
        return cur

    def lower_stmt(self, stmt, cur: Block):
        if (self.split_markers and isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis):
            nb = self.new_block()
            self._seal(cur, Goto(nb.id))
            return nb
        if isinstance(stmt, ast.Return):
            if not self.safe_mode:
                frames = [m for m in reversed(self.ctx) if m[0] == "x"]
                if frames:
                    # Evaluate the return value FIRST (while exc frames are still active, so a
                    # raise in the expression still triggers the finally), then unwind.
                    ret_val = stmt.value if stmt.value is not None else ast.Constant(value=None)
                    retval_name = self.namer.fresh("retval")
                    cur.stmts.append(_assign(retval_name, ret_val))
                    self._unwind_full(cur, frames, Ret(_load(retval_name)))
                    return None
            if self.split_markers:
                # De-signature the function end: compute the return value in `cur` (exactly where
                # the original `Ret(value)` would evaluate it — same control-flow point, so
                # order/side-effects/exceptions are preserved), then `Goto` a FRESH block whose
                # only terminator is `Ret(rn)`. An analyst who finds the `return` block sees just
                # `return <name>`; the value/logic that produced it lives in a different state.
                rv = stmt.value if stmt.value is not None else ast.Constant(value=None)
                rn = self.namer.fresh("ret")
                cur.stmts.append(_assign(rn, rv))
                nb = self.new_block()
                self._seal(cur, Goto(nb.id))
                self._seal(nb, Ret(_load(rn)))
                return None
            self._seal(cur, Ret(stmt.value))
            return None
        if isinstance(stmt, ast.Pass):
            return cur
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr,
                             ast.Import, ast.ImportFrom, ast.Delete, ast.Assert)):
            cur.stmts.append(stmt)
            return cur
        if isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
            cur.stmts.append(stmt)
            return cur
        if isinstance(stmt, ast.If):
            return self._lower_if(stmt, cur)
        if isinstance(stmt, ast.While):
            return self._lower_while(stmt, cur)
        if isinstance(stmt, ast.For):
            return self._lower_for(stmt, cur)
        if isinstance(stmt, ast.Raise):
            self.needs_exc = True
            self._seal(cur, RaiseTerm(stmt.exc, stmt.cause))
            return None
        if isinstance(stmt, ast.Try):
            return self._lower_try(stmt, cur)
        if isinstance(stmt, ast.Break):
            if not self.safe_mode:
                loop, frames = self._frames_to_loop(stmt)
                self._unwind_full(cur, frames, Goto(loop[2]))
                return None
            loop = self._unwind_to_loop(cur, stmt)
            self._seal(cur, Goto(loop[2]))
            return None
        if isinstance(stmt, ast.Continue):
            if not self.safe_mode:
                loop, frames = self._frames_to_loop(stmt)
                self._unwind_full(cur, frames, Goto(loop[1]))
                return None
            loop = self._unwind_to_loop(cur, stmt)
            self._seal(cur, Goto(loop[1]))
            return None
        raise AssertionError(f"cfg: unsupported stmt {type(stmt).__name__}")

    def _unwind_to_loop(self, cur: Block, stmt):
        """Find the nearest enclosing loop marker; emit `_exc_stack.pop()` for each try
        entered since then (break/continue leaving try regions). If there is NO enclosing
        loop in THIS dispatcher, the break/continue targets a loop outside the current
        sub-region (it crosses a finally) — reject fail-loud."""
        count = 0
        loop = None
        for m in reversed(self.ctx):
            if m[0] == "try":
                count += 1
            elif m[0] == "loop":
                loop = m
                break
        if loop is None:
            raise UnsupportedConstructError([Diagnostic(
                lineno=getattr(stmt, "lineno", 0),
                col_offset=getattr(stmt, "col_offset", 0),
                node_type=type(stmt).__name__,
                message="break/continue whose target loop is outside an enclosing "
                        "try/finally is not supported (safe_mode); rewrite to avoid "
                        "crossing the finally")])
        for _ in range(count):
            cur.stmts.append(_method(self.names.exc_stack, "pop", []))
        return loop

    def _unwind_full(self, cur, frames, terminal):
        """Run the finallys of the `frames` scopes (innermost-first ('x',kind,fin_or_None))
        being exited by a NON-exception transition, then perform `terminal` (a Ret/Goto
        terminator). Frames are popped INCREMENTALLY so OUTER scopes stay active while an
        inner finally runs (a finally-raise must be catchable by enclosing try/except):
          - at the site: pop up to+including the innermost finally, then jump to it;
          - between consecutive finallys: a trampoline pops the gap frames, then jumps to the
            next finally;
          - a final trampoline pops the tail frames (outer of the last finally) then `terminal`.
        Always seals `cur`."""
        fins = [(i, m[2]) for i, m in enumerate(frames) if m[1] == "f"]  # (pos, fin_body) inner-first
        if not fins:
            for _ in frames:
                cur.stmts.append(_pop(self.names.exc_stack))
                cur.stmts.append(_pop(self.names.kd))
            self._seal(cur, terminal)
            return
        final_tb = self.new_block()
        for _ in range(len(frames) - (fins[-1][0] + 1)):  # tail frames
            final_tb.stmts.append(_pop(self.names.exc_stack))
            final_tb.stmts.append(_pop(self.names.kd))
        self._seal(final_tb, terminal)
        tramp_ids = []
        for j in range(1, len(fins)):
            tb = self.new_block()
            for _ in range(fins[j][0] - fins[j - 1][0]):  # gap frames
                tb.stmts.append(_pop(self.names.exc_stack))
                tb.stmts.append(_pop(self.names.kd))
            self._seal(tb, Goto(fins[j][1]))
            tramp_ids.append(tb.id)
        cur.stmts.append(_kpush(self.names, _act_goto(final_tb.id)))
        for tid in reversed(tramp_ids):
            cur.stmts.append(_kpush(self.names, _act_goto(tid)))
        for _ in range(fins[0][0] + 1):  # pop up to+including the innermost finally
            cur.stmts.append(_pop(self.names.exc_stack))
            cur.stmts.append(_pop(self.names.kd))
        self._seal(cur, Goto(fins[0][1]))

    def _frames_to_loop(self, stmt):
        frames = []
        loop = None
        for m in reversed(self.ctx):
            if m[0] == "x":
                frames.append(m)
            elif m[0] == "loop":
                loop = m
                break
        if loop is None:
            raise UnsupportedConstructError([Diagnostic(
                lineno=getattr(stmt, "lineno", 0), col_offset=getattr(stmt, "col_offset", 0),
                node_type=type(stmt).__name__,
                message="break/continue outside a loop is not supported here")])
        return loop, frames

    def _lower_if(self, stmt, cur):
        then_b = self.new_block()
        after = self.new_block()
        else_b = self.new_block() if stmt.orelse else None
        self._seal(cur, CondGoto(stmt.test, then_b.id, else_b.id if else_b else after.id))
        t_end = self.lower_seq(stmt.body, then_b)
        if t_end is not None:
            self._seal(t_end, Goto(after.id))
        if else_b is not None:
            e_end = self.lower_seq(stmt.orelse, else_b)
            if e_end is not None:
                self._seal(e_end, Goto(after.id))
        return after

    def _lower_while(self, stmt, cur):
        head = self.new_block()
        body_b = self.new_block()
        after = self.new_block()
        else_b = self.new_block() if stmt.orelse else None
        self._seal(cur, Goto(head.id))
        self._seal(head, CondGoto(stmt.test, body_b.id, else_b.id if else_b else after.id))
        self.ctx.append(("loop", head.id, after.id))
        b_end = self.lower_seq(stmt.body, body_b)
        if b_end is not None:
            self._seal(b_end, Goto(head.id))
        self.ctx.pop()
        if else_b is not None:
            e_end = self.lower_seq(stmt.orelse, else_b)
            if e_end is not None:
                self._seal(e_end, Goto(after.id))
        return after

    def _lower_for(self, stmt, cur):
        self.needs_sentinel = True
        it_name = self.namer.fresh("it")
        v_name = self.namer.fresh("v")
        cur.stmts.append(_assign(it_name, _call("iter", [stmt.iter])))
        head = self.new_block()
        body_b = self.new_block()
        after = self.new_block()
        else_b = self.new_block() if stmt.orelse else None
        self._seal(cur, Goto(head.id))
        head.stmts.append(_assign(v_name, _call("next", [_load(it_name), _load(self.names.sentinel)])))
        test = ast.Compare(left=_load(v_name), ops=[ast.Is()], comparators=[_load(self.names.sentinel)])
        self._seal(head, CondGoto(test, else_b.id if else_b else after.id, body_b.id))
        body_b.stmts.append(ast.Assign(targets=[stmt.target], value=_load(v_name)))
        self.ctx.append(("loop", head.id, after.id))
        b_end = self.lower_seq(stmt.body, body_b)
        if b_end is not None:
            self._seal(b_end, Goto(head.id))
        self.ctx.pop()
        if else_b is not None:
            e_end = self.lower_seq(stmt.orelse, else_b)
            if e_end is not None:
                self._seal(e_end, Goto(after.id))
        return after

    def _lower_try(self, stmt, cur):
        if not stmt.finalbody:
            return self._lower_except(stmt, cur)
        if not self.safe_mode:
            return self._lower_finally_full(stmt, cur)
        # Hybrid: keep a REAL try/finally so CPython enforces finally semantics, but
        # flatten the protected region and the finally body into nested dispatchers.
        # Desugar try/except/else/finally -> try/finally(try/except/else).
        if stmt.handlers or stmt.orelse:
            inner = ast.Try(body=stmt.body, handlers=stmt.handlers,
                            orelse=stmt.orelse, finalbody=[])
            protected = [inner]
        else:
            protected = stmt.body
        protected_stmts = self._flatten_subregion(protected)
        finally_stmts = self._flatten_subregion(stmt.finalbody)
        cur.stmts.append(ast.Try(body=protected_stmts, handlers=[], orelse=[],
                                 finalbody=finally_stmts))
        return cur

    def _flatten_subregion(self, stmts):
        """Flatten `stmts` into a self-contained nested dispatcher (its own Names) whose
        normal completion is `break` (SubExit). Returns the list of statements forming
        that dispatcher. Shares `self.namer` so all names stay unique, and propagates
        `self.safe_mode` so nested try/finally also stays hybrid."""
        sub_names = alloc_names(self.namer)
        sub = Lowerer(self.namer, sub_names, safe_mode=self.safe_mode)
        entry = sub.new_block()
        cont = sub.lower_seq(stmts, entry)
        if cont is not None:
            sub._seal(cont, SubExit())
        for b in sub.blocks:
            if b.term is None:
                b.term = SubExit()
        return _render(sub.blocks, entry.id, sub_names, sub.needs_sentinel, sub.needs_exc)

    def _lower_except(self, stmt, cur):
        # Lower try/except/else; stmt.finalbody is empty here.
        self.needs_exc = True
        if not self.safe_mode:
            # full mode maintains _k/_kd per try-scope (see _render init) — ensure it's set up
            self.needs_k = True
        body_b = self.new_block()
        after = self.new_block()
        else_b = self.new_block() if stmt.orelse else None
        handler_blocks = [self.new_block() for _ in stmt.handlers]
        hd = self.new_block()
        cur.stmts.append(_method(self.names.exc_stack, "append", [ast.Constant(value=hd.id)]))
        if not self.safe_mode:
            cur.stmts.append(_kd_push(self.names))
        self._seal(cur, Goto(body_b.id))
        # try body (mark active so break/continue inside emit pops)
        self.ctx.append(("x", "h", None) if not self.safe_mode else ("try",))
        b_end = self.lower_seq(stmt.body, body_b)
        if b_end is not None:
            b_end.stmts.append(_pop(self.names.exc_stack))
            if not self.safe_mode:
                b_end.stmts.append(_pop(self.names.kd))
            self._seal(b_end, Goto(else_b.id if else_b else after.id))
        self.ctx.pop()
        # handler-dispatch state
        self._seal(hd, HandlerDispatch([(h.type, hb.id) for h, hb in zip(stmt.handlers, handler_blocks)]))
        # handler bodies
        for h, hb in zip(stmt.handlers, handler_blocks):
            if h.name:
                hb.stmts.append(_assign(h.name, _load(self.names.exc)))
            h_end = self.lower_seq(h.body, hb)
            if h_end is not None:
                if h.name:
                    h_end.stmts.append(ast.Delete(targets=[ast.Name(id=h.name, ctx=ast.Del())]))
                self._seal(h_end, Goto(after.id))
        # else
        if else_b is not None:
            e_end = self.lower_seq(stmt.orelse, else_b)
            if e_end is not None:
                self._seal(e_end, Goto(after.id))
        return after

    def _lower_finally_full(self, stmt, cur):
        self.needs_exc = True
        self.needs_k = True
        if stmt.handlers or stmt.orelse:
            inner = ast.Try(body=stmt.body, handlers=stmt.handlers,
                            orelse=stmt.orelse, finalbody=[])
            protected = [inner]
        else:
            protected = stmt.body
        fin_body = self.new_block()
        fin_exc = self.new_block()
        after = self.new_block()
        prot = self.new_block()
        # enter try: push exception entry (fin_exc) + record _k depth, go to protected
        cur.stmts.append(_method(self.names.exc_stack, "append", [ast.Constant(value=fin_exc.id)]))
        cur.stmts.append(_kd_push(self.names))
        self._seal(cur, Goto(prot.id))
        # fin_exc: exception path -> run finally then re-raise the captured exc
        fin_exc.stmts.append(_kpush(self.names, ast.Tuple(
            elts=[ast.Constant(value=_RAISE), _load(self.names.exc)], ctx=ast.Load())))
        self._seal(fin_exc, Goto(fin_body.id))
        # protected region (finally active)
        self.ctx.append(("x", "f", fin_body.id))
        pend = self.lower_seq(protected, prot)
        self.ctx.pop()
        if pend is not None:
            # normal completion: drop this try's exc frame, run finally with goto(after)
            pend.stmts.append(_pop(self.names.exc_stack))
            pend.stmts.append(_pop(self.names.kd))
            pend.stmts.append(_kpush(self.names, _act_goto(after.id)))
            self._seal(pend, Goto(fin_body.id))
        # finally body (return/break/continue inside it are rejected by FlattenPass)
        fend = self.lower_seq(stmt.finalbody, fin_body)
        if fend is not None:
            self._seal(fend, PopK())
        return after


# ---- junk-block injection ------------------------------------------------
def inject_junk_blocks(low, names: Names, rng) -> None:
    """Splice REACHABLE junk blocks onto a random subset of `Goto` edges. `A -Goto(T)->` becomes
    `A -Goto(J)-> J -Goto(T)->`, where J only mutates the dead junk var. Behavior is unchanged
    (J never touches a live name and cannot raise); the executed path just threads through junk
    states. Operates on `low.blocks` in place (new blocks via `low.new_block()`)."""
    edges = [b for b in list(low.blocks) if isinstance(b.term, Goto)]
    if not edges:
        return
    for b in edges:
        if rng.random() >= 0.5:
            continue
        target = b.term.target
        j = low.new_block()
        j.role = "junk"   # reachable-inert (sourcemap)
        # first stmt assigns a FRESH value (no external init); later stmts read the just-set var
        j.stmts = [_assign(names.junk, ast.BinOp(left=ast.Constant(value=rng.randrange(1, 99999)),
                                                  op=ast.Mult(), right=ast.Constant(value=rng.randrange(1, 99999))))]
        for _ in range(rng.randint(1, 2)):
            j.stmts.append(_assign(names.junk, ast.BinOp(
                left=ast.BinOp(left=_load(names.junk), op=ast.Add(),
                               right=ast.Constant(value=rng.randrange(1, 99999))),
                op=ast.Mod(), right=ast.Constant(value=rng.randrange(2, 9999)))))
        j.term = Goto(target)
        b.term = Goto(j.id)


# ---- import grouping (within a single block) ----------------------------
def _pure_expr(e) -> bool:
    """True if evaluating `e` has no observable side effect, so an `import` may be reordered across
    a statement built only from such exprs. Conservative: Call/Attribute/Subscript/etc. -> False
    (they may trigger descriptors / arbitrary code)."""
    if isinstance(e, (ast.Constant, ast.Name)):
        return True
    if isinstance(e, ast.BinOp):
        return _pure_expr(e.left) and _pure_expr(e.right)
    if isinstance(e, ast.UnaryOp):
        return _pure_expr(e.operand)
    if isinstance(e, ast.BoolOp):
        return all(_pure_expr(v) for v in e.values)
    if isinstance(e, ast.Compare):
        return _pure_expr(e.left) and all(_pure_expr(c) for c in e.comparators)
    if isinstance(e, ast.IfExp):
        return _pure_expr(e.test) and _pure_expr(e.body) and _pure_expr(e.orelse)
    if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
        return all(_pure_expr(x) for x in e.elts)
    return False


def _hoistable_past(stmt) -> bool:
    """True if an `import` may be safely moved ACROSS `stmt` with no observable side effect that
    could race with the import's execution (used only to GROUP imports within one block)."""
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return not stmt.decorator_list  # a decorator evaluates (side effect) at def time
    if isinstance(stmt, ast.Assign):
        return all(isinstance(t, ast.Name) for t in stmt.targets) and _pure_expr(stmt.value)
    if isinstance(stmt, ast.AugAssign):
        return isinstance(stmt.target, ast.Name) and _pure_expr(stmt.value)
    if isinstance(stmt, ast.AnnAssign):
        return isinstance(stmt.target, ast.Name) and (stmt.value is None or _pure_expr(stmt.value))
    return False


def _group_imports(stmts):
    """Within ONE block, bubble each `import`/`from-import` up past preceding side-effect-free
    statements so the imports cluster together near the block top. Bubbling stops at any statement
    that could have an observable side effect, so the order of side effects is never changed — pure
    grouping, behavior-preserving."""
    out = list(stmts)
    for i in range(len(out)):
        if isinstance(out[i], (ast.Import, ast.ImportFrom)):
            j = i
            while (j > 0 and not isinstance(out[j - 1], (ast.Import, ast.ImportFrom))
                   and _hoistable_past(out[j - 1])):
                out[j - 1], out[j] = out[j], out[j - 1]
                j -= 1
    return out


# ---- render --------------------------------------------------------------
def _handler_chain(handlers, state_name, exc_name):
    chain = ast.Raise(exc=_load(exc_name), cause=None)  # default else: propagate
    for type_expr, hid in reversed(handlers):
        route = [_assign(state_name, ast.Constant(value=hid)), ast.Continue()]
        test = ast.Constant(value=True) if type_expr is None else _call("isinstance", [_load(exc_name), type_expr])
        chain = ast.If(test=test, body=route, orelse=[chain])
    return chain


def _src_range(stmts):
    """[min,max] ORIGINAL source line spanned by a block's statements, or None for synthetic /
    empty blocks. Mirrors analyze._block_lines (scan lineno/end_lineno over each stmt subtree)."""
    los, his = [], []
    for s in stmts:
        for node in ast.walk(s):
            lo = getattr(node, "lineno", None)
            if isinstance(lo, int) and lo > 0:
                hi = getattr(node, "end_lineno", None)
                los.append(lo)
                his.append(hi if isinstance(hi, int) and hi > 0 else lo)
    return [min(los), max(his)] if los else None


def _dispatcher_while(rendered):
    """The scope's top-level dispatcher `while` (skips nested-scope whiles, which live inside
    guard bodies, not at the top of `rendered`)."""
    return next((s for s in rendered if isinstance(s, ast.While)), None)


def _scope_states(rendered):
    """The states dict of this scope's `_pyobf_scopemap` (attached to the dispatcher while by
    _render), or None. Block-adding post-render passes register their state ids here so the
    opt-in sourcemap stays authoritative regardless of dispatch_tree erasing `state == K`."""
    w = _dispatcher_while(rendered)
    if w is None or not hasattr(w, "_pyobf_scopemap"):
        return None
    return w._pyobf_scopemap["states"]


def _render(blocks, entry_id, names: Names, needs_sentinel, needs_exc, needs_k=False, scope=None):
    out: list = []
    state_meta: dict = {}
    if needs_sentinel:
        out.append(_assign(names.sentinel, _call("object", [])))
    if needs_exc:
        out.append(_assign(names.exc_stack, ast.List(elts=[], ctx=ast.Load())))
    out.append(_assign(names.state, ast.Constant(value=entry_id)))
    if needs_k:
        out.append(_assign(names.k, ast.List(elts=[], ctx=ast.Load())))
        out.append(_assign(names.kd, ast.List(elts=[], ctx=ast.Load())))

    guards: list = []
    for b in blocks:
        gb = _group_imports(b.stmts)
        t = b.term
        if isinstance(t, Ret):
            gb.append(ast.Return(value=t.value))
        elif isinstance(t, Goto):
            gb.append(_assign(names.state, ast.Constant(value=t.target)))
            gb.append(ast.Continue())
        elif isinstance(t, CondGoto):
            gb.append(ast.If(
                test=t.test,
                body=[_assign(names.state, ast.Constant(value=t.then)), ast.Continue()],
                orelse=[_assign(names.state, ast.Constant(value=t.orelse)), ast.Continue()],
            ))
        elif isinstance(t, RaiseTerm):
            if t.exc is None:
                gb.append(ast.Raise(exc=_load(names.exc), cause=None))
            else:
                gb.append(ast.Raise(exc=t.exc, cause=t.cause))
        elif isinstance(t, HandlerDispatch):
            gb.append(_handler_chain(t.handlers, names.state, names.exc))
        elif isinstance(t, SubExit):
            gb.append(ast.Break())
        elif isinstance(t, PopK):
            gb.append(_assign(names.act, ast.Call(
                func=ast.Attribute(value=_load(names.k), attr="pop", ctx=ast.Load()),
                args=[], keywords=[])))
            sub0 = ast.Subscript(value=_load(names.act), slice=ast.Constant(value=0), ctx=ast.Load())
            sub1 = ast.Subscript(value=_load(names.act), slice=ast.Constant(value=1), ctx=ast.Load())
            gb.append(ast.If(
                test=ast.Compare(left=sub0, ops=[ast.Eq()], comparators=[ast.Constant(value=_GOTO)]),
                body=[_assign(names.state, sub1), ast.Continue()],
                orelse=[ast.If(
                    test=ast.Compare(left=ast.Subscript(value=_load(names.act), slice=ast.Constant(value=0), ctx=ast.Load()),
                                     ops=[ast.Eq()], comparators=[ast.Constant(value=_RET)]),
                    body=[ast.Return(value=ast.Subscript(value=_load(names.act), slice=ast.Constant(value=1), ctx=ast.Load()))],
                    orelse=[ast.Raise(exc=ast.Subscript(value=_load(names.act), slice=ast.Constant(value=1), ctx=ast.Load()), cause=None)])]))
        else:
            gb.append(ast.Return(value=ast.Constant(value=None)))
        guards.append(ast.If(
            test=ast.Compare(left=_load(names.state), ops=[ast.Eq()],
                             comparators=[ast.Constant(value=b.id)]),
            body=gb, orelse=[]))
        state_meta[b.id] = {"role": b.role, "src": _src_range(b.stmts)}

    if needs_exc:
        handler_body = [
            ast.If(test=ast.UnaryOp(op=ast.Not(), operand=_load(names.exc_stack)),
                   body=[ast.Raise(exc=None, cause=None)], orelse=[]),
            _assign(names.exc, _load(names.caught)),
        ]
        if needs_k:
            # del _k[_kd.pop():]   -> truncate continuation orphans to this scope's entry depth
            handler_body.append(ast.Delete(targets=[ast.Subscript(
                value=_load(names.k),
                slice=ast.Slice(lower=ast.Call(
                    func=ast.Attribute(value=_load(names.kd), attr="pop", ctx=ast.Load()),
                    args=[], keywords=[]), upper=None, step=None),
                ctx=ast.Del())]))
        handler_body.append(_assign(names.state, ast.Call(
            func=ast.Attribute(value=_load(names.exc_stack), attr="pop", ctx=ast.Load()),
            args=[], keywords=[])))
        handler_body.append(ast.Continue())
        wrapper = ast.Try(
            body=guards,
            handlers=[ast.ExceptHandler(type=_load("BaseException"), name=names.caught, body=handler_body)],
            orelse=[], finalbody=[])
        loop_body = [wrapper]
    else:
        loop_body = guards
    while_node = ast.While(test=ast.Constant(value=True), body=loop_body, orelse=[])
    # Per-scope provenance for the opt-in sourcemap (cff/sourcemap.py). Attached to the dispatcher
    # while (never discarded). dispatch_var holds the temp state name (sourcemap translates it via
    # finalize_names' out_map). Updated in place by harden_states / inflate_attest_blocks /
    # inject_bogus / inject_attest / dispatch_tree_transform.
    while_node._pyobf_scopemap = {"scope": scope, "dispatch_var": names.state,
                                  "states": state_meta, "dispatch_tree": None}
    out.append(while_node)
    return out


# ---- block splitter -------------------------------------------------------
def split_blocks(blocks, low, max_stmts) -> None:
    """Split any block with > max_stmts statements into a chain of <= max_stmts blocks
    linked by gotos. Pure sequential re-chunking — behavior unchanged. No-op if max_stmts
    is falsy/<1. `blocks` is `low.blocks`; new blocks are appended via `low.new_block()`."""
    if not max_stmts or max_stmts < 1:
        return
    i = 0
    while i < len(blocks):
        b = blocks[i]
        if len(b.stmts) > max_stmts:
            rest = b.stmts[max_stmts:]
            b.stmts = b.stmts[:max_stmts]
            orig_term = b.term
            prev = b
            for j in range(0, len(rest), max_stmts):
                nb = low.new_block()
                nb.stmts = rest[j:j + max_stmts]
                prev.term = Goto(nb.id)
                prev = nb
            prev.term = orig_term
        i += 1


# ---- build / flatten -----------------------------------------------------
def build_blocks(funcdef: ast.FunctionDef, namer: Namer, names: Names, safe_mode: bool = True, split_markers: bool = False):
    desugar_with(funcdef, namer)
    low = Lowerer(namer, names, safe_mode=safe_mode, split_markers=split_markers)
    entry = low.new_block()
    cont = low.lower_seq(funcdef.body, entry)
    if cont is not None:
        low._seal(cont, Ret(None))
    for b in low.blocks:
        if b.term is None:
            b.term = Ret(None)
    return low.blocks, entry.id, low


def inflate_attest_blocks(rendered, names: Names, rng, target_blocks: int, namer: Namer = None) -> None:
    """Inflate a small / low-complexity flattened unit with dead clone blocks so that even a
    tiny function gets a meaningful, density-controlled attest state-transition weave.

    Reuses the bogus-clone machinery (`_collect_real_guard_stmts` + `_build_bogus_body_cloned` +
    `_mutate_clone`): each added guard's body is a mutated clone of real statements (or self-gen
    junk if no donor) followed by a `state = <real label>` goto. The added blocks have NO inbound
    edge -> they are unreachable dead code, exactly like bogus blocks, so behavior is unchanged
    whether or not attest later gates their transitions (correctness rests on attest + protect's
    own integrity, not on these blocks). Unlike `inject_bogus` this does NOT rewrite real
    transitions into never-taken IfExp edges, so the genuine `state = Constant` gotos stay gateable.

    Runs before attest site collection, so the inflated `state = Constant` gotos become gating
    candidates and `attest_density` can actually resolve on units that otherwise expose too few
    sites (where the minimum-count floor would pin the gate count). No-op once the unit already has
    >= target_blocks guards."""
    if namer is None:
        namer = Namer()
    guards = _guard_list(rendered)
    if guards is None:
        return
    real = sorted({c.value for c in _state_const_nodes(rendered, names)})
    if not real or len(guards) >= target_blocks:
        return
    real_guard_pool = _collect_real_guard_stmts(guards, names)
    used = set(real)
    lo = max(1000, real[-1] + 1)
    new_guards, new_labels = [], []
    while len(guards) + len(new_guards) < target_blocks:
        while True:
            bl = rng.randrange(lo, 2 ** 31)
            if bl not in used:
                used.add(bl)
                break
        cloned_body = _build_bogus_body_cloned(real_guard_pool, names, rng, real, namer)
        if cloned_body is None:
            cloned_body = _build_bogus_body_synth(rng, namer)
        goto = ast.Assign(targets=[ast.Name(id=names.state, ctx=ast.Store())],
                          value=ast.Constant(value=rng.choice(real)))  # dead: block has no inbound
        g = ast.If(
            test=ast.Compare(left=ast.Name(id=names.state, ctx=ast.Load()),
                             ops=[ast.Eq()], comparators=[ast.Constant(value=bl)]),
            body=cloned_body + [goto, ast.Continue()], orelse=[])
        ast.fix_missing_locations(g)
        new_guards.append(g)
        new_labels.append(bl)
    if new_guards:
        guards.extend(new_guards)
        states = _scope_states(rendered)   # dead inflate clones (sourcemap)
        if states is not None:
            for bl in new_labels:
                states[bl] = {"role": "bogus", "src": None}
        rng.shuffle(guards)


def inject_attest(rendered, names: Names, rng, requests: list,
                  attest_density: float, state_delta: bool,
                  oracle_var: str, oracle_name_str: str,
                  attest_inflate: bool = False, attest_target_blocks: int = 10,
                  namer: Namer = None, cohash=None) -> None:
    """Post-harden: randomly replace a subset of `state = Constant(T)` gotos (both direct
    and inside CondGoto-generated If nodes) inside `if state == Constant(s):` guards with
    an oracle-computed transition.

    state_delta OFF: state = O(state) ^ __pyobf_corr_<id>__   (absolute)
    state_delta ON:  state += (O(state) ^ __pyobf_corr_<id>__) & MASK  (relative)

    A unique sentinel Name node __pyobf_corr_<id>__ acts as a placeholder; protect/core.py
    replaces it with the computed CORRECTION constant after it knows S_correct.

    A subset of transitions is gated probabilistically (attest_density), with a minimum-count
    floor (ATTEST_MIN_GATES) so even tiny programs get >=1 gated transition.

    Appends one AttestRequest per gated transition to `requests`.
    Also emits one `O = globals().setdefault(<charcode name>, <decoy oracle>)` binding before the
    While loop (the name is char-code-built, the fallback is a plausible wrong hash; see attest.py).

    Runs only when called; when attest is off this function is never called, so there is zero
    change to the rendered output.
    """
    from .attest import (make_setdefault_binding, make_oracle_goto_absolute,
                          make_oracle_goto_relative, ATTEST_MIN_GATES)

    # Body self-cohash: when active, every gated transition folds a runtime self-hash term H.
    # h_var is a fixed dunder name (per-unit local; survives finalize_names) derived from the
    # seed-stable oracle_name_str so the func + module flatten paths agree. guard/hashfn are the
    # module-level defs wrap_module emits once. cohash=None -> byte-identical to the no-cohash output.
    h_var = guard_name = hashfn_name = None
    if cohash is not None:
        from .attest import make_cohash_binding
        guard_name, hashfn_name = cohash
        _hvh = 0
        for _ch in oracle_name_str:
            _hvh = (_hvh * 137 + ord(_ch)) & 0xFFFF   # 137 != oracle_var's 131 -> distinct suffix
        h_var = f"__pyobf_h_{_hvh:04x}__"

    # When enabled, inflate small/low-complexity units with dead clone blocks (reusing the
    # bogus-clone machinery) so attest_density has enough `state = Constant` sites to resolve.
    if attest_inflate and attest_target_blocks and attest_target_blocks > 0:
        inflate_attest_blocks(rendered, names, rng, attest_target_blocks, namer=namer)

    guards = _guard_list(rendered)
    if guards is None:
        return

    def _is_state_goto(stmt) -> bool:
        return (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == names.state
                and isinstance(stmt.value, ast.Constant)
                and type(stmt.value.value) is int)

    # --- Pass 1: collect every gateable `state = Constant(T)` site. inject_attest runs before
    # inject_bogus, so no bogus guards exist yet -> every candidate is a real-path block. ---
    sites = []  # list of (stmt_list, idx, s, T)

    def _collect(stmt_list, s):
        for i in range(len(stmt_list)):
            st = stmt_list[i]
            if _is_state_goto(st):
                sites.append((stmt_list, i, s, st.value.value))
            elif isinstance(st, ast.If):
                # CondGoto-generated If: recurse (we only gate Assigns, so the If stays in place
                # and these stmt_list/idx references remain valid after later replacements).
                _collect(st.body, s)
                _collect(st.orelse, s)

    for g in guards:
        # Only handle plain `if state == Constant(s):` guards
        if not (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                and len(g.test.comparators) == 1
                and isinstance(g.test.comparators[0], ast.Constant)
                and type(g.test.comparators[0].value) is int):
            continue
        _collect(g.body, g.test.comparators[0].value)

    if not sites:
        return

    # --- Choose how many sites to gate: a deterministic, density-proportional target count with a
    # minimum-count floor. A deterministic count (vs independent per-site Bernoulli draws) makes
    # attest_density monotonic and actually responsive even for the few `state = T` sites a
    # flattened unit exposes; the floor still guarantees >=1 gated transition so a dumped body
    # cannot coincidentally run correctly without the oracle. Density controls the gate count
    # across [floor, len(sites)].
    floor = min(ATTEST_MIN_GATES, len(sites))
    target = min(len(sites), max(floor, round(attest_density * len(sites))))
    chosen = sorted(rng.sample(range(len(sites)), target))

    # --- Pass 2: apply gating in collection order. Marker ids start at len(requests) so they are
    # globally unique across multiple inject_attest calls on the shared requests list. ---
    base = len(requests)
    for n, j in enumerate(chosen):
        stmt_list, idx, s, T = sites[j]
        marker_name = f"__pyobf_corr_{base + n}__"
        if state_delta:
            stmt_list[idx] = make_oracle_goto_relative(names.state, oracle_var, marker_name, h_var)
        else:
            stmt_list[idx] = make_oracle_goto_absolute(names.state, oracle_var, marker_name, h_var)
        requests.append((base + n, s, T, state_delta))

    states = _scope_states(rendered)   # mark blocks whose outbound goto is oracle-gated (sourcemap)
    if states is not None:
        for j in chosen:
            s = sites[j][2]
            if s in states:
                states[s]["attest"] = True

    # Emit the oracle binding before the While loop (only reached when >=1 transition was gated).
    # When body cohash is active, also bind H = hashfn(guard.__code__.co_code) right before it, so the
    # gated transitions (which fold ^ H) can read it. Both are plain statements (no lambda/closure).
    binding = make_setdefault_binding(oracle_var, oracle_name_str, rng)
    while_idx = next((k for k, stmt in enumerate(rendered)
                      if isinstance(stmt, ast.While)), None)
    inserts = [binding]
    if h_var is not None:
        inserts.append(make_cohash_binding(h_var, hashfn_name, guard_name))
    if while_idx is not None:
        rendered[while_idx:while_idx] = inserts
    for _st in inserts:
        ast.fix_missing_locations(_st)


def flatten_function(funcdef: ast.FunctionDef, namer: Namer,
                     names: Names | None = None, min_blocks: int = 1,
                     safe_mode: bool = True, state_rng=None,
                     bogus_rng=None, opaque_rng=None,
                     max_block_stmts=None, dedup: bool = False,
                     state_delta: bool = False, tree_rng=None,
                     split_markers: bool = False,
                     junk_rng=None,
                     key_consts_flag: bool = False,
                     bogus_clone_ratio: float = 0.0,
                     attest_rng=None, attest_density: float = 0.3,
                     attest_requests: list | None = None,
                     oracle_var: str = "__pyobf_o__",
                     oracle_name_str: str = "__pyobf_oracle__",
                     attest_inflate: bool = False, attest_target_blocks: int = 10,
                     cohash=None) -> ast.FunctionDef:
    names = names or alloc_names(namer)
    blocks, entry_id, low = build_blocks(funcdef, namer, names, safe_mode=safe_mode, split_markers=split_markers)
    if len(blocks) < min_blocks:
        return funcdef
    split_blocks(blocks, low, max_block_stmts)
    if junk_rng is not None:
        inject_junk_blocks(low, names, junk_rng)
    rendered = _render(blocks, entry_id, names, low.needs_sentinel, low.needs_exc, low.needs_k,
                       scope=funcdef.name)
    if dedup and not low.needs_k:
        dedup_blocks(rendered, names)
    if state_rng is not None and not low.needs_k:
        harden_states(rendered, names, state_rng)
    if key_consts_flag and not low.needs_k:
        key_consts(rendered, names)
    if attest_rng is not None and attest_requests is not None:
        inject_attest(rendered, names, attest_rng, attest_requests, attest_density,
                      state_delta, oracle_var, oracle_name_str,
                      attest_inflate, attest_target_blocks, namer=namer, cohash=cohash)
    if bogus_rng is not None:
        inject_bogus(rendered, names, bogus_rng, bogus_clone_ratio=bogus_clone_ratio, namer=namer)
    if state_delta:
        state_delta_transform(rendered, names)
    if opaque_rng is not None:
        inject_opaque(rendered, names, opaque_rng)
    if tree_rng is not None:
        dispatch_tree_transform(rendered, names, tree_rng)
    funcdef.body = rendered
    ast.fix_missing_locations(funcdef)
    return funcdef


def _state_const_nodes(rendered, names: Names):
    """The Constant nodes that hold dispatcher state ids: `<state> == K`, `<state> = K`,
    and `<exc_stack>.append(K)` (identifiable via the fresh state/exc_stack names)."""
    out = []
    state, estk = names.state, names.exc_stack
    for root in rendered:
        for node in ast.walk(root):
            if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                    and node.left.id == state and len(node.ops) == 1
                    and isinstance(node.ops[0], ast.Eq) and len(node.comparators) == 1
                    and isinstance(node.comparators[0], ast.Constant)
                    and type(node.comparators[0].value) is int):
                out.append(node.comparators[0])
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == state
                    and isinstance(node.value, ast.Constant) and type(node.value.value) is int):
                out.append(node.value)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "append" and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == estk and len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is int):
                out.append(node.args[0])
    return out


def harden_states(rendered, names: Names, rng) -> None:
    """Post-render: remap dispatcher state ids to random distinct large ints and shuffle
    the guard order. Pure relabel + reorder — semantically identical. Mutates `rendered`
    in place."""
    consts = _state_const_nodes(rendered, names)
    olds = sorted({c.value for c in consts})
    if olds:
        lo = max(1000, olds[-1] + 1)
        used, mapping = set(), {}
        for old in olds:
            while True:
                new = rng.randrange(lo, 2 ** 31)
                if new not in used:
                    break
            used.add(new)
            mapping[old] = new
        for c in consts:
            c.value = mapping[c.value]
        states = _scope_states(rendered)   # keep the sourcemap's state ids in sync with the relabel
        if states is not None:
            _dispatcher_while(rendered)._pyobf_scopemap["states"] = {
                mapping.get(k, k): v for k, v in states.items()}
    while_node = next((s for s in rendered if isinstance(s, ast.While)), None)
    if while_node is not None:
        body = while_node.body
        guards = body[0].body if (len(body) == 1 and isinstance(body[0], ast.Try)) else body
        rng.shuffle(guards)


def _guard_list(rendered):
    """The list of guard `If`s (the While body, or the wrapper Try.body when needs_exc)."""
    while_node = next((s for s in rendered if isinstance(s, ast.While)), None)
    if while_node is None:
        return None
    body = while_node.body
    if len(body) == 1 and isinstance(body[0], ast.Try):
        return body[0].body
    return body


def dedup_blocks(rendered, names: Names) -> None:
    """Merge byte-identical dispatcher guards (fixpoint). Behavior-preserving: a block's body is
    the same regardless of which state-id reached it, so transitions to a duplicate are redirected
    to the canonical identical block. Mutates `rendered` in place."""
    while True:
        guards = _guard_list(rendered)
        if guards is None:
            return
        groups = {}
        for g in guards:
            if not (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                    and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                    and len(g.test.comparators) == 1
                    and isinstance(g.test.comparators[0], ast.Constant)
                    and type(g.test.comparators[0].value) is int):
                continue  # not a plain `state == K` guard; skip
            k = g.test.comparators[0].value
            key = tuple(ast.dump(s) for s in g.body)
            groups.setdefault(key, []).append((k, g))
        merge, drop = {}, set()
        for lst in groups.values():
            if len(lst) > 1:
                canon = lst[0][0]
                for k, g in lst[1:]:
                    merge[k] = canon
                    drop.add(id(g))
        if not merge:
            return
        for c in _state_const_nodes(rendered, names):
            if c.value in merge:
                c.value = merge[c.value]
        gl = _guard_list(rendered)
        gl[:] = [g for g in gl if id(g) not in drop]


class _DeltaRewrite(ast.NodeTransformer):
    def __init__(self, state: str, k: int):
        self.state = state
        self.k = k

    def visit_Assign(self, node):
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == self.state
                and isinstance(node.value, ast.Constant) and type(node.value.value) is int):
            delta = node.value.value - self.k
            op = ast.Add() if delta >= 0 else ast.Sub()
            return ast.AugAssign(target=ast.Name(id=self.state, ctx=ast.Store()),
                                 op=op, value=ast.Constant(value=abs(delta)))
        return node


def state_delta_transform(rendered, names: Names) -> None:
    """Rewrite `state = T` gotos inside each `if state == k` guard to `state += (T - k)`."""
    guards = _guard_list(rendered)
    if guards is None:
        return
    for g in guards:
        if not (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                and len(g.test.comparators) == 1
                and isinstance(g.test.comparators[0], ast.Constant)
                and type(g.test.comparators[0].value) is int):
            continue
        k = g.test.comparators[0].value
        g.body = [_DeltaRewrite(names.state, k).visit(s) for s in g.body]


def dispatch_tree_transform(rendered, names: Names, rng) -> None:
    """Replace the flat `if state == k` guard list with a binary search tree whose INTERIOR
    nodes are `if state >= pivot:` and whose LEAVES are the block bodies DIRECTLY — no
    `if state == k` check, so a fragment's concrete state value never appears in the dispatch.
    Each pivot is chosen RANDOMLY in the open gap between the two adjacent state values it
    separates (`vals[mid-1] < pivot <= vals[mid]`), so the split points are not the state ids
    either. Correct because `state` is always one of the block ids the tree partitions into
    singleton ranges, so navigation lands on exactly the matching leaf."""
    guards = _guard_list(rendered)
    if guards is None:
        return
    items = []
    for g in guards:
        if (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                and len(g.test.comparators) == 1
                and isinstance(g.test.comparators[0], ast.Constant)
                and type(g.test.comparators[0].value) is int):
            items.append((g.test.comparators[0].value, g.body))
        else:
            return  # unexpected guard shape; leave the dispatch as-is (fail-safe)
    if len(items) < 2:
        return
    items.sort(key=lambda t: t[0])
    vals = [v for v, _ in items]

    def build(lo, hi):
        # Returns (ast_nodes, meta). meta mirrors the BST for the sourcemap: interior nodes carry
        # the unique `pivot` (the `if state >= pivot` split) with `ge`/`lt` subtrees; leaves carry
        # the concrete `state` id (erased from the emitted dispatch). RNG draw order is fixed
        # (pivot, then ge=build(mid,hi), then lt=build(lo,mid)) to keep output deterministic.
        if hi - lo == 1:
            return items[lo][1], {"state": vals[lo]}  # leaf: the block's statements, no `== k` guard
        mid = (lo + hi) // 2
        pivot = rng.randrange(vals[mid - 1] + 1, vals[mid] + 1)  # vals[mid-1] < pivot <= vals[mid]
        ge_ast, ge_meta = build(mid, hi)
        lt_ast, lt_meta = build(lo, mid)
        node = [ast.If(
            test=ast.Compare(left=_load(names.state), ops=[ast.GtE()],
                             comparators=[ast.Constant(value=pivot)]),
            body=ge_ast, orelse=lt_ast)]
        return node, {"pivot": pivot, "ge": ge_meta, "lt": lt_meta}

    tree_ast, tree_meta = build(0, len(items))
    guards[:] = tree_ast
    w = _dispatcher_while(rendered)   # record the BST so the sourcemap can navigate (pivot+/pivot-)
    if w is not None and hasattr(w, "_pyobf_scopemap"):
        w._pyobf_scopemap["dispatch_tree"] = tree_meta


class _KeyConsts(ast.NodeTransformer):
    """Rewrite eager int constants in one block (where `state == K`) to `enc - (state & mask)`."""
    def __init__(self, state: str, K: int, skip_ids: set):
        self.state = state
        self.K = K
        self.skip = skip_ids

    # do NOT descend into deferred / separate scopes (state != K when they later run)
    def visit_Lambda(self, node): return node
    def visit_GeneratorExp(self, node): return node
    def visit_FunctionDef(self, node): return node
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_ClassDef(self, node): return node

    def visit_Constant(self, node):
        if id(node) in self.skip:
            return node
        v = node.value
        if type(v) is int and abs(v) > 1:   # type(): excludes bool; skip 0/1/-1
            nbytes = max(1, (abs(v).bit_length() + 7) // 8)
            mask = (1 << (8 * nbytes)) - 1
            key = self.K & mask
            return ast.BinOp(
                left=ast.Constant(value=v + key), op=ast.Sub(),
                right=ast.BinOp(left=_load(self.state), op=ast.BitAnd(),
                                right=ast.Constant(value=mask)))
        return node


def key_consts(rendered, names: Names) -> None:
    """Per-block: encrypt eager int constants with the block's own `state` value as the key.
    Behavior-preserving (`enc - (state & mask)` == c when state == K) and fold-proof (state is a
    runtime var). Run after harden (final K), before dispatch_tree/state_delta/bogus/opaque."""
    guards = _guard_list(rendered)
    if guards is None:
        return
    skip = {id(c) for c in _state_const_nodes(rendered, names)}
    for g in guards:
        if not (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                and len(g.test.comparators) == 1
                and isinstance(g.test.comparators[0], ast.Constant)
                and type(g.test.comparators[0].value) is int):
            continue
        K = g.test.comparators[0].value
        rw = _KeyConsts(names.state, K, skip)
        g.body = [rw.visit(s) for s in g.body]


def _collect_real_guard_stmts(guards, names: Names) -> list:
    """Return a list of (guard_body_stmts,) from real (non-bogus) guards — specifically,
    the 'simple computation' statements inside each guard's body that are safe to clone:
    ast.Assign, ast.AugAssign, ast.Expr. Excludes the terminator (state= / Continue /
    Return / Raise / Break) and all control-flow constructs."""
    _SIMPLE = (ast.Assign, ast.AugAssign, ast.Expr)
    _TERMINATOR_TARGET = names.state  # state-assign is the Goto terminator
    result = []
    for g in guards:
        if not (isinstance(g, ast.If) and isinstance(g.test, ast.Compare)
                and isinstance(g.test.left, ast.Name) and g.test.left.id == names.state
                and len(g.test.comparators) == 1
                and isinstance(g.test.comparators[0], ast.Constant)
                and type(g.test.comparators[0].value) is int):
            continue  # skip non-standard guards (e.g. after dispatch_tree)
        simple = []
        for s in g.body:
            if not isinstance(s, _SIMPLE):
                continue
            # Skip the state-assignment terminator (state = <int>)
            if (isinstance(s, ast.Assign) and len(s.targets) == 1
                    and isinstance(s.targets[0], ast.Name)
                    and s.targets[0].id == _TERMINATOR_TARGET):
                continue
            simple.append(s)
        if simple:
            result.append(simple)
    return result


_SYNTH_OPS = [ast.Add, ast.Sub, ast.Mult, ast.BitXor]


def _mutate_clone(stmts, rng, namer) -> list:
    """Deep-copy `stmts` into an independent MIRROR: every identifier is renamed to a fresh random
    name (consistently — reads and writes), and Constant values are lightly mutated. The result is a
    structural twin of a real block operating entirely on 'random variables', so it reads like real
    code yet touches no real state. Bogus blocks are unreachable, so reading a not-yet-written fresh
    name never executes — it just looks like a cross-block reference. Returns NEW AST nodes."""
    import copy
    cloned = copy.deepcopy(stmts)
    order = []                                   # original ids, first-appearance order (deterministic)
    for s in cloned:
        for n in ast.walk(s):
            if isinstance(n, ast.Name) and n.id not in order:
                order.append(n.id)
    rmap = {orig: namer.fresh("b") for orig in order}

    class _Mutator(ast.NodeTransformer):
        def visit_Name(self, node):
            node.id = rmap.get(node.id, node.id)
            return node
        def visit_Constant(self, node):
            v = node.value
            if type(v) is int and abs(v) <= 10 ** 15:
                return ast.Constant(value=v + rng.randint(-50, 50))
            if type(v) is float:
                return ast.Constant(value=v + rng.uniform(-10.0, 10.0))
            if type(v) is str and len(v) > 0:
                chars = list(v)
                for _ in range(max(1, len(chars) // 4)):
                    idx = rng.randrange(len(chars))
                    chars[idx] = chr(ord(chars[idx]) ^ rng.randint(1, 7))
                return ast.Constant(value="".join(chars))
            return node

    m = _Mutator()
    mutated = [m.visit(s) for s in cloned]
    rng.shuffle(mutated)
    return mutated


def _build_bogus_body_synth(rng, namer) -> list:
    """A realistic synthesized bogus body for when there is no real block to clone: 2-4 assignments
    to FRESH vars with masked mixed arithmetic, mirroring the style of real flattened blocks. Never
    the obvious single-`junk` product that reads as dead code."""
    vs = [namer.fresh("b") for _ in range(rng.randint(2, 4))]
    body = [_assign(vs[0], ast.Constant(value=rng.randrange(1, 1 << 20)))]
    for i in range(1, len(vs)):
        rhs = ast.BinOp(left=_load(vs[i - 1]), op=rng.choice(_SYNTH_OPS)(),
                        right=ast.Constant(value=rng.randrange(1, 1 << 16)))
        rhs = ast.BinOp(left=rhs, op=ast.BitAnd(),
                        right=ast.Constant(value=(1 << rng.choice([16, 32, 64])) - 1))
        body.append(_assign(vs[i], rhs))
    return body


def _build_bogus_body_cloned(real_guard_pool, names: Names, rng, real_labels, namer) -> list:
    """Mirror a real guard's simple statements into an independent bogus body (fresh-renamed vars),
    NOT including the terminator. Returns None if the donor pool is empty (caller synthesizes)."""
    if not real_guard_pool:
        return None
    donor = rng.choice(real_guard_pool)
    n = rng.randint(1, max(1, len(donor)))
    sample = rng.sample(donor, min(n, len(donor)))
    return _mutate_clone(sample, rng, namer)


def inject_bogus(rendered, names: Names, rng, bogus_clone_ratio: float = 1.0, namer: Namer = None) -> None:
    """Append unreachable bogus guard blocks. Their label is never a transition target, so
    they never execute — behavior unchanged. After creation, wrap a random subset of real
    state-assign transitions as `state = (BOGUS if <always-false> else K)` so each bogus
    label has at least one inbound (never-taken) edge — making bogus blocks reachable-looking.

    Each bogus body MIRRORS a real block (cloned, with every var renamed to a fresh random — so it
    reads like a real branch on independent variables) when a donor exists, else a realistic
    synthesized body (masked mixed arithmetic on fresh vars). `bogus_clone_ratio` is the fraction
    that prefer mirroring vs synth. NEITHER is the old obvious single-junk product."""
    if namer is None:
        namer = Namer()
    real = sorted({c.value for c in _state_const_nodes(rendered, names)})
    guards = _guard_list(rendered)
    if not real or guards is None:
        return
    lo = max(1000, real[-1] + 1)
    used = set(real)

    # Collect donor pool for cloning BEFORE we append bogus guards to the guard list
    real_guard_pool = _collect_real_guard_stmts(guards, names) if bogus_clone_ratio > 0.0 else []

    bogus_labels = []
    for _ in range(max(1, len(real) // 2)):
        while True:
            bl = rng.randrange(lo, 2 ** 31)
            if bl not in used:
                break
        used.add(bl)
        bogus_labels.append(bl)

        # Body: mirror a real block (cloned, vars renamed to fresh randoms) when a donor exists,
        # else a realistic synthesized body. Never the old obvious single-junk product.
        body = None
        if bogus_clone_ratio > 0.0 and rng.random() < bogus_clone_ratio:
            body = _build_bogus_body_cloned(real_guard_pool, names, rng, real, namer)
        if body is None:
            body = _build_bogus_body_synth(rng, namer)
        goto = ast.Assign(targets=[ast.Name(id=names.state, ctx=ast.Store())],
                          value=ast.Constant(value=rng.choice(real)))  # dead: never reached
        body_stmts = body + [goto, ast.Continue()]

        guards.append(ast.If(
            test=ast.Compare(left=ast.Name(id=names.state, ctx=ast.Load()),
                             ops=[ast.Eq()], comparators=[ast.Constant(value=bl)]),
            body=body_stmts, orelse=[]))
    states = _scope_states(rendered)   # unreachable bogus blocks (sourcemap)
    if states is not None:
        for bl in bogus_labels:
            states[bl] = {"role": "bogus", "src": None}
    if bogus_labels:
        top_nodes = set(id(r) for r in rendered)
        assigns = [n for root in rendered for n in ast.walk(root)
                   if isinstance(n, ast.Assign) and len(n.targets) == 1
                   and isinstance(n.targets[0], ast.Name) and n.targets[0].id == names.state
                   and isinstance(n.value, ast.Constant) and type(n.value.value) is int
                   and id(n) not in top_nodes]   # exclude top-level initial assign (state undefined)
        for n in assigns:
            if rng.random() < 0.5:
                continue
            K = n.value.value
            n.value = ast.IfExp(test=rng.choice(_OPAQUE_FALSE)(names.state, rng),
                                body=ast.Constant(value=rng.choice(bogus_labels)),  # never taken
                                orelse=ast.Constant(value=K))                        # always taken
    rng.shuffle(guards)


# ---- opaque-predicate family ------------------------------------------------
def _ld(name: str) -> ast.Name:
    return ast.Name(id=name, ctx=ast.Load())


def _bo(l, op, r) -> ast.BinOp:
    return ast.BinOp(left=l, op=op, right=r)


def _mod(e, m: int) -> ast.BinOp:
    return _bo(e, ast.Mod(), ast.Constant(value=m))


def _cmp(l, op, r: int) -> ast.Compare:
    return ast.Compare(left=l, ops=[op], comparators=[ast.Constant(value=r)])


# TRUE for all int >= 0
def _t_sq_plus(var: str, rng) -> ast.expr:   # (var*var + var) % 2 == 0
    e = _bo(_bo(_ld(var), ast.Mult(), _ld(var)), ast.Add(), _ld(var))
    return _cmp(_mod(e, 2), ast.Eq(), 0)


def _t_cube(var: str, rng) -> ast.expr:       # (var**3 - var) % 6 == 0
    cube = _bo(_bo(_ld(var), ast.Mult(), _ld(var)), ast.Mult(), _ld(var))
    return _cmp(_mod(_bo(cube, ast.Sub(), _ld(var)), 6), ast.Eq(), 0)


def _t_or1(var: str, rng) -> ast.expr:        # (var | 1) % 2 == 1
    return _cmp(_mod(_bo(_ld(var), ast.BitOr(), ast.Constant(value=1)), 2), ast.Eq(), 1)


def _t_sq_mod4(var: str, rng) -> ast.expr:    # (var*var) % 4 != 2
    return _cmp(_mod(_bo(_ld(var), ast.Mult(), _ld(var)), 4), ast.NotEq(), 2)


def _t_consec(var: str, rng) -> ast.expr:     # ((var+1)*(var+2)) % 2 == 0
    a = _bo(_ld(var), ast.Add(), ast.Constant(value=1))
    b = _bo(_ld(var), ast.Add(), ast.Constant(value=2))
    return _cmp(_mod(_bo(a, ast.Mult(), b), 2), ast.Eq(), 0)


# FALSE for all int >= 0 (complements of the above)
def _f_sq_plus(var: str, rng) -> ast.expr:
    e = _bo(_bo(_ld(var), ast.Mult(), _ld(var)), ast.Add(), _ld(var))
    return _cmp(_mod(e, 2), ast.Eq(), 1)


def _f_or1(var: str, rng) -> ast.expr:
    return _cmp(_mod(_bo(_ld(var), ast.BitOr(), ast.Constant(value=1)), 2), ast.Eq(), 0)


def _f_sq_mod4(var: str, rng) -> ast.expr:
    return _cmp(_mod(_bo(_ld(var), ast.Mult(), _ld(var)), 4), ast.Eq(), 2)


def _f_cube(var: str, rng) -> ast.expr:       # (var**3 - var) % 6 == 1  -> always false
    cube = _bo(_bo(_ld(var), ast.Mult(), _ld(var)), ast.Mult(), _ld(var))
    return _cmp(_mod(_bo(cube, ast.Sub(), _ld(var)), 6), ast.Eq(), 1)


def _f_consec(var: str, rng) -> ast.expr:
    a = _bo(_ld(var), ast.Add(), ast.Constant(value=1))
    b = _bo(_ld(var), ast.Add(), ast.Constant(value=2))
    return _cmp(_mod(_bo(a, ast.Mult(), b), 2), ast.Eq(), 1)


_OPAQUE_TRUE  = [_t_sq_plus, _t_cube, _t_or1, _t_sq_mod4, _t_consec]
_OPAQUE_FALSE = [_f_sq_plus, _f_or1, _f_sq_mod4, _f_cube, _f_consec]


def _opaque_choice(real_node, fake_node, var: str, rng) -> ast.IfExp:
    """IfExp that always evaluates to real_node; real lands in body (true-form) or orelse
    (false-form) ~50/50. `var` is a nonneg-int variable name (state or opq)."""
    if rng.random() < 0.5:
        return ast.IfExp(test=rng.choice(_OPAQUE_TRUE)(var, rng),
                         body=real_node, orelse=fake_node)
    return ast.IfExp(test=rng.choice(_OPAQUE_FALSE)(var, rng),
                     body=fake_node, orelse=real_node)


def inject_opaque(rendered, names: Names, rng) -> None:
    """Inject `opq = <int>` before the loop and wrap a random subset of `<state> = K`
    goto-assignments as `<state> = (K if <always-true> else <real label>)`.
    Also wraps AugAssign(state, Add|Sub, Constant) for state_delta+opaque composition."""
    # top-level assigns (direct rendered items, e.g. the initial state = K before while):
    # state is not yet defined there so only `opq` is safe as predicate operand.
    # Nested assigns (inside while/if guards) may use either state or opq.
    top_assigns = []    # Assign(state, Constant) that are direct children of rendered
    nested_assigns = [] # Assign(state, Constant) nested inside loops/ifs
    augs = []           # AugAssign(state, Add|Sub, Constant)
    top_nodes = set(id(r) for r in rendered)
    for root in rendered:
        for node in ast.walk(root):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == names.state
                    and isinstance(node.value, ast.Constant)
                    and type(node.value.value) is int):
                if id(node) in top_nodes:
                    top_assigns.append(node)
                else:
                    nested_assigns.append(node)
            elif (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
                    and node.target.id == names.state
                    and isinstance(node.op, (ast.Add, ast.Sub))
                    and isinstance(node.value, ast.Constant)
                    and type(node.value.value) is int):
                augs.append(node)
    assigns = top_assigns + nested_assigns
    if not assigns and not augs:
        return
    reals = sorted({a.value.value for a in assigns}) or [0]
    rendered.insert(0, ast.Assign(targets=[ast.Name(id=names.opq, ctx=ast.Store())],
                                  value=ast.Constant(value=rng.randrange(2, 10000))))
    for a in top_assigns:
        if rng.random() < 0.5:
            continue  # leave some plain so not every transition is wrapped
        # state is not defined yet at top level; only opq (just assigned above) is safe
        a.value = _opaque_choice(ast.Constant(value=a.value.value),
                                 ast.Constant(value=rng.choice(reals)), names.opq, rng)
    for a in nested_assigns:
        if rng.random() < 0.5:
            continue  # leave some plain so not every transition is wrapped
        # state is always defined inside the loop guards; use it as predicate operand
        # to tie the opaque test to the live dispatcher variable.
        a.value = _opaque_choice(ast.Constant(value=a.value.value),
                                 ast.Constant(value=rng.choice(reals)), names.state, rng)
    for a in augs:
        if rng.random() < 0.5:
            continue
        a.value = _opaque_choice(ast.Constant(value=a.value.value),
                                 ast.Constant(value=rng.randrange(0, 10000)), names.state, rng)


def flatten_module_body(body_stmts, namer: Namer, min_blocks: int = 1,
                        safe_mode: bool = True, state_rng=None,
                        bogus_rng=None, opaque_rng=None,
                        max_block_stmts=None, dedup: bool = False,
                        state_delta: bool = False, tree_rng=None,
                        split_markers: bool = False,
                        junk_rng=None,
                        key_consts_flag: bool = False,
                        bogus_clone_ratio: float = 0.0,
                        attest_rng=None, attest_density: float = 0.3,
                        attest_requests: list | None = None,
                        oracle_var: str = "__pyobf_o__",
                        oracle_name_str: str = "__pyobf_oracle__",
                        attest_inflate: bool = False, attest_target_blocks: int = 10,
                        cohash=None):
    """Flatten a sequence of MODULE-level statements into a module-level dispatcher.
    Module bodies cannot `return`, so normal completion is `SubExit` (-> `break`); names
    defined inside the dispatcher still bind module globals (a while/if introduces no
    scope). Returns the rendered statement list, or None if there are fewer than
    `min_blocks` blocks (nothing worth wrapping)."""
    container = ast.Module(body=list(body_stmts), type_ignores=[])
    desugar_with(container, namer)  # module-level `with` -> try/finally (hybrid)
    names = alloc_names(namer)
    low = Lowerer(namer, names, safe_mode=safe_mode, split_markers=split_markers)
    entry = low.new_block()
    cont = low.lower_seq(container.body, entry)
    if cont is not None:
        low._seal(cont, SubExit())
    for b in low.blocks:
        if b.term is None:
            b.term = SubExit()
    if len(low.blocks) < min_blocks:
        return None
    split_blocks(low.blocks, low, max_block_stmts)
    if junk_rng is not None:
        inject_junk_blocks(low, names, junk_rng)
    rendered = _render(low.blocks, entry.id, names, low.needs_sentinel, low.needs_exc, low.needs_k,
                       scope="<module>")
    if dedup and not low.needs_k:
        dedup_blocks(rendered, names)
    if state_rng is not None and not low.needs_k:
        harden_states(rendered, names, state_rng)
    if key_consts_flag and not low.needs_k:
        key_consts(rendered, names)
    if attest_rng is not None and attest_requests is not None:
        inject_attest(rendered, names, attest_rng, attest_requests, attest_density,
                      state_delta, oracle_var, oracle_name_str,
                      attest_inflate, attest_target_blocks, namer=namer, cohash=cohash)
    if bogus_rng is not None:
        inject_bogus(rendered, names, bogus_rng, bogus_clone_ratio=bogus_clone_ratio, namer=namer)
    if state_delta:
        state_delta_transform(rendered, names)
    if opaque_rng is not None:
        inject_opaque(rendered, names, opaque_rng)
    if tree_rng is not None:
        dispatch_tree_transform(rendered, names, tree_rng)
    return rendered
