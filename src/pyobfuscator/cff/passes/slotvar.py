from __future__ import annotations

import ast

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from .flatten import FLATTEN_ALLOWED

_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
           ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _param_names(fn) -> set:
    a = fn.args
    out = set()
    for grp in (a.posonlyargs, a.args, a.kwonlyargs):
        for arg in grp:
            out.add(arg.arg)
    if a.vararg:
        out.add(a.vararg.arg)
    if a.kwarg:
        out.add(a.kwarg.arg)
    return out


def _analyze(fn) -> set:
    """Local names of `fn` that are safely slottable: plain simple-Name Assign targets,
    excluding hard targets (destructuring, for/with/except/import/walrus/AnnAssign),
    global/nonlocal names, parameters, and names captured by nested scopes."""
    assigned, hard, nested = set(), set(), set()

    def hard_targets(target):
        for n in ast.walk(target):
            if isinstance(n, ast.Name):
                hard.add(n.id)

    def visit(node):
        if isinstance(node, _NESTED):
            for n in ast.walk(node):
                if isinstance(n, ast.Name):
                    nested.add(n.id)
            return
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assigned.add(t.id)
                else:
                    hard_targets(t)
            visit(node.value)
            return
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                assigned.add(node.target.id)
            else:
                hard_targets(node.target)
            visit(node.value)
            return
        if isinstance(node, ast.AnnAssign):
            hard_targets(node.target)
            if node.value is not None:
                visit(node.value)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            hard_targets(node.target)
            visit(node.iter)
            for s in node.body:
                visit(s)
            for s in node.orelse:
                visit(s)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                visit(item.context_expr)
                if item.optional_vars is not None:
                    hard_targets(item.optional_vars)
            for s in node.body:
                visit(s)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.name:
                hard.add(node.name)
            if node.type is not None:
                visit(node.type)
            for s in node.body:
                visit(s)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                hard.add((alias.asname or alias.name).split(".")[0])
            return
        if isinstance(node, ast.Delete):
            # Exclude `del`'d names from slotting so `del x` keeps its exact semantics
            # (a later read of x must still raise, not return a slot value of None).
            for t in node.targets:
                hard_targets(t)
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            hard.update(node.names)
            return
        if isinstance(node, ast.NamedExpr):
            # walrus target must stay a Name (`_slots[i] := ...` is invalid) -> never slot it
            if isinstance(node.target, ast.Name):
                hard.add(node.target.id)
            visit(node.value)
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    for stmt in fn.body:
        visit(stmt)
    return assigned - hard - nested - _param_names(fn)


class _Rewriter(ast.NodeTransformer):
    def __init__(self, slots: str, index: dict):
        self.slots = slots
        self.index = index

    def _skip(self, node):
        return node

    visit_FunctionDef = _skip
    visit_AsyncFunctionDef = _skip
    visit_Lambda = _skip
    visit_ClassDef = _skip
    visit_ListComp = _skip
    visit_SetComp = _skip
    visit_DictComp = _skip
    visit_GeneratorExp = _skip

    def visit_Name(self, node):
        if node.id in self.index:
            return ast.copy_location(ast.Subscript(
                value=ast.Name(id=self.slots, ctx=ast.Load()),
                slice=ast.Constant(value=self.index[node.id]),
                ctx=node.ctx), node)
        return node


def _slot_function(fn, namer: Namer) -> None:
    order = sorted(_analyze(fn))
    if not order:
        return
    index = {name: i for i, name in enumerate(order)}
    slots = namer.fresh("slots")
    rw = _Rewriter(slots, index)
    new_body = [rw.visit(stmt) for stmt in fn.body]
    init = ast.Assign(
        targets=[ast.Name(id=slots, ctx=ast.Store())],
        value=ast.BinOp(left=ast.List(elts=[ast.Constant(value=None)], ctx=ast.Load()),
                        op=ast.Mult(), right=ast.Constant(value=len(order))))
    pos = 0
    if (new_body and isinstance(new_body[0], ast.Expr)
            and isinstance(new_body[0].value, ast.Constant)
            and isinstance(new_body[0].value.value, str)):
        pos = 1  # keep a leading docstring first
    new_body.insert(pos, init)
    fn.body = new_body
    ast.fix_missing_locations(fn)


class SlotVarPass:
    name = "slotvar"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.slot_vars:
            return tree
        namer = Namer(options.seed, collect_names(tree))
        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        for fn in funcs:
            _slot_function(fn, namer)
        return tree
