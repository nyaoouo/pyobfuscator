from __future__ import annotations

import ast

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from ..diagnostics import Diagnostic, UnsupportedConstructError
from .flatten import FLATTEN_ALLOWED

_MATCH_NODES = frozenset({
    ast.Match, ast.match_case, ast.MatchValue, ast.MatchSingleton, ast.MatchSequence,
    ast.MatchMapping, ast.MatchClass, ast.MatchStar, ast.MatchAs, ast.MatchOr,
})


def _load(n): return ast.Name(id=n, ctx=ast.Load())
def _assign(n, v): return ast.Assign(targets=[ast.Name(id=n, ctx=ast.Store())], value=v)


def _reject(node, what):
    raise UnsupportedConstructError([Diagnostic(
        lineno=getattr(node, "lineno", 0), col_offset=getattr(node, "col_offset", 0),
        node_type=type(node).__name__,
        message=f"match: {what} is not supported yet (use if/elif, or a supported pattern)")])


class _MatchDesugar(ast.NodeTransformer):
    def __init__(self, namer: Namer):
        self.namer = namer

    def visit_Match(self, node: ast.Match):
        self.generic_visit(node)  # desugar nested matches inside case bodies first
        subj = self.namer.fresh("subj")
        matched = self.namer.fresh("matched")
        out = [_assign(subj, node.subject), _assign(matched, ast.Constant(value=False))]
        for case in node.cases:
            test, binds = self._pattern(case.pattern, _load(subj))
            # innermost: __matched = True; <body>
            run = [_assign(matched, ast.Constant(value=True))] + case.body
            guarded = run if case.guard is None else [
                ast.If(test=case.guard, body=run, orelse=[])]
            inner = [_assign(t, v) for (t, v) in binds] + guarded
            if test is not None:
                inner = [ast.If(test=test, body=inner, orelse=[])]
            out.append(ast.If(
                test=ast.UnaryOp(op=ast.Not(), operand=_load(matched)),
                body=inner, orelse=[]))
        return out  # list replaces the Match node

    def _pattern(self, pat, subj):
        """Return (structural_test_expr_or_None, binds[list of (name, value_expr)])."""
        if isinstance(pat, ast.MatchValue):
            return ast.Compare(left=subj, ops=[ast.Eq()], comparators=[pat.value]), []
        if isinstance(pat, ast.MatchSingleton):
            return ast.Compare(left=subj, ops=[ast.Is()],
                               comparators=[ast.Constant(value=pat.value)]), []
        if isinstance(pat, ast.MatchAs):
            if pat.pattern is None:  # bare capture or wildcard
                binds = [(pat.name, subj)] if pat.name is not None else []
                return None, binds
            # `P as name`: bind only when P matches -> caller emits binds inside the test block
            sub_test, sub_binds = self._pattern(pat.pattern, subj)
            if sub_binds:
                _reject(pat, "`as` over a capturing pattern")
            return sub_test, ([(pat.name, subj)] if pat.name is not None else [])
        if isinstance(pat, ast.MatchOr):
            tests = []
            for p in pat.patterns:
                t, b = self._pattern(p, subj)
                if b or t is None:
                    _reject(pat, "OR pattern with captures/irrefutable alternative")
                tests.append(t)
            return ast.BoolOp(op=ast.Or(), values=tests), []
        _reject(pat, type(pat).__name__)


class _ReturnVar(ast.NodeTransformer):
    def __init__(self, var: str):
        self.var = var

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef
    # NOTE: do NOT override visit_Lambda (lambdas have no return statements)

    def visit_Return(self, node):
        val = node.value if node.value is not None else ast.Constant(value=None)
        return [
            ast.Assign(targets=[ast.Name(id=self.var, ctx=ast.Store())], value=val),
            ast.Return(value=ast.Name(id=self.var, ctx=ast.Load())),
        ]


class NormalizePass:
    name = "normalize"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED | _MATCH_NODES)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        namer = Namer(options.seed, collect_names(tree))
        _MatchDesugar(namer).visit(tree)
        if options.return_var:
            _ReturnVar(namer.fresh("r")).visit(tree)
        ast.fix_missing_locations(tree)
        return tree
