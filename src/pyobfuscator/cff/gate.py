from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .diagnostics import Diagnostic, Severity, UnsupportedConstructError
from ..options import UnsupportedPolicy

# Structural sub-nodes that carry no standalone semantic hazard: expression
# contexts and operators. They are always allowed so the allowlist can focus on
# meaningful statements/expressions. Any node type that is neither here nor in a
# SupportSet.allowed is rejected (default-deny) — including future syntax.
STRUCTURAL_NODES = frozenset({
    ast.Module, ast.Expression, ast.Expr, ast.arguments, ast.arg,
    ast.Load, ast.Store, ast.Del,
    ast.And, ast.Or,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd, ast.MatMult,
    ast.UAdd, ast.USub, ast.Not, ast.Invert,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Is, ast.IsNot, ast.In, ast.NotIn,
})


@dataclass(frozen=True)
class SupportSet:
    allowed: frozenset = field(default_factory=frozenset)

    def permits(self, node: ast.AST) -> bool:
        t = type(node)
        return t in self.allowed or t in STRUCTURAL_NODES


class GuardVisitor(ast.NodeVisitor):
    def __init__(self, support: SupportSet):
        self.support = support
        self.diagnostics: list[Diagnostic] = []

    def generic_visit(self, node: ast.AST):
        if not self.support.permits(node):
            self.diagnostics.append(Diagnostic(
                lineno=getattr(node, "lineno", 0),
                col_offset=getattr(node, "col_offset", 0),
                node_type=type(node).__name__,
                message=f"`{type(node).__name__}` is not supported",
                severity=Severity.ERROR,
            ))
        super().generic_visit(node)


def collect_diagnostics(tree: ast.AST, support: SupportSet) -> list[Diagnostic]:
    visitor = GuardVisitor(support)
    visitor.visit(tree)
    return visitor.diagnostics


def enforce(tree, support, policy: UnsupportedPolicy = UnsupportedPolicy.STRICT):
    diags = collect_diagnostics(tree, support)
    errors = [d for d in diags if d.severity is Severity.ERROR]
    if policy is UnsupportedPolicy.STRICT and errors:
        raise UnsupportedConstructError(errors)
    return diags
