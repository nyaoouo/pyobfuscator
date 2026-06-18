from __future__ import annotations

import ast
from typing import Protocol, runtime_checkable

from ..gate import SupportSet, enforce
from ...options import ObfOptions


@runtime_checkable
class Pass(Protocol):
    name: str

    def supports(self) -> SupportSet: ...

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST: ...


class Pipeline:
    def __init__(self, passes=()):
        self.passes = list(passes)

    def run(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        for p in self.passes:
            enforce(tree, p.supports(), options.on_unsupported)
            tree = p.transform(tree, options)
        return tree


_REGISTRY: dict[str, Pass] = {}


def register(pass_obj: Pass) -> Pass:
    _REGISTRY[pass_obj.name] = pass_obj
    return pass_obj


def get(name: str) -> Pass:
    return _REGISTRY[name]


def all_passes() -> dict[str, Pass]:
    return dict(_REGISTRY)
