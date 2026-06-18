from __future__ import annotations

import ast
from typing import Protocol, runtime_checkable


@runtime_checkable
class VarStore(Protocol):
    """Abstraction over local/global name access. The default implementation uses identity
    (plain name reads/writes). SlotVarPass can swap in array-slot storage without touching cfg."""

    def read(self, name: str) -> ast.expr: ...
    def write(self, name: str) -> ast.expr: ...


class IdentityVarStore:
    """Names stay real names (no slotting)."""

    def read(self, name: str) -> ast.expr:
        return ast.Name(id=name, ctx=ast.Load())

    def write(self, name: str) -> ast.expr:
        return ast.Name(id=name, ctx=ast.Store())
