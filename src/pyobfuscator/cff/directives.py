from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass

PREFIX = "pyobf:"


@dataclass(frozen=True)
class Directive:
    lineno: int
    text: str  # normalized payload, e.g. "skip", "nocheck", "level=heavy"


def extract_directives(src: str) -> list[Directive]:
    out: list[Directive] = []
    readline = io.StringIO(src).readline
    for tok in tokenize.generate_tokens(readline):
        if tok.type == tokenize.COMMENT:
            body = tok.string.lstrip("#").strip()
            if body.startswith(PREFIX):
                out.append(Directive(lineno=tok.start[0],
                                     text=body[len(PREFIX):].strip()))
    return out


def map_to_defs(tree: ast.AST, directives: list[Directive]) -> dict[Directive, str]:
    """Bind each directive to the name of the def/class on or after its line."""
    defs = sorted(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))),
        key=lambda n: n.lineno,
    )
    mapping: dict[Directive, str] = {}
    for d in directives:
        target = None
        for node in defs:
            if node.lineno >= d.lineno:
                target = node
                break
        if target is not None:
            mapping[d] = target.name
    return mapping
