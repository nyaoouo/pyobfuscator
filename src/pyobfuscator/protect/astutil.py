"""AST-based code generation.

Instead of building launcher source by f-string/`.format` concatenation, we keep the launcher
snippets as REAL code in `_templates.py`, parse that module once, and *instantiate* a snippet by
renaming placeholder identifiers and substituting placeholder loads with concrete values / AST
nodes — then splice the resulting statements into the launcher tree.

  emit_def(name, **b)  -> ast.stmt         the template's (renamed) `def`
  emit_body(name, **b) -> list[ast.stmt]   the template function's body, inline
  emit_expr(name, **b) -> ast.expr         the expression a `return`-template returns

A binding whose value is a `str` renames an identifier; any other value is substituted as a
literal (via its `repr`) or, if it is already an AST node, spliced in as-is.
"""
from __future__ import annotations

import ast
import copy
import inspect

from . import _templates

try:
    _TEMPLATE_SRC = inspect.getsource(_templates)
except OSError:  # pragma: no cover - source-less install
    with open(_templates.__file__, encoding="utf-8") as _f:
        _TEMPLATE_SRC = _f.read()

_TEMPLATE_DEFS = {
    n.name: n for n in ast.parse(_TEMPLATE_SRC).body if isinstance(n, ast.FunctionDef)
}


def _to_node(value):
    """A concrete value -> an AST node. AST nodes pass through; everything else is embedded as
    its literal form (int/bytes/str/bool/None/tuple/list/dict are all valid via repr)."""
    if isinstance(value, ast.AST):
        return value
    return ast.parse(repr(value), mode="eval").body


class _Subst(ast.NodeTransformer):
    def __init__(self, bindings: dict):
        self._renames = {k: v for k, v in bindings.items() if isinstance(v, str)}
        self._values = {k: v for k, v in bindings.items() if not isinstance(v, str)}

    def visit_FunctionDef(self, node):
        if node.name in self._renames:
            node.name = self._renames[node.name]
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        # substitute a placeholder *load* with its concrete value/node
        if isinstance(node.ctx, ast.Load) and node.id in self._values:
            return ast.copy_location(_to_node(self._values[node.id]), node)
        if node.id in self._renames:
            node.id = self._renames[node.id]
        return node


def _instantiate(name: str, bindings: dict) -> ast.FunctionDef:
    node = copy.deepcopy(_TEMPLATE_DEFS[name])
    _Subst(bindings).visit(node)
    ast.fix_missing_locations(node)
    return node


def emit_def(name: str, **bindings) -> ast.stmt:
    """Instantiate a template that IS a function definition (rename via a binding on its name)."""
    return _instantiate(name, bindings)


def emit_body(name: str, **bindings) -> list:
    """Instantiate a template's BODY as a list of statements to splice inline."""
    return _instantiate(name, bindings).body


def emit_expr(name: str, **bindings) -> ast.expr:
    """Instantiate a `return <expr>` template and return the (renamed/substituted) expression."""
    node = _instantiate(name, bindings)
    ret = node.body[-1]
    assert isinstance(ret, ast.Return), f"template {name!r} must end in `return <expr>`"
    return ret.value


def _chain(op, nodes):
    nodes = list(nodes)
    acc = nodes[0]
    for n in nodes[1:]:
        acc = ast.BinOp(left=acc, op=op, right=n)
    return acc


def xor_chain(nodes) -> ast.expr:
    """Left-fold expr nodes into nested `a ^ b ^ c`."""
    return _chain(ast.BitXor(), nodes)


def add_chain(nodes) -> ast.expr:
    """Left-fold expr nodes into nested `a + b + c`."""
    return _chain(ast.Add(), nodes)


def name(ident: str) -> ast.expr:
    return ast.Name(id=ident, ctx=ast.Load())


def mul_const(ident: str, k: int) -> ast.expr:
    """`<ident> * <k>` as an AST node."""
    return ast.BinOp(left=name(ident), op=ast.Mult(), right=ast.Constant(k))


def import_stmt(alias: str, module: str, options) -> ast.stmt:
    """`import <module> as <alias>`, or — under obf_imports — `<alias> = __import__(<chr-codes>)`."""
    if getattr(options, "obf_imports", False):
        return emit_body("t_obf_import", ALIAS=alias, CODES=[ord(c) for c in module])[0]
    return ast.Import(names=[ast.alias(name=module, asname=alias)])


def _imports_pyobf(stmt) -> bool:
    if isinstance(stmt, ast.ImportFrom):
        return (stmt.module or "").split(".")[0] == "pyobfuscator"
    if isinstance(stmt, ast.Import):
        return any(a.name.split(".")[0] == "pyobfuscator" for a in stmt.names)
    return False


class _MagicResolver(ast.NodeTransformer):
    """Rewrite `M.<NAME>` attribute access to the real launcher variable from `magic`."""
    def __init__(self, magic):
        self._magic = magic

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id == "M" and node.attr in self._magic:
            return ast.copy_location(ast.Name(id=self._magic[node.attr], ctx=node.ctx), node)
        return node


def resolve_magic(handler_src: str, magic: dict) -> list:
    """Parse a user handler, drop any `pyobfuscator` import, bind `M.<NAME>` to the real launcher
    variables in `magic`, and return its statements for splicing. Raises on an unknown `M.<NAME>`."""
    tree = ast.parse(handler_src)
    body = [s for s in tree.body if not _imports_pyobf(s)]
    module = ast.Module(body=body, type_ignores=[])
    _MagicResolver(magic).visit(module)
    for node in ast.walk(module):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "M"):
            raise ValueError("handler references unknown magic var M.%s "
                             "(available: %s)" % (node.attr, ", ".join(sorted(magic))))
    ast.fix_missing_locations(module)
    return module.body
