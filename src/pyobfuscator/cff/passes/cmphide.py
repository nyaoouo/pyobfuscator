"""CmpHidePass (flag `hide_compares`) — hide the CONSTANT in user `expr == CONST` / `expr != CONST`
comparisons (int CONST, |CONST| > 1) by rewriting them to `_h(expr) <op> <baked>`, where
`_h(x) = splitmix64(zigzag(x))` and `<baked> = _h(CONST)` is computed at BUILD time.

Why: the compared constant never appears as a plaintext runtime value at/near the comparison, so an
AST-instrumentation differential that reads the comparison operands sees only the 64-bit digest —
to recover CONST it must invert/brute-force the mix. PORTABLE: pure integer math (no co_code),
version-independent, so it works for cross-version TEXT distribution (unlike co_code self-hashing).
It is a BAR-RAISER, not a wall: small CONSTs are brute-forceable from the digest; paired with
body-self-cohash on PYC (which blocks instrumentation entirely) it is fully closed.

Equivalence: `_h(a) == _h(b)  <=>  a == b` because zigzag (64-bit signed->unsigned) ∘ splitmix64 is a
BIJECTION on x ∈ [-2**63, 2**63). Real comparison operands are far inside that range; values outside
(|x| >= 2**63) could collide — astronomically rare, documented. Runs EARLY (after Normalize, before
flatten) so it NEVER touches the dispatcher's own synthetic `state == K`.
"""
from __future__ import annotations

import ast

from ..gate import SupportSet
from ..names import Namer, collect_names
from ...options import ObfOptions
from .flatten import FLATTEN_ALLOWED

_MASK = (1 << 64) - 1
_C0 = 0x9E3779B97F4A7C15   # splitmix64 increment
_C1 = 0xBF58476D1CE4E5B9
_C2 = 0x94D049BB133111EB


def _mix_zz(n: int) -> int:
    """Build-side twin of the emitted helper: splitmix64(zigzag64(n)). Bijective for n ∈ [-2**63, 2**63)."""
    v = ((n << 1) ^ (n >> 63)) & _MASK          # zigzag: 0,-1,1,-2,2,... -> 0,1,2,3,4,...
    v = (v + _C0) & _MASK
    v = ((v ^ (v >> 30)) * _C1) & _MASK
    v = ((v ^ (v >> 27)) * _C2) & _MASK
    return (v ^ (v >> 31)) & _MASK


# The emitted helper MUST compute _mix_zz byte-for-byte (build bakes _mix_zz(CONST); runtime computes
# _h(expr)); any drift breaks the comparison. The body reuses the param name as the accumulator.
_HELPER_TMPL = (
    "def {fn}({x}):\n"
    "    {x} = (({x} << 1) ^ ({x} >> 63)) & {mask}\n"
    "    {x} = ({x} + {c0}) & {mask}\n"
    "    {x} = (({x} ^ {x} >> 30) * {c1}) & {mask}\n"
    "    {x} = (({x} ^ {x} >> 27) * {c2}) & {mask}\n"
    "    return ({x} ^ {x} >> 31) & {mask}\n"
)


def _eligible(node):
    """(side, const) for a single-op == / != Compare with exactly ONE int-Constant operand (|v|>1),
    the other non-constant; else None. (Two constants = constant-fold candidate, leave it.)"""
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))):
        return None
    left, right = node.left, node.comparators[0]
    lc = isinstance(left, ast.Constant) and type(left.value) is int and abs(left.value) > 1
    rc = isinstance(right, ast.Constant) and type(right.value) is int and abs(right.value) > 1
    if lc and not rc:
        return ("left", left.value)
    if rc and not lc:
        return ("right", right.value)
    return None


def _skip_head(body) -> int:
    pos = 0
    while pos < len(body) and (
            (isinstance(body[pos], ast.Expr) and isinstance(body[pos].value, ast.Constant)
             and isinstance(body[pos].value.value, str))
            or (isinstance(body[pos], ast.ImportFrom) and body[pos].module == "__future__")):
        pos += 1
    return pos


class CmpHidePass:
    name = "cmphide"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not getattr(options, "hide_compares", False):
            return tree
        namer = Namer(options.seed, collect_names(tree))
        fn = namer.fresh("h", kind="func")
        used = [False]

        class _Rw(ast.NodeTransformer):
            def visit_Compare(self, node):
                self.generic_visit(node)            # rewrite nested comparisons first
                elig = _eligible(node)
                if elig is None:
                    return node
                side, const = elig
                used[0] = True
                baked = ast.Constant(value=_mix_zz(const))

                def wrap(e):
                    return ast.Call(func=ast.Name(id=fn, ctx=ast.Load()), args=[e], keywords=[])

                if side == "right":      # expr OP const  ->  _h(expr) OP baked
                    node.left = wrap(node.left)
                    node.comparators = [baked]
                else:                    # const OP expr  ->  baked OP _h(expr)
                    node.left = baked
                    node.comparators = [wrap(node.comparators[0])]
                return node

        tree = _Rw().visit(tree)
        if not used[0]:
            return tree
        helper = ast.parse(_HELPER_TMPL.format(fn=fn, x=namer.fresh("v"), mask=_MASK,
                                               c0=_C0, c1=_C1, c2=_C2)).body
        body = (tree.body if isinstance(tree, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
                else None)
        if body is not None:
            pos = _skip_head(body)
            body[pos:pos] = helper
        ast.fix_missing_locations(tree)
        return tree
