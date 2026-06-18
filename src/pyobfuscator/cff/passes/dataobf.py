from __future__ import annotations

import ast
import random

from ..gate import SupportSet
from ..names import Namer, collect_names
from ...options import ObfOptions
from .flatten import FLATTEN_ALLOWED


# ---------------------------------------------------------------------------
# Miller-Rabin prime helpers
# ---------------------------------------------------------------------------

def _is_prime(num: int) -> bool:
    """Deterministic Miller-Rabin for the ~40-bit primes we generate."""
    if num < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % p == 0:
            return num == p
    d, r = num - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(r - 1):
            x = x * x % num
            if x == num - 1:
                break
        else:
            return False
    return True


def _gen_prime(rng: random.Random, bits: int = 42) -> int:
    while True:
        cand = rng.randrange(1 << (bits - 1), 1 << bits) | 1
        if _is_prime(cand):
            return cand


def _rsa_params(rng: random.Random):
    """Return (e, d, n) with n = p*q (distinct ~42-bit primes => n > 2**64 so any 8-byte chunk
    m < 2**64 < n decodes uniquely; n squarefree => RSA identity holds for ALL m < n)."""
    p = _gen_prime(rng)
    q = _gen_prime(rng)
    while q == p:
        q = _gen_prime(rng)
    n = p * q
    phi = (p - 1) * (q - 1)
    for e in (65537, 257, 17, 5, 3):
        if phi % e != 0:
            try:
                d = pow(e, -1, phi)
            except ValueError:
                continue
            return e, d, n
    raise RuntimeError("no usable RSA exponent")  # essentially never for random primes


# ---------------------------------------------------------------------------
# Powmod chunk encoder
# ---------------------------------------------------------------------------

def _chunks_expr(data: bytes, e: int, n: int) -> ast.List:
    """Encode ``data`` into a list of RSA-encrypted 8-byte little-endian chunks."""
    chunks = [data[i:i + 8] for i in range(0, len(data), 8)] or [b""]
    encs = [pow(int.from_bytes(c, "little"), e, n) for c in chunks]
    return ast.List(elts=[ast.Constant(value=x) for x in encs], ctx=ast.Load())


def _dec_call(data: bytes, e: int, n: int, make_ref) -> ast.Call:
    """Build ``<make_ref()>(<chunks>, <length>)`` call AST."""
    L = len(data)
    chunks = _chunks_expr(data, e, n)
    return ast.Call(
        func=make_ref(),
        args=[chunks, ast.Constant(value=L)],
        keywords=[],
    )


def _str_expr(s: str, e: int, n: int, make_ref) -> ast.expr:
    """Build ``<make_ref()>(<chunks>, <length>).decode()`` for a str literal."""
    data = s.encode("utf-8")
    inner = _dec_call(data, e, n, make_ref)
    return ast.Call(
        func=ast.Attribute(value=inner, attr="decode", ctx=ast.Load()),
        args=[],
        keywords=[],
    )


def _bytes_expr(b: bytes, e: int, n: int, make_ref) -> ast.expr:
    """Build ``<make_ref()>(<chunks>, <length>)`` for a bytes literal."""
    return _dec_call(b, e, n, make_ref)


# ---------------------------------------------------------------------------
# Skip-set: constants that must NOT be encoded
# ---------------------------------------------------------------------------

def _collect_skip(tree: ast.AST) -> set:
    """id()s of Constant nodes that must NOT be rewritten: docstrings, f-string literal
    pieces, and constants inside annotations."""
    skip: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                skip.add(id(body[0].value))
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant):
                    skip.add(id(v))
        anns = []
        if isinstance(node, ast.AnnAssign) and node.annotation is not None:
            anns.append(node.annotation)
        if isinstance(node, ast.arg) and node.annotation is not None:
            anns.append(node.annotation)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            anns.append(node.returns)
        for ann in anns:
            for n in ast.walk(ann):
                if isinstance(n, ast.Constant):
                    skip.add(id(n))
    return skip


# ---------------------------------------------------------------------------
# AST rewriter
# ---------------------------------------------------------------------------

class _Rewriter(ast.NodeTransformer):
    def __init__(self, options: ObfOptions, e: int, n: int, make_ref, skip: set):
        self.options = options
        self.e = e
        self.n = n
        self.make_ref = make_ref
        self.skip = skip
        self.rewrote = False

    def visit_Constant(self, node):
        if id(node) in self.skip:
            return node
        v = node.value
        if self.options.obf_strings and type(v) is str:
            self.rewrote = True
            return ast.copy_location(_str_expr(v, self.e, self.n, self.make_ref), node)
        if self.options.obf_strings and type(v) is bytes:
            self.rewrote = True
            return ast.copy_location(_bytes_expr(v, self.e, self.n, self.make_ref), node)
        return node


# ---------------------------------------------------------------------------
# Decode-helper builder (injected AFTER the rewrite so its own 'little' string
# literal is NOT itself encoded — no bootstrap recursion).
# ---------------------------------------------------------------------------

def _build_dec_helper(dec_name: str, d: int, n: int) -> ast.FunctionDef:
    """Build the AST for:

        def <dec_name>(cs, L):
            b = b"".join(pow(c, <d>, <n>).to_bytes(8, "little") for c in cs)
            return b[:L]
    """
    # pow(c, d, n)
    pow_call = ast.Call(
        func=ast.Name(id="pow", ctx=ast.Load()),
        args=[
            ast.Name(id="c", ctx=ast.Load()),
            ast.Constant(value=d),
            ast.Constant(value=n),
        ],
        keywords=[],
    )
    # .to_bytes(8, "little")
    to_bytes_call = ast.Call(
        func=ast.Attribute(value=pow_call, attr="to_bytes", ctx=ast.Load()),
        args=[ast.Constant(value=8), ast.Constant(value="little")],
        keywords=[],
    )
    # generator: pow(c, d, n).to_bytes(8, "little") for c in cs
    gen = ast.GeneratorExp(
        elt=to_bytes_call,
        generators=[
            ast.comprehension(
                target=ast.Name(id="c", ctx=ast.Store()),
                iter=ast.Name(id="cs", ctx=ast.Load()),
                ifs=[],
                is_async=0,
            )
        ],
    )
    # b"".join(...)
    join_call = ast.Call(
        func=ast.Attribute(value=ast.Constant(value=b""), attr="join", ctx=ast.Load()),
        args=[gen],
        keywords=[],
    )
    # b = b"".join(...)
    assign_b = ast.Assign(
        targets=[ast.Name(id="b", ctx=ast.Store())],
        value=join_call,
        lineno=0, col_offset=0,
    )
    # return b[:L]
    return_stmt = ast.Return(
        value=ast.Subscript(
            value=ast.Name(id="b", ctx=ast.Load()),
            slice=ast.Slice(upper=ast.Name(id="L", ctx=ast.Load())),
            ctx=ast.Load(),
        )
    )
    fn = ast.FunctionDef(
        name=dec_name,
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="cs"), ast.arg(arg="L")],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=[assign_b, return_stmt],
        decorator_list=[],
        returns=None,
        lineno=0, col_offset=0,
    )
    # At injection: rename the helper's literal params/locals (cs/L/...) to fresh obfuscator names.
    from .localrename import rename_simple_helper_locals
    rename_simple_helper_locals(ast.Module(body=[fn], type_ignores=[]))
    return fn


# ---------------------------------------------------------------------------
# Pass
# ---------------------------------------------------------------------------

class DataObfPass:
    name = "dataobf"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.obf_strings:
            return tree

        seed = options.seed if options.seed is not None else 0
        rng = random.Random(seed)
        e, d, n = _rsa_params(rng)

        # Allocate both names from ONE shared Namer so they are distinct and collision-free
        namer = Namer(seed, collect_names(tree))
        dec_name = namer.fresh("dec")
        use_dict = bool(options.dict_indirect)
        if use_dict:
            ds_name = namer.fresh("D")
            ds_key = rng.randrange(0, 1 << 16)
            make_ref = lambda: ast.Subscript(
                value=ast.Name(id=ds_name, ctx=ast.Load()),
                slice=ast.Constant(value=ds_key),
                ctx=ast.Load(),
            )
        else:
            make_ref = lambda: ast.Name(id=dec_name, ctx=ast.Load())

        skip = _collect_skip(tree)
        rw = _Rewriter(options, e, n, make_ref, skip)
        rw.visit(tree)

        # Inject the helper AFTER the rewrite so its own string literals ('little') are
        # NOT themselves encoded (prevents bootstrap recursion).
        if rw.rewrote:
            helper = _build_dec_helper(dec_name, d, n)
            ast.fix_missing_locations(helper)

            if isinstance(tree, ast.Module):
                body = tree.body
            elif isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = tree.body
            else:
                body = None

            if body is not None:
                # Find insertion point: after docstring and __future__ imports
                pos = 0
                while pos < len(body) and (
                    (isinstance(body[pos], ast.Expr)
                     and isinstance(body[pos].value, ast.Constant)
                     and isinstance(body[pos].value.value, str))
                    or (isinstance(body[pos], ast.ImportFrom)
                        and body[pos].module == "__future__")):
                    pos += 1
                # Build ordered splice: ds={}, helper def, ds[KEY]=_dec
                to_insert = []
                if use_dict:
                    to_insert.append(ast.Assign(
                        targets=[ast.Name(id=ds_name, ctx=ast.Store())],
                        value=ast.Dict(keys=[], values=[]),
                        lineno=0, col_offset=0,
                    ))
                to_insert.append(helper)
                if use_dict:
                    to_insert.append(ast.Assign(
                        targets=[ast.Subscript(
                            value=ast.Name(id=ds_name, ctx=ast.Load()),
                            slice=ast.Constant(value=ds_key),
                            ctx=ast.Store(),
                        )],
                        value=ast.Name(id=dec_name, ctx=ast.Load()),
                        lineno=0, col_offset=0,
                    ))
                body[pos:pos] = to_insert

        ast.fix_missing_locations(tree)
        return tree
