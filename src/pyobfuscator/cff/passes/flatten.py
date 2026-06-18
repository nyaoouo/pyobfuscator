from __future__ import annotations

import ast
import random

from ..gate import SupportSet
from ...options import ObfOptions
from ..names import Namer, collect_names
from ..cfg import flatten_function
from ..diagnostics import Diagnostic, UnsupportedConstructError

# Function-body node allowlist. FunctionDef is permitted so the OUTER function
# passes the whole-tree gate; nested FunctionDefs are rejected separately below.
FLATTEN_ALLOWED = frozenset({
    ast.FunctionDef, ast.ClassDef,
    ast.Return, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Pass,
    ast.If, ast.While, ast.For, ast.Break, ast.Continue,
    ast.Try, ast.ExceptHandler, ast.Raise,
    ast.With, ast.withitem,
    ast.Name, ast.Constant, ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.Compare,
    ast.Call, ast.keyword, ast.Attribute, ast.Subscript, ast.Slice,
    ast.Tuple, ast.List, ast.Dict, ast.Set, ast.Starred, ast.IfExp,
    ast.JoinedStr, ast.FormattedValue,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.comprehension, ast.Lambda,
    ast.Import, ast.ImportFrom, ast.alias, ast.Delete,
    ast.NamedExpr,  # walrus `:=` — an opaque expression (binds a local; carried as-is)
    ast.Assert,     # carried as-is (preserves `-O` removal semantics, unlike an if/raise desugar)
})

def _child_scopes(node) -> list:
    """FunctionDefs/ClassDefs directly within `node` (at any block depth), NOT descending
    into a nested scope's own body. For a ClassDef these are its methods + nested classes;
    for a FunctionDef, its nested funcs + nested classes."""
    found: list = []

    def visit(n):
        for child in ast.iter_child_nodes(n):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.append(child)  # do NOT recurse into it here
            else:
                visit(child)

    visit(node)
    return found


class FlattenPass:
    name = "flatten"

    def supports(self) -> SupportSet:
        return SupportSet(allowed=FLATTEN_ALLOWED)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        if not options.safe_mode:
            self._reject_finally(tree)
        seed_base = options.seed or 0
        state_rng = random.Random(seed_base ^ 0x57A7) if options.shuffle_states else None
        bogus_rng = random.Random(seed_base ^ 0xB0C5) if options.bogus_blocks else None
        opaque_rng = random.Random(seed_base ^ 0x09A1) if options.opaque_predicates else None
        tree_rng = random.Random(seed_base ^ 0x7233) if options.dispatch_tree else None
        junk_rng = random.Random(seed_base ^ 0x1234) if options.junk_code else None
        # Cut-markers (Ellipsis Expr) are emitted by the stackcall splitter whenever call-hiding is
        # active (flat cuttable call form is the default), so the Lowerer must consume them as block
        # boundaries in those modes too — not only under the explicit split_calls flag.
        split_markers = options.split_calls or options.stack_calls or options.hide_external_args
        key_consts = options.obf_ints or getattr(options, "const_archive", False) or getattr(options, "name_vault", False)
        bogus_clone_ratio = getattr(options, "bogus_clone_ratio", 0.0)

        # Attestation is only active when pack_body + key_from_cff is also set (oracle is installed
        # by the packer). attest=False (default) => zero change to function processing.
        attest_active = getattr(options, "attest", False)
        # Body self-cohash: seed-derived (guard, hashfn) names shared by every gated unit and the
        # wrap_module-emitted defs; None unless body_cohash is on.
        _cohash = None
        if attest_active:
            from ..attest import (oracle_name as _oracle_name, MAGIC as _MAGIC,
                                  cohash_names as _cohash_names)
            _oracle_name_str = _oracle_name(seed_base)
            if getattr(options, "body_cohash", False):
                _cohash = _cohash_names(seed_base)
            # We use a module-level Namer to get a fresh oracle var name; store on tree later.
            # For functions, the oracle var name must match what wrap_module uses. Since functions
            # share the module globals via globals().setdefault(), the oracle_name_str is the key.
            # We store the oracle_var on tree so wrap_module can use the same name.
            _attest_rng = random.Random(seed_base ^ 0xA77E5710)
            _attest_density = getattr(options, "attest_density", 0.3)
            _attest_inflate = getattr(options, "attest_inflate", False)
            _attest_target_blocks = getattr(options, "attest_target_blocks", 10)
            # Requests accumulator: shared across all function bodies + module body
            # (wrap_module will also append to this if it's set on the tree)
            if not hasattr(tree, "_pyobf_attest"):
                tree._pyobf_attest = []
                tree._pyobf_oracle_name = _oracle_name_str
                # Oracle var name will be set by wrap_module (it allocates the namer)
                # For functions, we need a temporary oracle_var name that will be replaced
                # by the module-level namer in wrap_module. Use a fixed placeholder.
                tree._pyobf_oracle_var = None  # to be filled by wrap_module
        else:
            _attest_rng = None
            _attest_density = 0.3
            _attest_inflate = False
            _attest_target_blocks = 10
            _oracle_name_str = "__pyobf_oracle__"

        if isinstance(tree, (ast.FunctionDef, ast.ClassDef)):
            roots = [tree]
        else:
            roots = [n for n in ast.iter_child_nodes(tree)
                     if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
        for root in roots:
            self._flatten_scope(root, options.seed, options.min_blocks, options.safe_mode, state_rng, bogus_rng, opaque_rng, options.max_block_stmts, options.dedup, options.state_delta, tree_rng, split_markers, junk_rng, key_consts, bogus_clone_ratio,
                                attest_rng=_attest_rng, attest_density=_attest_density,
                                attest_requests=getattr(tree, "_pyobf_attest", None),
                                attest_inflate=_attest_inflate, attest_target_blocks=_attest_target_blocks,
                                oracle_name_str=_oracle_name_str, cohash=_cohash)
        return tree

    def _flatten_scope(self, node, seed, min_blocks: int, safe_mode: bool, state_rng, bogus_rng, opaque_rng, max_block_stmts, dedup: bool = False, state_delta: bool = False, tree_rng=None, split_markers: bool = False, junk_rng=None, key_consts: bool = False, bogus_clone_ratio: float = 0.0,
                       attest_rng=None, attest_density: float = 0.3,
                       attest_requests=None, oracle_name_str: str = "__pyobf_oracle__",
                       attest_inflate: bool = False, attest_target_blocks: int = 10, cohash=None) -> None:
        for child in _child_scopes(node):
            self._flatten_scope(child, seed, min_blocks, safe_mode, state_rng, bogus_rng, opaque_rng, max_block_stmts, dedup, state_delta, tree_rng, split_markers, junk_rng, key_consts, bogus_clone_ratio,
                                attest_rng=attest_rng, attest_density=attest_density,
                                attest_requests=attest_requests, oracle_name_str=oracle_name_str,
                                attest_inflate=attest_inflate, attest_target_blocks=attest_target_blocks, cohash=cohash)
        if isinstance(node, ast.FunctionDef):
            self._flatten(node, seed, min_blocks, safe_mode, state_rng, bogus_rng, opaque_rng, max_block_stmts, dedup, state_delta, tree_rng, split_markers, junk_rng, key_consts, bogus_clone_ratio,
                          attest_rng=attest_rng, attest_density=attest_density,
                          attest_requests=attest_requests, oracle_name_str=oracle_name_str,
                          attest_inflate=attest_inflate, attest_target_blocks=attest_target_blocks, cohash=cohash)

    def _reject_finally(self, fn: ast.AST) -> None:
        diags = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Try) and node.finalbody:
                diags.extend(self._finally_override_diags(node.finalbody))
        if diags:
            raise UnsupportedConstructError(diags)

    def _finally_override_diags(self, finalbody):
        diags = []

        def visit(node, ld):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                return
            if isinstance(node, ast.Return):
                diags.append(Diagnostic(lineno=getattr(node, "lineno", 0),
                                        col_offset=getattr(node, "col_offset", 0),
                                        node_type="Return",
                                        message="return inside a finally is not supported under "
                                                "safe_mode=False (use safe_mode=True)"))
                return
            if isinstance(node, (ast.Break, ast.Continue)):
                if ld == 0:
                    diags.append(Diagnostic(lineno=getattr(node, "lineno", 0),
                                            col_offset=getattr(node, "col_offset", 0),
                                            node_type=type(node).__name__,
                                            message="break/continue crossing a finally is not "
                                                    "supported under safe_mode=False (use safe_mode=True)"))
                return
            if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                for s in node.body:
                    visit(s, ld + 1)
                for s in node.orelse:
                    visit(s, ld)
                return
            for child in ast.iter_child_nodes(node):
                visit(child, ld)

        for s in finalbody:
            visit(s, 0)
        return diags

    def _flatten(self, fn, seed, min_blocks, safe_mode, state_rng, bogus_rng, opaque_rng, max_block_stmts, dedup: bool = False, state_delta: bool = False, tree_rng=None, split_markers: bool = False, junk_rng=None, key_consts: bool = False, bogus_clone_ratio: float = 0.0,
                 attest_rng=None, attest_density: float = 0.3,
                 attest_requests=None, oracle_name_str: str = "__pyobf_oracle__",
                 attest_inflate: bool = False, attest_target_blocks: int = 10, cohash=None) -> None:
        namer = Namer(seed, collect_names(fn))
        # oracle_var is derived from oracle_name_str so it is consistent within a build. Use a STABLE
        # rolling hash, NOT the builtin hash(): builtin hash() of a str is PYTHONHASHSEED-randomized,
        # so it varied per process — and since this var appears in EVERY gated goto, the whole body
        # source (then the packed blob, then the launcher's offsets) became non-deterministic across
        # runs of the same seed. The rolling hash is seed-stable (oracle_name_str is seed-derived).
        _ovh = 0
        for _ch in oracle_name_str:
            _ovh = (_ovh * 131 + ord(_ch)) & 0xFFFF
        oracle_var = f"__pyobf_o_{_ovh:04x}__"
        flatten_function(fn, namer, min_blocks=min_blocks, safe_mode=safe_mode,
                         state_rng=state_rng, bogus_rng=bogus_rng, opaque_rng=opaque_rng,
                         max_block_stmts=max_block_stmts, dedup=dedup,
                         state_delta=state_delta, tree_rng=tree_rng,
                         split_markers=split_markers, junk_rng=junk_rng,
                         key_consts_flag=key_consts,
                         bogus_clone_ratio=bogus_clone_ratio,
                         attest_rng=attest_rng, attest_density=attest_density,
                         attest_requests=attest_requests,
                         attest_inflate=attest_inflate, attest_target_blocks=attest_target_blocks,
                         oracle_var=oracle_var, oracle_name_str=oracle_name_str, cohash=cohash)
