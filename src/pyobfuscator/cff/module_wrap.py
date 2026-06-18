from __future__ import annotations

import ast
import random

from .cfg import flatten_module_body
from .names import Namer, collect_names
from ..options import ObfOptions


def _is_docstring(stmt) -> bool:
    return (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str))


def _is_future(stmt) -> bool:
    return isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__"


def wrap_module(tree: ast.AST, options: ObfOptions) -> ast.AST:
    """Flatten a module's top-level body into a module-level dispatcher, keeping the
    module docstring and `__future__` imports as the leading statements (they must come
    first). No-op for non-Module trees or bodies too small to wrap."""
    if not isinstance(tree, ast.Module):
        return tree
    body = tree.body
    head: list = []
    i = 0
    if i < len(body) and _is_docstring(body[i]):
        head.append(body[i]); i += 1
    while i < len(body) and _is_future(body[i]):
        head.append(body[i]); i += 1
    rest = body[i:]
    if not rest:
        return tree
    namer = Namer(options.seed, collect_names(tree))
    seed_base = options.seed or 0
    state_rng = random.Random(seed_base ^ 0x57A7) if options.shuffle_states else None
    bogus_rng = random.Random(seed_base ^ 0xB0C5) if options.bogus_blocks else None
    opaque_rng = random.Random(seed_base ^ 0x09A1) if options.opaque_predicates else None
    tree_rng = random.Random(seed_base ^ 0x7233) if options.dispatch_tree else None
    junk_rng = random.Random(seed_base ^ 0x1234) if options.junk_code else None

    # Attestation: only active when explicitly requested (default attest=False => zero change)
    attest_active = getattr(options, "attest", False)
    _cohash = None   # body self-cohash (guard, hashfn) names; None unless body_cohash on
    if attest_active:
        from .attest import oracle_name as _oracle_name, MAGIC as _MAGIC, cohash_names as _cohash_names
        _oracle_name_str = _oracle_name(seed_base)
        _oracle_var = namer.fresh("oracle")
        if getattr(options, "body_cohash", False):
            _cohash = _cohash_names(seed_base)
        _attest_rng = random.Random(seed_base ^ 0xA77E5710)
        _attest_density = getattr(options, "attest_density", 0.3)
        _attest_inflate = getattr(options, "attest_inflate", False)
        _attest_target_blocks = getattr(options, "attest_target_blocks", 10)
        # Reuse the existing list from FlattenPass (which ran earlier in the pipeline).
        # FlattenPass sets tree._pyobf_attest when attest is active; we append to it.
        if hasattr(tree, "_pyobf_attest"):
            _attest_requests = tree._pyobf_attest
        else:
            _attest_requests = []
        # Store the oracle name/var on the tree so FlattenPass-set values are consistent
        # (both use the same seed, so they agree).
        if hasattr(tree, "_pyobf_oracle_name"):
            # Sanity: should match since same seed
            assert tree._pyobf_oracle_name == _oracle_name_str, (
                f"oracle name mismatch: {tree._pyobf_oracle_name!r} vs {_oracle_name_str!r}")
    else:
        _oracle_name_str = "__pyobf_oracle__"
        _oracle_var = "__pyobf_o__"
        _attest_rng = None
        _attest_density = 0.3
        _attest_inflate = False
        _attest_target_blocks = 10
        _attest_requests = None

    dispatcher = flatten_module_body(rest, namer, min_blocks=options.min_blocks,
                                     safe_mode=options.safe_mode, state_rng=state_rng,
                                     bogus_rng=bogus_rng, opaque_rng=opaque_rng,
                                     max_block_stmts=options.max_block_stmts,
                                     dedup=options.dedup,
                                     state_delta=options.state_delta,
                                     tree_rng=tree_rng,
                                     split_markers=options.split_calls or options.stack_calls or options.hide_external_args,
                                     junk_rng=junk_rng,
                                     key_consts_flag=options.obf_ints or getattr(options, "const_archive", False) or getattr(options, "name_vault", False),
                                     bogus_clone_ratio=getattr(options, "bogus_clone_ratio", 0.0),
                                     attest_rng=_attest_rng,
                                     attest_density=_attest_density,
                                     attest_requests=_attest_requests,
                                     attest_inflate=_attest_inflate,
                                     attest_target_blocks=_attest_target_blocks,
                                     oracle_var=_oracle_var,
                                     oracle_name_str=_oracle_name_str, cohash=_cohash)
    # When body cohash is active and ANY unit got gated, emit the guard + hashfn defs ONCE at the
    # module top (after head). They are spliced AFTER flattening so they stay un-transformed -> their
    # co_code equals the build-side cohash_build_hash() standalone compile. Dunder names survive
    # finalize_names; defined before anything runs, so every unit's `H = hashfn(guard.__code__.co_code)`
    # binding (in flattened functions as well as the module dispatcher) resolves them. This must also
    # cover the dispatcher-is-None case: the module body was too trivial to wrap, but FlattenPass may
    # still have gated function bodies whose bindings reference these defs -> emit them anyway.
    cohash_defs = []
    if _cohash is not None and getattr(tree, "_pyobf_attest", None):
        from .attest import make_cohash_guard_def, make_cohash_hashfn_def
        _gname, _hname = _cohash
        cohash_defs = [make_cohash_guard_def(_gname, seed_base), make_cohash_hashfn_def(_hname)]
    if dispatcher is None:
        if cohash_defs:                      # funcs were gated even though the module wasn't wrapped
            tree.body = head + cohash_defs + rest
            ast.fix_missing_locations(tree)
        return tree  # too trivial to wrap (funcs/classes already flattened)
    tree.body = head + cohash_defs + dispatcher
    # Stash attest requests on the tree (in-memory attribute; not serialized).
    # protect/core.py reads this to patch correction placeholders.
    if attest_active and _attest_requests is not None:
        tree._pyobf_attest = _attest_requests
        tree._pyobf_oracle_name = _oracle_name_str
        tree._pyobf_oracle_var = _oracle_var
    ast.fix_missing_locations(tree)
    return tree
