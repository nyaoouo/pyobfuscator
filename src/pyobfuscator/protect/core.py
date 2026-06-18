"""Launcher/body packer orchestration.

`pack_module` replaces an already-obfuscated module tree with a launcher module that carries the
body as an encrypted blob and decrypts+execs it at runtime. The launcher is assembled from REAL
code templates (`_templates.py`) instantiated via `astutil` (rename placeholders + substitute
values) and spliced as AST — NOT by f-string/`.format` code concatenation. Layers:
  - packer skeleton (temp key) when key_from_cff is off;
  - control-flow-derived key (fold over the launcher's correct dispatch path);
  - branchless decoy + builtin-identity integrity;
  - detection aggregate folded into the selector (key_binds_env) — see `detectors.py`;
  - obfuscated launcher imports.
Behaviour on the untampered path is identical to the body; tamper/detection ⇒ decoy.
"""
from __future__ import annotations

import ast
import base64
import random
from dataclasses import replace

from ..cff.names import Namer, collect_names
from ..cff.attest import (mix as _attest_mix, oracle_name as _attest_oracle_name,
                          MAGIC as _attest_MAGIC, name_to_charcode_expr as _attest_name_expr)
from ..options import ObfOptions, OutputFormat
from .cipher import (
    _MASK, _TEMP_KEY, _SALT_SEL, _SALT_KEY, _SALT_DECOY, _BI_MAGIC, _D_MAGIC, _P_MAGIC,
    _kdf, _fold, _ks_xor, _hash_bytes,
)
from .templates import _DEFAULT_DECOY, _resolve_format, _body_bytes, _decoy_bytes
from .detectors import build_detection
from . import astutil
from .astutil import emit_def, emit_body, import_stmt


_BODY_NS_SALT = 0x42B0D9   # body's finalize namespace, disjoint from the launcher's (they share
                           # globals via exec(body, launcher_globals), so their module-level names
                           # MUST NOT overlap — the body's const_archive _get/_ks/_kdf functions
                           # would overwrite the launcher's identically-named dispatcher variable).
                           # The launcher is finalized in emit() with the default ns_salt=0, so the
                           # two namespaces never collide.
_DECOY_NS_SALT = 0x5EC0D9  # the (optionally obfuscated) decoy's finalize namespace — a THIRD disjoint
                           # space. The decoy execs in the launcher's globals when the selector picks
                           # it (mutually exclusive with the body), so it must not collide with the
                           # launcher (default salt); a distinct salt also keeps it independent of the
                           # body. Used only when obf_module pre-obfuscates the decoy (pack_decoy).


def _as_module(stmts) -> ast.Module:
    module = ast.Module(body=stmts, type_ignores=[])
    ast.fix_missing_locations(module)
    return module


def _inner_fname(options) -> str:
    """Per-build randomized co_filename for the inner (body) code object. An in-process audit-hook
    dump that arms on `event == 'exec'` with `co.co_filename == '<pyobf>'` detects exactly when the
    inner layer runs. Randomizing the name breaks that fixed-string match; the angle-bracket form is
    kept so CPython does no source-file lookup for tracebacks. Seed-derived so build output stays
    deterministic (dedicated rng stream — does not perturb the Namer)."""
    rng = random.Random((options.seed or 0) ^ 0xF11E0C)
    return "<%08x>" % rng.randrange(1 << 32)


def _needs_audit_cell(options) -> bool:
    """Whether to allocate the audit-tripwire poison cell + install our audit hook. The cell is
    shared infra read by the AuditDetector (detect_audit), the attest oracle (attest_runtime_bind),
    and the set-API neuter (anti_trace_neuter)."""
    return bool(getattr(options, "detect_audit", False)
                or getattr(options, "attest_runtime_bind", False)
                or getattr(options, "anti_trace_neuter", False))


def _emit_neuter(options, fmt, namer, n_cell, n_sys) -> list:
    """Neuter the Python-level debug set-APIs before the body exec. Default = blackhole a tracer
    install (``settrace(None)`` still passes through for harmless cleanup) + trip the poison cell;
    honeypot (``anti_trace_neuter_honeypot``) = poison + SystemExit. The reliable APIs
    (settrace/setprofile/addaudithook/threading) are patched unconditionally and a PASSIVE self-check
    confirms the patch took (poison if not); ``sys.monitoring`` (PEP 669) is best-effort — a source
    build always emits it behind try/except (cross-version), a bytecode build emits it only when the
    version-locked build interpreter has it."""
    import sys as _bsys
    honeypot = bool(getattr(options, "anti_trace_neuter_honeypot", False))
    factory = "t_neuter_factory_honeypot" if honeypot else "t_neuter_factory_blackhole"
    n_mk, n_thr = namer.fresh("mk"), namer.fresh("thr")
    stmts = [emit_def(factory, **{factory: n_mk})]
    stmts += emit_body("t_neuter_set", SYS=n_sys, MK=n_mk, CELL=n_cell)
    stmts.append(import_stmt(n_thr, "threading", options))
    stmts += emit_body("t_neuter_threading", THREADING=n_thr, MK=n_mk, CELL=n_cell)
    if fmt == "source" or _bsys.version_info >= (3, 12):
        stmts += emit_body("t_neuter_monitoring_safe", SYS=n_sys, CELL=n_cell)
    stmts += emit_body("t_neuter_selfcheck", SYS=n_sys, CELL=n_cell)
    return stmts


_DEFAULT_BI_CHECKS = ("compile", "exec", "pow", "sum", "open", "len")


def _choose_bi(options):
    """Select this build's builtin-integrity check set. `builtin_checks` (configurable) each get a
    RELATIVE type-identity term (`type(X) is BT`); a per-build RANDOM subset of size
    `builtin_spot_count` additionally gets an ABSOLUTE "is X a Python-defined function?" term
    (`not hasattr(X, '__code__')`). The absolute term does not depend on any reference builtin, so
    it still fires when every builtin is replaced uniformly (the blind spot of the relative-only
    check). Returns (checks, spot, clean_value) where clean_value is what the summed terms evaluate
    to in a clean environment (== len(checks) + len(spot)); the build folds it into s_correct."""
    checks = tuple(getattr(options, "builtin_checks", None) or _DEFAULT_BI_CHECKS)
    spot_n = max(0, min(len(checks), getattr(options, "builtin_spot_count", 3)))
    rng = random.Random((options.seed or 0) ^ 0xB1C7EC)
    spot = rng.sample(list(checks), spot_n) if spot_n else []
    return checks, spot, len(checks) + len(spot)


# Builtins checked via the EFFECTIVE (global-or-builtin) binding rather than the bare/vaulted name.
# These are the ones the exec tail actually CALLS, so a GLOBAL shadow of them (e.g. a static
# layer-peeler that captures the first compile(), or any global rebind) must be detected — a
# bare/vaulted `type(compile) is BT` reads builtins.compile and is blind to a global shadow.
# `compile`/`exec` are exactly what such a peeler hooks AND what the tail runs with, so checking +
# executing with the SAME effective binding closes the gap: clean -> the fallback (real builtin) ->
# BT; shadowed -> the shadow -> not BT -> decoy.
_BI_EFFECTIVE = ("compile", "exec")


def _eff_ref(n_g, nm):
    """`<G>.get("<nm>", <nm>)` — the EFFECTIVE binding of builtin `nm`: a global shadow when present
    in the launcher globals, else the fallback (the bare/vaulted real builtin). One node per call
    (no aliasing)."""
    return ast.Call(
        func=ast.Attribute(value=ast.Name(id=n_g, ctx=ast.Load()), attr="get", ctx=ast.Load()),
        args=[ast.Constant(value=nm), ast.Name(id=nm, ctx=ast.Load())], keywords=[])


def _exec_compile_refs(n_g):
    """(XF, CF, GLB) AST nodes for an exec tail. n_g None -> plain `exec` / `compile` / `globals()`;
    else the global-effective `G.get('exec', exec)` / `G.get('compile', compile)` / `G`. With the
    effective form a static layer-peeler that captures the first compile() receives the decoy
    payload, while the genuine path uses the real builtin via the `.get` fallback."""
    if not n_g:
        return (ast.Name(id="exec", ctx=ast.Load()), ast.Name(id="compile", ctx=ast.Load()),
                ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]))
    return _eff_ref(n_g, "exec"), _eff_ref(n_g, "compile"), ast.Name(id=n_g, ctx=ast.Load())


def _emit_bi(checks, spot, namer, n_bt, n_bi, n_g=None):
    """Emit the builtin-integrity prologue:
        BT = type(''.join)
        BIVAL = (type(c) is BT for c in checks)  +  int(not hasattr(s, '__code__')) for s in spot
    Each term is 1 in a clean env; a builtin replaced by a Python def lowers BIVAL -> wrong key
    selector -> branchless decoy. Built programmatically (not a fixed template) so the checked set
    and the random spot-check subset are build-configurable. `compile`/`exec` (when n_g is given) are
    checked via the effective binding `type(G.get("X", X)) is BT` (catches a global shadow too) —
    same term count, so the clean fold value is unchanged."""
    stmts = []
    terms = []
    if checks:
        stmts += emit_body("t_bi_bt", BT=n_bt)
        for nm in checks:
            if n_g and nm in _BI_EFFECTIVE:
                terms.append(ast.Compare(
                    left=ast.Call(func=ast.Name(id="type", ctx=ast.Load()),
                                  args=[_eff_ref(n_g, nm)], keywords=[]),
                    ops=[ast.Is()], comparators=[ast.Name(id=n_bt, ctx=ast.Load())]))
            else:
                terms.append(astutil.emit_expr("t_bi_rel", X=nm, BT=n_bt))
    terms += [astutil.emit_expr("t_bi_abs", X=nm) for nm in spot]
    value = astutil.add_chain(terms) if terms else ast.Constant(value=0)
    stmts += emit_body("t_assign", NAME=n_bi, VALUE=value)
    return stmts


def _flatten_launcher(module: ast.Module, options, top_defs=()) -> ast.Module:
    # Flatten the launcher so the fold/detection live inside the dispatcher (control-flow tamper
    # ⇒ wrong key). obf_strings=False so the encrypted blob is not powmod-expanded; pack_body=False
    # to avoid recursion. attest=False so the launcher itself is NOT gated (the oracle attestation
    # only applies to the body, not the launcher which installs the oracle).
    # Imported lazily to avoid an import cycle with the package __init__.
    from .. import _MODULE_PIPELINE
    from ..cff.module_wrap import wrap_module
    # Cap launcher block size so no single dispatcher state is a giant tell (esp. the blob-chunk
    # assignments) — split_blocks scatters oversized blocks across states (behaviour-preserving).
    lopts = replace(options, obf_strings=False, pack_body=False, attest=False,
                    max_block_stmts=(options.max_block_stmts or 12))
    # name_vault / name_vault_attrs / const_archive are safe on the launcher and are intentionally
    # INHERITED from `options` (not disabled): the body and the launcher are finalized from DISJOINT
    # _pyobf_<hex> namespaces (body = _BODY_NS_SALT, launcher = default salt 0 in emit()), so the
    # body's module-level const_archive accessors can no longer overwrite the launcher's identically-
    # named dispatcher variable through the shared exec globals. With that overlap gone, vaulting the
    # launcher's own glue routes correctly AND pools the detect_* attr-name strings (sys.settrace /
    # gettrace / monitoring.set_events / addaudithook / breakpoint ...) into the encrypted archive,
    # hiding the anti-debug surface that was previously plaintext in the launcher.
    if _needs_audit_cell(options):
        # The anti-TOCTOU machinery (audit-hook lambda, oracle closure with gt()/type(pw) calls,
        # neuter guard) lives in lambdas/closures the call-routing transforms corrupt (they descend
        # into the closures and reroute external-call args through the thread-local arg stack ->
        # AttributeError at runtime). Disable those flags FOR THE LAUNCHER ONLY when the machinery
        # is present; the launcher's strength still comes from the dispatcher flatten + key fold +
        # integrity, not from call-arg hiding. The body keeps all flags.
        lopts = replace(lopts, stack_calls=False, hide_external_args=False, split_calls=False,
                        dict_indirect=False, slot_vars=False)
    module = _MODULE_PIPELINE.run(module, lopts)
    module = wrap_module(module, lopts)
    if top_defs:
        # Inject guard defs at the top AFTER flattening so their co_code stays un-transformed and
        # equals the build-side standalone compile (cohash integrity).
        module.body = list(top_defs) + module.body
    ast.fix_missing_locations(module)
    return module


def _guard_cohash(guard_def, gname) -> int:
    """Build-side FNV-1a of the guard function's co_code (compiled standalone). Matches the runtime
    `hash(guard.__code__.co_code)`: the guard is self-contained (only a parameter + literals) and is
    injected un-flattened, so its co_code is context-independent."""
    import copy
    mod = ast.Module(body=[copy.deepcopy(guard_def)], type_ignores=[])
    ast.fix_missing_locations(mod)
    code = compile(mod, "<guard>", "exec")
    gco = next(c for c in code.co_consts
               if hasattr(c, "co_code") and getattr(c, "co_name", None) == gname)
    return _hash_bytes(gco.co_code)


def _emit_blob_assign(n_blob, raw: bytes, options, namer) -> list:
    """Bind the blob variable. TEXT output embeds it as `base64.b85decode(b'<ascii>')` — b85 is
    ~1.25x vs ~2.87x for a raw `b'\\xNN'` literal in source. PYC/AST output embeds the raw bytes
    literal (optimal in a compiled/binary container; b85 would only bloat it). AST is treated as
    PYC (it never reaches pack_module, but raw is the safe choice if it ever does)."""
    if options.output is OutputFormat.TEXT:
        n_b64 = namer.fresh("b6")
        ascii_blob = base64.b85encode(raw)
        stmts = [import_stmt(n_b64, "base64", options)]
        # Split a large blob into per-chunk assignments so no single source line is a giant literal.
        # The launcher flatten's max_block_stmts then scatters these chunk assignments across
        # dispatcher states. Small blobs keep the simple one-liner. b''.join-via-`+` concat
        # reconstructs it; execution order (and so the concat) is preserved by the dispatcher.
        _CHUNK = 3072
        if len(ascii_blob) <= _CHUNK:
            return stmts + emit_body("t_assign_b85", NAME=n_blob, B64=n_b64, ASCII=ascii_blob)
        pieces = [ascii_blob[i:i + _CHUNK] for i in range(0, len(ascii_blob), _CHUNK)]
        cvars = []
        for p in pieces:
            cv = namer.fresh("bc")
            cvars.append(cv)
            chunk = ast.Constant(value=p)
            chunk._pyobf_no_archive = True   # prevent const_archive from re-pooling the chunks
            # back into one giant archive-blob literal (that would re-create the split's purpose)
            stmts.append(ast.Assign(targets=[ast.Name(id=cv, ctx=ast.Store())], value=chunk))
        concat = ast.Name(id=cvars[0], ctx=ast.Load())
        for cv in cvars[1:]:
            concat = ast.BinOp(left=concat, op=ast.Add(), right=ast.Name(id=cv, ctx=ast.Load()))
        stmts.append(ast.Assign(
            targets=[ast.Name(id=n_blob, ctx=ast.Store())],
            value=ast.Call(func=ast.Attribute(value=ast.Name(id=n_b64, ctx=ast.Load()),
                                              attr="b85decode", ctx=ast.Load()),
                           args=[concat], keywords=[])))
        return stmts
    return emit_body("t_assign", NAME=n_blob, VALUE=raw)


def _single_tail(fmt, options, namer, ks, blob, key, fname="<pyobf>", n_g=None):
    """Non-decoy tail: decompress + decrypt + exec the single blob in the launcher's globals.
    `fname` sets the inner code object's co_filename on the source path (runtime compile);
    the bytecode path bakes it in `_body_bytes`. `n_g` (when set) routes exec/compile/globals through
    the global-effective refs (see _exec_compile_refs)."""
    zl = namer.fresh("zl")
    head = [import_stmt(zl, "zlib", options)]
    xf, cf, glb = _exec_compile_refs(n_g)
    if fmt == "source":
        return head + emit_body("t_single_tail_src", KS=ks, BLOB=blob, KEY=key, ZLIB=zl,
                                FNAME=ast.Constant(value=fname), XF=xf, CF=cf, GLB=glb)
    mar = namer.fresh("mar")
    return head + [import_stmt(mar, "marshal", options)] + emit_body(
        "t_single_tail_bc", KS=ks, BLOB=blob, KEY=key, MAR=mar, ZLIB=zl, XF=xf, GLB=glb)


def _patch_attest_markers(tree: ast.Module, requests: list, s_correct: int,
                          magic: int, state_delta: bool, h_build: int = 0) -> None:
    """Replace __pyobf_corr_<id>__ Name placeholders in the body AST with the computed
    CORRECTION constants. Must be called BEFORE serializing the body to bytes.

    For each (marker_id, s, T, is_delta) request:
      - is_delta=False (absolute): CORRECTION = (T ^ mix(s, s_correct, magic) ^ H_build) & MASK
        The goto `state = O(state) [^ H] ^ CORRECTION` then evaluates to:
        mix(s,...) ^ H ^ (T ^ mix(s,...) ^ H_build) = T ^ (H ^ H_build) = T  when H == H_build  ✓
      - is_delta=True (relative): CORRECTION = (T - s) ^ mix(s, s_correct, magic) ^ H_build
        The goto `state += (O(state) [^ H] ^ CORRECTION)` evaluates to:
        s + (mix(s,...) ^ H ^ ((T-s) ^ mix(s,...) ^ H_build))  [XOR cancels]
        = s + (T - s)  when H == H_build  [Python unbounded ints: exact, no masking]
        = T  ✓
        NOTE: NO & MASK — Python ints are unbounded, masking a negative delta would give
        a huge positive (2^64 + delta), making state != T for T < s.

    `h_build` (body self-cohash, PYC-only) is the build-side FNV of the body guard's co_code; it
    is 0 unless body_cohash is active. When non-zero, the body's gates emit a matching `^ H` runtime
    term (H = the same hash recomputed at runtime); on the genuine path H == h_build so the two cancel
    and the path is unchanged, while any co_code tamper (instrumentation/recompile) flips H -> wrong
    state. cff emits `^ H` iff body_cohash is on, so the gate term and this fold are keyed together.
    """
    # Build correction map: marker_name -> Constant(CORRECTION)
    _MASK64 = (1 << 64) - 1
    corrections = {}
    for (mid, s, T, is_delta) in requests:
        marker_name = f"__pyobf_corr_{mid}__"
        mix_val = _attest_mix(s, s_correct, magic)
        if is_delta:
            # No masking: Python unbounded ints handle negative deltas (T - s) correctly.
            correction = (T - s) ^ mix_val ^ h_build
        else:
            correction = (T ^ mix_val ^ h_build) & _MASK64
        corrections[marker_name] = correction

    if not corrections:
        return

    class _MarkerReplace(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in corrections:
                return ast.copy_location(ast.Constant(value=corrections[node.id]), node)
            return node

    _MarkerReplace().visit(tree)
    ast.fix_missing_locations(tree)


def pack_module(tree: ast.AST, options: ObfOptions, *, sourcemap_out: dict | None = None,
                decoy_tree: ast.AST | None = None) -> ast.AST:
    """Return a launcher Module whose execution reproduces `tree` (a Module) in its own
    globals. Only meaningful for Module trees; returns `tree` unchanged otherwise.

    When emit_sourcemap is on and `sourcemap_out` is supplied, the BODY layer map and the readable
    body payload (the obfuscated-but-not-yet-encrypted source that lives inside the blob) are placed
    in the sink as `sourcemap_out['body']` / `['body_src']`."""
    if not isinstance(tree, ast.Module):
        return tree
    module, guard_inject, _regions, do_flatten = _assemble_launcher(tree, options,
                                                                    sourcemap_out=sourcemap_out,
                                                                    decoy_tree=decoy_tree)
    if not do_flatten:
        return module
    return _flatten_launcher(module, options, guard_inject)


def _assemble_launcher(tree: ast.AST, options: ObfOptions, *, sourcemap_out: dict | None = None,
                       decoy_tree: ast.AST | None = None):
    """Build the launcher module BEFORE the final flatten. Returns
    `(module, guard_inject, regions, do_flatten)`:
      - `module`        the assembled (pre-flatten) launcher;
      - `guard_inject`  un-flattened guard defs spliced in after flatten (cohash);
      - `regions`       list of `(label, stmt_start, stmt_end)` over `module.body` — pure
                        bookkeeping for the visualizer, it never alters `stmts`;
      - `do_flatten`    False for the temp-key path (returned un-flattened), True otherwise.
    pack_module = `_flatten_launcher(module, options, guard_inject)` when `do_flatten`."""
    assert isinstance(tree, ast.Module)
    # Finalize the BODY tree's monotonic temp names (_pyobf_g<n> from Namer.fresh, minted by every
    # pass that ran on the body) to uniform _pyobf_<hex> BEFORE it is serialized by _body_bytes. The
    # body is serialized inside this function, so emit()'s final-rename never sees it; we must do it
    # here. Runs before _patch_attest_markers too, but that is irrelevant: the attest CORRECTION /
    # oracle names are double-underscore (`__pyobf_corr_*__`, `__pyobf_oracle_*__`) and NOT in
    # _GEN_ISSUED, so finalize_names provably leaves them untouched (body<->launcher oracle agreement
    # is preserved). The launcher tree built below uses its OWN fresh() temp names, finalized later by
    # emit() with the DEFAULT salt (ns_salt=0). We finalize the body with _BODY_NS_SALT so the two
    # _pyobf_<hex> namespaces are DISJOINT: the body is exec'd in the launcher's globals, so a
    # module-level name shared between them would let the body's const_archive _get/_ks/_kdf functions
    # overwrite the launcher's identically-named dispatcher variable (key-stack list) -> the launcher's
    # `key_stack.pop()` then runs on a function -> AttributeError. Disjoint salts make that impossible,
    # which is what lets const_archive (+ name_vault) run on BOTH the body and the launcher.
    from ..cff.lambdalift import lift_lambdas
    lift_lambdas(tree)   # body: lift attest decoy/oracle lambdas to defs before serialization
    from ..cff.rename import finalize_names
    body_om = {} if (getattr(options, "emit_sourcemap", False) and sourcemap_out is not None) else None
    finalize_names(tree, options.seed, ns_salt=_BODY_NS_SALT, out_map=body_om)
    if body_om is not None:
        # The body payload (readable obfuscated source that lives, encrypted, inside the blob) + its
        # map. Both ast.unparse and build_sourcemap are read-only, so the serialized blob — and thus
        # the launcher — stay byte-identical whether or not the sourcemap is requested.
        from ..cff.sourcemap import build_sourcemap
        sourcemap_out["body"] = build_sourcemap(tree, body_om, layer="body", seed=options.seed,
                                                source=None, artifact=None)
        sourcemap_out["body_src"] = ast.unparse(tree)

    fmt = _resolve_format(options)
    fname = _inner_fname(options)            # per-build randomized inner co_filename
    namer = Namer(options.seed, collect_names(tree))
    n_blob, n_ks = namer.fresh("blob"), namer.fresh("ks")
    regions = []

    if not options.key_from_cff:
        # Temporary hardcoded key path. NOT flattened.
        body_bytes = _body_bytes(tree, fmt, fname)
        blob = _ks_xor(body_bytes, _TEMP_KEY)
        stmts = [emit_def("t_ks", t_ks=n_ks)]
        stmts += _emit_blob_assign(n_blob, blob, options, namer)
        stmts += _single_tail(fmt, options, namer, n_ks, n_blob, _TEMP_KEY, fname)
        regions.append(("payload + exec tail (temp key)", 0, len(stmts)))
        return _as_module(stmts), (), regions, False

    # --- control-flow-derived key + optional builtin-fold + decoy + detection ---
    rng = random.Random((options.seed or 0) ^ 0x5EED2A)
    steps = [((rng.randrange(3, 1 << 32) | 1), rng.randrange(0, 1 << 48)) for _ in range(6)]
    seed0 = rng.randrange(0, 1 << 48)
    s_path = _fold(seed0, steps)

    use_bi = options.integrity_selfcheck
    fold_bi = use_bi or options.pack_decoy
    _bi_checks, _bi_spot, _bi_clean = _choose_bi(options)
    s_correct = (s_path ^ (_bi_clean * _BI_MAGIC)) & _MASK if fold_bi else s_path

    n_acc, n_kdf = namer.fresh("acc"), namer.fresh("kdf")
    n_S, n_ent, n_bi = namer.fresh("S"), namer.fresh("ent"), namer.fresh("bi")
    n_bt, n_table = namer.fresh("bt"), namer.fresh("tab")
    # Captured globals dict — only needed when builtin-integrity runs (use_bi), where it lets the
    # compile/exec terms AND the exec tail read the EFFECTIVE (global-or-builtin) binding so a global
    # compile/exec shadow is detected -> wrong key -> decoy, and the tail's effective compile feeds
    # any such shadow the decoy slice. None -> plain refs.
    n_g = namer.fresh("g") if use_bi else None

    _r0 = 0  # region cursor: index of the next region's first statement
    stmts = list(emit_body("t_seed", ACC=n_acc, SEED0=seed0))
    for m, c in steps:
        stmts += emit_body("t_step", ACC=n_acc, M=m, C=c)
    stmts.append(emit_def("t_kdf", t_kdf=n_kdf))
    stmts.append(emit_def("t_ks", t_ks=n_ks))
    if n_g:
        stmts += emit_body("t_capture_globals", G=n_g)
    if use_bi:
        stmts += _emit_bi(_bi_checks, _bi_spot, namer, n_bt, n_bi, n_g)
    else:
        stmts += emit_body("t_assign", NAME=n_bi, VALUE=_bi_clean)
    regions.append(("key fold + integrity", _r0, len(stmts)))
    _r0 = len(stmts)

    # Audit-tripwire poison cell + our own audit hook (shared infra also read by the attest
    # oracle and the set-API neuter). Emitted before detection so AuditDetector reads it,
    # and before the exec tail so the hook is live when an attacker settraces during the body exec.
    n_cell = None
    n_audit_sys = None     # hoisted: reused by the oracle (gettrace/getprofile) and neuter
    if _needs_audit_cell(options):
        n_cell = namer.fresh("cell")
        n_audit_sys = namer.fresh("sys")
        stmts += emit_body("t_audit_cell", CELL=n_cell)
        stmts.append(import_stmt(n_audit_sys, "sys", options))
        stmts += emit_body("t_audit_install", SYS=n_audit_sys, CELL=n_cell)
        regions.append(("audit tripwire", _r0, len(stmts)))
    _r0 = len(stmts)

    det_stmts, n_dvar, magic = build_detection(options, namer, poison_cell=n_cell)
    stmts += det_stmts
    if det_stmts:
        regions.append(("detection", _r0, len(stmts)))
    _r0 = len(stmts)

    # Optional user honeypot handler (build-input): reads M.<signal> vars, may set M.POISON.
    # POISON folds into the selector like the detection aggregate; build assumes POISON == 0.
    n_poison = None
    if getattr(options, "handler_src", None):
        n_poison = namer.fresh("p")
        stmts += emit_body("t_assign", NAME=n_poison, VALUE=0)
        stmts += astutil.resolve_magic(options.handler_src, {**magic, "POISON": n_poison})
        regions.append(("honeypot handler", _r0, len(stmts)))
    _r0 = len(stmts)

    # Optional co_code integrity: a non-flattened guard fn whose co_code hash folds into S.
    # Patching the guard's bytes -> different hash -> wrong selector -> decoy.
    guard_inject = ()
    n_h = None
    if options.cohash_integrity:
        n_guard, n_hfn, n_h = namer.fresh("g"), namer.fresh("hfn"), namer.fresh("h")
        guard_def = emit_def("t_guard", t_guard=n_guard)
        s_correct = (s_correct ^ _guard_cohash(guard_def, n_guard)) & _MASK
        stmts.append(emit_def("t_hashfn", t_hashfn=n_hfn))
        stmts += emit_body("t_cohash", HVAR=n_h, HFN=n_hfn, GUARD=n_guard)
        guard_inject = (emit_def("t_guard", t_guard=n_guard),)
        regions.append(("cohash integrity", _r0, len(stmts)))
    _r0 = len(stmts)

    # --- Attestation (cff <-> python oracle channel) ---
    # If attest is active, patch CORRECTION placeholders in the body AST using s_correct,
    # THEN install the oracle into the launcher stmts BEFORE the exec tail.
    # The oracle is a closure: O(s) = mix(s, s_correct, magic_val)
    attest_oracle_stmts = []
    if getattr(options, "attest", False):
        attest_requests = getattr(tree, "_pyobf_attest", [])
        seed_base = options.seed or 0
        magic_val = _attest_MAGIC(seed_base)
        oracle_name_str = _attest_oracle_name(seed_base)
        # Fold the body guard's co_code hash into every correction (PYC-only). cff emits the
        # matching `^ H` runtime term iff body_cohash is on, so both sides are keyed on the same flag.
        h_build = 0
        if getattr(options, "body_cohash", False):
            from ..cff.attest import cohash_build_hash
            h_build = cohash_build_hash(options.seed)
        if attest_requests:
            _patch_attest_markers(tree, attest_requests, s_correct, magic_val,
                                  getattr(options, "state_delta", False), h_build)
        # Install the oracle into the launcher globals: globals()[oracle_name_str] = O
        # O is a closure: (lambda k, m: lambda s: mix(s, k, m))(s_correct, magic_val)
        # The mix computation is inlined to avoid importing cff.attest at launcher runtime.
        n_oracle_var = namer.fresh("ora")
        runtime_bind = bool(getattr(options, "attest_runtime_bind", False))
        cap_stmts, n_gt, n_gp, n_pw, n_bt = [], None, None, None, None
        if runtime_bind and n_audit_sys:
            n_gt, n_gp, n_pw, n_bt = (namer.fresh("gt"), namer.fresh("gp"),
                                      namer.fresh("pw"), namer.fresh("bt"))
            cap_stmts = emit_body("t_oracle_caps", SYS=n_audit_sys, GT=n_gt, GP=n_gp, PW=n_pw, BT=n_bt)
        attest_oracle_stmts = cap_stmts + _build_oracle_install_stmts(
            oracle_name_str, n_oracle_var, s_correct, magic_val,
            runtime_bind=runtime_bind, cell_name=n_cell,
            gt_name=n_gt, gp_name=n_gp, pw_name=n_pw, bt_name=n_bt)

    # Serialize body bytes AFTER patching attest markers
    body_bytes = _body_bytes(tree, fmt, fname)

    # Extensible selector: acc [^ (bi*_BI_MAGIC)] [^ (d*_D_MAGIC)] [^ (poison*_P_MAGIC)] [^ h].
    # Build assumes a clean env (D == 0, POISON == 0) but DOES include the (non-zero, known) cohash H.
    s_terms = [astutil.name(n_acc)]
    if fold_bi:
        s_terms.append(astutil.mul_const(n_bi, _BI_MAGIC))
    if n_dvar:
        s_terms.append(astutil.mul_const(n_dvar, _D_MAGIC))
    if n_poison:
        s_terms.append(astutil.mul_const(n_poison, _P_MAGIC))
    if n_h:
        s_terms.append(astutil.name(n_h))
    sexpr = astutil.xor_chain(s_terms)

    # Neuter the debug set-APIs just before the exec tail (after the audit hook + oracle are in
    # place). Shared across both payload paths. Requires the cell + sys alias from the audit tripwire.
    neuter_stmts = (_emit_neuter(options, fmt, namer, n_cell, n_audit_sys)
                    if getattr(options, "anti_trace_neuter", False) and n_cell and n_audit_sys else [])

    if options.pack_decoy:
        k_real = _kdf((s_correct ^ _SALT_KEY) & _MASK)
        e_real = _ks_xor(body_bytes, k_real)
        decoy_src = options.decoy_src if getattr(options, "decoy_src", None) else _DEFAULT_DECOY
        k_decoy = _kdf(_SALT_DECOY)
        # When obf_module pre-obfuscated the decoy (decoy_tree), serialize it like the real body so the
        # decrypted decoy is structurally indistinguishable from the real one. Else embed the raw source.
        decoy_payload = (_body_bytes(decoy_tree, fmt, fname) if decoy_tree is not None
                         else _decoy_bytes(decoy_src, fmt, fname))
        e_decoy = _ks_xor(decoy_payload, k_decoy)
        # Real + decoy share ONE ciphertext blob; the table gates (offset, length) per selector,
        # so statically there is a single opaque package — not two payloads where the larger,
        # un-triggered one would stand out. The real slice is gated behind K_real (correct path).
        bigblob = e_real + e_decoy
        sel_correct = _kdf((s_correct ^ _SALT_SEL) & _MASK)
        table = {sel_correct: (0, len(e_real), (k_real ^ s_correct) & _MASK, 1)}
        default = (len(e_real), len(e_decoy), k_decoy, 0)
        stmts += _emit_blob_assign(n_blob, bigblob, options, namer)
        stmts += emit_body("t_assign", NAME=n_table, VALUE=table)
        stmts += emit_body("t_decoy_set_s", S=n_S, SEXPR=sexpr, ENT=n_ent, TABLE=n_table,
                           KDF=n_kdf, SALT_SEL=_SALT_SEL, KEY=n_acc, DEFAULT=default)
        regions.append(("payload + selector (decoy)", _r0, len(stmts)))
        _r0 = len(stmts)
        # Install oracle BEFORE the exec tail (so the body's oracle binding finds it in globals)
        stmts += attest_oracle_stmts
        if attest_oracle_stmts:
            regions.append(("oracle install (attest)", _r0, len(stmts)))
        _r0 = len(stmts)
        stmts += neuter_stmts
        if neuter_stmts:
            regions.append(("anti-trace neuter", _r0, len(stmts)))
        _r0 = len(stmts)
        n_zlib = namer.fresh("zl")
        stmts.append(import_stmt(n_zlib, "zlib", options))
        _xf, _cf, _glb = _exec_compile_refs(n_g)
        if fmt == "source":
            stmts += emit_body("t_decoy_tail_src", KS=n_ks, BLOB=n_blob, ENT=n_ent, KEY=n_acc, ZLIB=n_zlib,
                               FNAME=ast.Constant(value=fname), XF=_xf, CF=_cf, GLB=_glb)
        else:
            n_mar2 = namer.fresh("mar")
            stmts.append(import_stmt(n_mar2, "marshal", options))
            stmts += emit_body("t_decoy_tail_bc", KS=n_ks, BLOB=n_blob, ENT=n_ent, KEY=n_acc, MAR=n_mar2,
                               ZLIB=n_zlib, XF=_xf, GLB=_glb)
        regions.append(("exec tail", _r0, len(stmts)))
    else:
        key = _kdf(s_correct)
        blob = _ks_xor(body_bytes, key)
        stmts += _emit_blob_assign(n_blob, blob, options, namer)
        stmts += emit_body("t_single_set_s", S=n_S, SEXPR=sexpr, ACC=n_acc, KDF=n_kdf)
        regions.append(("payload + selector", _r0, len(stmts)))
        _r0 = len(stmts)
        # Install oracle BEFORE the exec tail
        stmts += attest_oracle_stmts
        if attest_oracle_stmts:
            regions.append(("oracle install (attest)", _r0, len(stmts)))
        _r0 = len(stmts)
        stmts += neuter_stmts
        if neuter_stmts:
            regions.append(("anti-trace neuter", _r0, len(stmts)))
        _r0 = len(stmts)
        stmts += _single_tail(fmt, options, namer, n_ks, n_blob, n_acc, fname, n_g=n_g)
        regions.append(("exec tail", _r0, len(stmts)))

    return _as_module(stmts), guard_inject, regions, True


def _build_oracle_install_stmts(oracle_name_str: str, oracle_var: str,
                                 s_correct: int, magic_val: int,
                                 runtime_bind: bool = False,
                                 cell_name: str | None = None,
                                 gt_name: str | None = None, gp_name: str | None = None,
                                 pw_name: str | None = None, bt_name: str | None = None) -> list:
    """Build AST stmts that install the oracle into the launcher's globals dict.

    Emits (pure form):
        globals()['<oracle_name>'] = (lambda k, m: lambda s: <inlined_mix>(s, k, m))(s_correct, magic)

    The mix function is inlined to avoid any runtime import of cff.attest. The inlined form
    mirrors the mix() body from cff/attest.py exactly. The oracle is installed by setting
    globals()[key] so the body's `globals().setdefault(key, fallback)` finds it already present.

    When runtime_bind is on: the oracle key becomes ``k ^ SIGNAL`` where SIGNAL is a sum of runtime
    integrity terms that are 0 in a clean env — ``int(gettrace() is not None)`` /
    ``int(getprofile() is not None)`` (via captured ``sys.gettrace``/``getprofile``), the audit
    poison ``cell[0]``, and ``int(type(pow) is not type(''.join))`` (builtin pow swap). Captured by
    value at install time as extra lambda args. Because the body re-calls ``O(state)`` on EVERY
    gated goto, the signal is re-evaluated continuously: a tracer attached at ANY time (even mid-body
    via the audit TOCTOU) makes the next gated transition land on a wrong state ⇒ divergence. Clean
    env ⇒ SIGNAL == 0 ⇒ ``k ^ 0 == k`` ⇒ the CORRECTION constants (built with ``mix(s, s_correct,
    magic)``) cancel exactly ⇒ the genuine path is byte-identical to the non-bound oracle."""
    _MASK_VAL = (1 << 64) - 1

    # Build the inlined mix lambda body: splitmix64 of (s ^ k ^ m).
    # The inner lambda is: lambda s: _mix_expr where _mix_expr is the splitmix64 result.

    def _name(n):
        return ast.Name(id=n, ctx=ast.Load())

    def _const(v):
        return ast.Constant(value=v)

    def _binop(l, op, r):
        return ast.BinOp(left=l, op=op, right=r)

    def _mask(expr):
        return _binop(expr, ast.BitAnd(), _const(_MASK_VAL))

    def _is_not(left, right):
        return ast.Compare(left=left, ops=[ast.IsNot()], comparators=[right])

    def _int(expr):
        return ast.Call(func=_name("int"), args=[expr], keywords=[])

    def _call(fn, *a):
        return ast.Call(func=_name(fn), args=list(a), keywords=[])

    # Build the runtime SIGNAL (0 in a clean env) and the captured extra lambda params/args.
    # The capture VALUES are PLAIN names precomputed by t_oracle_caps (gt/gp/pw/bt) so the install
    # statement survives the launcher's stack_calls/hide_external_args flatten (nested attribute/`type()`
    # args inside the install call break it). The signal CALLS (gt(), type(pw)) live inside the oracle
    # lambda, which is never flattened. extra_params/extra_args stay index-aligned.
    extra_params, extra_args, sig_terms = [], [], []
    if runtime_bind:
        if gt_name and gp_name:
            extra_params += ["gt", "gp"]
            extra_args += [_name(gt_name), _name(gp_name)]
            sig_terms += [_int(_is_not(_call("gt"), _const(None))),
                          _int(_is_not(_call("gp"), _const(None)))]
        if cell_name:
            extra_params += ["cell"]
            extra_args += [_name(cell_name)]
            sig_terms += [ast.Subscript(value=_name("cell"), slice=_const(0), ctx=ast.Load())]
        if pw_name and bt_name:
            extra_params += ["pw", "bt"]
            extra_args += [_name(pw_name), _name(bt_name)]
            sig_terms += [_int(_is_not(_call("type", _name("pw")), _name("bt")))]
    # Effective key: k (pure) or k ^ (sum of signal terms) (runtime-bound).
    k_expr = _binop(_name("k"), ast.BitXor(), astutil.add_chain(sig_terms)) if sig_terms else _name("k")

    # v = (s ^ k ^ m) & MASK
    v_expr = _mask(_binop(_binop(_name("s"), ast.BitXor(), _name("k")), ast.BitXor(), _name("m")))
    # Chain as nested lambdas: each step takes a named param, so intermediate values are named
    # without assignment inside the lambda body.
    C1 = 0x9E3779B97F4A7C15
    C2 = 0xBF58476D1CE4E5B9
    C3 = 0x94D049BB133111EB

    # Step: v2 = (v + C1) & MASK
    def _step1(v_name):
        return _mask(_binop(_name(v_name), ast.Add(), _const(C1)))

    # Step: z3 = ((z ^ (z >> 30)) * C2) & MASK
    def _step2(z_name):
        xor_part = _binop(_name(z_name), ast.BitXor(),
                          _binop(_name(z_name), ast.RShift(), _const(30)))
        return _mask(_binop(xor_part, ast.Mult(), _const(C2)))

    # Step: z4 = ((z ^ (z >> 27)) * C3) & MASK
    def _step3(z_name):
        xor_part = _binop(_name(z_name), ast.BitXor(),
                          _binop(_name(z_name), ast.RShift(), _const(27)))
        return _mask(_binop(xor_part, ast.Mult(), _const(C3)))

    # Final: (z ^ (z >> 31)) & MASK
    def _final(z_name):
        return _mask(_binop(_name(z_name), ast.BitXor(),
                            _binop(_name(z_name), ast.RShift(), _const(31))))

    # Build the nested lambda chain from inside out:
    inner = _final("z4")
    lam_z4 = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="z4")], vararg=None,
                           kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=inner)
    call_z4 = ast.Call(func=lam_z4, args=[_step3("z3")], keywords=[])

    lam_z3 = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="z3")], vararg=None,
                           kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=call_z4)
    call_z3 = ast.Call(func=lam_z3, args=[_step2("z2")], keywords=[])

    lam_z2 = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="z2")], vararg=None,
                           kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=call_z3)
    # z2 = (v + C1) & MASK where v = (s ^ k_eff ^ m) & MASK
    call_v_inner = ast.Call(func=lam_z2, args=[_step1("v1")], keywords=[])

    lam_v1 = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="v1")], vararg=None,
                           kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=call_v_inner)
    # Arg to lam_v1 is (s ^ k_eff ^ m) & MASK where k_eff = k (pure) or k ^ SIGNAL (runtime-bound).
    xor_skm = _mask(_binop(_binop(_name("s"), ast.BitXor(), k_expr), ast.BitXor(), _name("m")))
    call_outer = ast.Call(func=lam_v1, args=[xor_skm], keywords=[])

    # Inner lambda: lambda s: <mix>
    inner_s_lam = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="s")], vararg=None,
                           kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=call_outer)

    # Outer lambda: lambda k, m [, gt, gp, cell, pw, bt]: lambda s: <mix>
    outer_lam = ast.Lambda(
        args=ast.arguments(posonlyargs=[],
                           args=[ast.arg(arg="k"), ast.arg(arg="m")] + [ast.arg(arg=p) for p in extra_params],
                           vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=inner_s_lam)

    # Call with build-time s_correct, magic_val and any captured runtime-signal sources.
    oracle_fn_call = ast.Call(func=outer_lam,
                              args=[_const(s_correct), _const(magic_val)] + extra_args,
                              keywords=[])

    # globals()[<charcode oracle name>] = oracle_fn_call
    # The name is emitted as a charcode expression (not a greppable literal); the body's
    # setdefault key uses the same _attest_name_expr, so both sides agree on the globals key.
    subscript_set = ast.Assign(
        targets=[ast.Subscript(
            value=ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]),
            slice=_attest_name_expr(oracle_name_str),
            ctx=ast.Store())],
        value=oracle_fn_call)

    ast.fix_missing_locations(subscript_set)
    return [subscript_set]
