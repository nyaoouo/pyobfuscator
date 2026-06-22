"""pyobfuscator — source-level Python obfuscator."""
from __future__ import annotations

import ast
import sys
import warnings

from .options import ObfOptions, ModuleObfOptions, OutputFormat, UnsupportedPolicy
from .cff.passes.base import Pipeline
from .cff.passes.flatten import FlattenPass
from .cff.passes.dataobf import DataObfPass
from .cff.passes.archive import ArchivePass
from .cff.passes.namevault import NameVaultPass
from .cff.passes.slotvar import SlotVarPass
from .cff.passes.normalize import NormalizePass
from .cff.passes.cmphide import CmpHidePass
from .cff.passes.localrename import LocalRenamePass
from .cff.passes.stackcall import StackCallPass
from .cff.passes.localcall import LocalCallPass
from .cff.passes.dictindirect import DictIndirectPass
from .cff.marker import local_call
from .cff.emit import emit
from .cff.analyze import build_model, analyze_html, build_protect_model, protect_html
from .cff.module_wrap import wrap_module
from .packer import pack_module
from .protect.project import obf_project

__version__ = "0.0.0"

__all__ = [
    "obf_func", "obf_module", "obf_project",
    "ObfOptions", "ModuleObfOptions", "OutputFormat", "UnsupportedPolicy",
    "build_model", "analyze_html", "build_protect_model", "protect_html",
    "local_call", "cache_tag", "sourceless_pyc_name", "MIN_SUPPORTED_PYTHON",
]

# Lowest Python (major, minor) the obfuscator's OUTPUT targets — the single source of truth for the
# `require_min_python` runtime guard. KEEP IN SYNC with pyproject `requires-python` (currently >=3.11).
# (Empirically the full TEXT stack is CI-verified on 3.12 + 3.14; 3.11 is the declared floor.)
MIN_SUPPORTED_PYTHON = (3, 11)


def _version_guard_src() -> str:
    """Plaintext min-version guard prepended to the outermost TEXT layer (require_min_python). Reads
    MIN_SUPPORTED_PYTHON at call time so it tracks the constant. Uses a `_pyx_`-prefixed alias so it
    never collides with the bootstrap (`_pyx_k/_c/_b`) or the `_pyobf_<hex>` finalized names."""
    mj, mn = MIN_SUPPORTED_PYTHON
    # Message deliberately does NOT name the obfuscator: the shipped artifact should not advertise the
    # tool, and some build pipelines assert the artifact carries no "pyobfuscator" reference.
    return ("import sys as _pyx_sys\n"
            "if _pyx_sys.version_info[:2] < (%d, %d):\n"
            "    raise SystemExit('This program requires Python %d.%d or newer "
            "(running %%d.%%d)' %% _pyx_sys.version_info[:2])\n" % (mj, mn, mj, mn))


def _insert_version_guard(tree: ast.AST) -> None:
    """Insert the min-version guard into a Module tree AFTER any leading docstring + `from __future__`
    imports (which MUST stay first) — for the non-compressed TEXT path, where there is no outer
    bootstrap to prepend to. The guard then runs before any obfuscated logic."""
    body = getattr(tree, "body", None)
    if body is None:
        return
    i = 0
    if (i < len(body) and isinstance(body[i], ast.Expr)
            and isinstance(body[i].value, ast.Constant) and isinstance(body[i].value.value, str)):
        i += 1                                           # module docstring
    while i < len(body) and isinstance(body[i], ast.ImportFrom) and body[i].module == "__future__":
        i += 1                                           # __future__ imports
    body[i:i] = ast.parse(_version_guard_src()).body
    ast.fix_missing_locations(tree)


def cache_tag() -> str:
    """The build interpreter's bytecode cache tag, e.g. ``"cpython-314"``
    (``sys.implementation.cache_tag``). An ``output="pyc"`` artifact is LOCKED to this interpreter
    version by its magic number; use the tag to label a version-specific distribution (dir/filename)."""
    return sys.implementation.cache_tag


def sourceless_pyc_name(module: str, *, tagged: bool = False) -> str:
    """Conventional filename for a sourceless ``output="pyc"`` artifact of `module`.

    ``output="pyc"`` returns a PEP-552 hash-based, UNCHECKED, **sourceless** ``.pyc`` (no source file is
    needed at run time). Written under ``sourceless_pyc_name(m)`` → ``"<m>.pyc"`` it is BOTH directly
    runnable (``python <m>.pyc``) AND importable as ``import <m>`` (the import system's
    SourcelessFileLoader recognises a bare ``<module>.pyc`` on ``sys.path``). The bare name carries no
    version tag on purpose: a sourceless ``.pyc`` MUST be named exactly ``<module>.pyc`` to be
    import-recognised — the target version is locked internally by the magic number, so a redundant tag
    would only BREAK bare import. Pass ``tagged=True`` for the cache-style ``"<m>.<cache_tag>.pyc"`` name,
    which is appropriate ONLY when placing the file under ``__pycache__/`` next to a ``<m>.py`` (where the
    import system loads it as that module's cache); a tagged name is not importable as a top-level module."""
    return f"{module}.{cache_tag()}.pyc" if tagged else f"{module}.pyc"

# StackCallPass(phase="post_vault") is the SECOND, targeted arg-hiding pass: it runs AFTER
# NameVault/Archive/DataObf so it can see the const-archive `_get(...)` accessor CALL SITES those
# passes create, and routes ONLY those marked accessors (and ONLY at statement-level value positions)
# through a fresh push/invoke stack — never the helper internals. Gated on the same
# `hide_external_args` flag as the first pass. (Vault `_D[k](...)` calls are intentionally NOT
# routed; see _is_routable_marked_call for why doing so would corrupt the first pass's push helper.)
_FUNC_PIPELINE = Pipeline([LocalCallPass(), DictIndirectPass(), NormalizePass(), CmpHidePass(), LocalRenamePass(), StackCallPass(), SlotVarPass(), NameVaultPass(), ArchivePass(), DataObfPass(), StackCallPass(phase="post_vault"), FlattenPass()])
_MODULE_PIPELINE = Pipeline([LocalCallPass(), DictIndirectPass(), NormalizePass(), CmpHidePass(), LocalRenamePass(), StackCallPass(), SlotVarPass(), NameVaultPass(), ArchivePass(), DataObfPass(), StackCallPass(phase="post_vault"), FlattenPass()])


def _to_tree(src) -> ast.AST:
    return ast.parse(src) if isinstance(src, str) else src


def _warn_docstrings(tree: ast.AST, options) -> None:
    """Docstrings are NOT stripped (that would change `__doc__` and break equivalence). But a MODULE
    docstring is kept PLAINTEXT by wrap_module, and function/class docstrings stay plaintext when
    string obfuscation is off — both LEAK information. Warn explicitly so sensitive docstrings can be
    removed from the source before obfuscation (the obfuscator does not strip them automatically)."""
    str_obf = bool(options.obf_strings or getattr(options, "const_archive", False))
    leaks = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if ast.get_docstring(node, clean=False) is None:
            continue
        is_module = isinstance(node, ast.Module)
        if is_module or not str_obf:   # module docstring always plaintext; others only without str-obf
            leaks.append("<module>" if is_module else getattr(node, "name", "?"))
    if leaks:
        shown = ", ".join(leaks[:8]) + (" …" if len(leaks) > 8 else "")
        warnings.warn(
            "pyobfuscator: docstrings are PRESERVED (not stripped, to keep __doc__ equivalence) and "
            "will leak as plaintext in the output: %s. Remove sensitive docstrings from the source if "
            "needed." % shown, UserWarning, stacklevel=3)


def _warn_version_lock(options) -> None:
    """`cohash_integrity` hashes co_code (Python-version-specific bytecode) at BUILD and RUNTIME and
    folds it into the key. For PYC this is moot (a .pyc is already version-locked by its magic). For
    TEXT — whose purpose is cross-version PORTABILITY — it LOCKS the launcher to the build Python
    version: a genuine run under a different version produces different co_code -> hash mismatch ->
    wrong key -> DECOY. Warn so the caller can pick portability (drop cohash) vs version-locked strength.
    (body_cohash adds the same lock.)"""
    if options.output is OutputFormat.TEXT and getattr(options, "cohash_integrity", False):
        warnings.warn(
            "pyobfuscator: cohash_integrity hashes co_code (version-specific bytecode), so a TEXT "
            "launcher is LOCKED to the build Python %d.%d — a genuine run on a DIFFERENT version will "
            "decode the DECOY, defeating TEXT's cross-version portability. Use PYC (already version-"
            "locked), or disable cohash_integrity for portable TEXT." % sys.version_info[:2],
            UserWarning, stacklevel=3)


def _obfuscate_decoy(options):
    """Obfuscate the decoy through the SAME pipeline as the real body, then finalize with a DISJOINT
    namespace salt so a decrypted decoy is structurally indistinguishable from the real body (no
    plaintext source). Two layers of control:
      * `decoy_obf_overrides` (optional dict): per-flag CFF overrides applied on top of the body's flags
        BEFORE finalizing — lets a build dial the decoy's strength down (e.g. drop opaque predicates /
        bogus blocks / string obfuscation so a triggered decoy is legible and the trap is obvious) while
        keeping the rest. None -> the decoy inherits the body's flags unchanged.
      * structural flags are then FORCED off regardless of overrides: attest / attest_runtime_bind /
        body_cohash / cohash_integrity (the decoy is reached BECAUSE anti-debug fired, so it must run
        under the debugger that selected it — attestation would make IT diverge too), and pack/decoy/
        compress (it is embedded, not re-wrapped).
    Returns the finalized obfuscated decoy tree, or None if there is no decoy."""
    decoy_src = getattr(options, "decoy_src", None)
    if not decoy_src:
        return None
    from dataclasses import replace
    from .cff.lambdalift import lift_lambdas
    from .cff.passes.localrename import rename_simple_helper_locals
    from .cff.rename import finalize_names
    from .protect.core import _DECOY_NS_SALT
    overrides = getattr(options, "decoy_obf_overrides", None) or {}
    dopts = replace(options, **overrides) if overrides else options   # build-side fine-tuning first
    dopts = replace(dopts, protect_level="off", attest=False, attest_runtime_bind=False,
                    body_cohash=False, cohash_integrity=False, pack_body=False, pack_decoy=False,
                    compress_output=False)                            # forced: the decoy must run under debug
    dtree = ast.parse(decoy_src)
    _warn_docstrings(dtree, dopts)            # the decoy's own module docstring would also leak plaintext
    dtree = wrap_module(_MODULE_PIPELINE.run(dtree, dopts), dopts)
    lift_lambdas(dtree)
    rename_simple_helper_locals(dtree)
    finalize_names(dtree, options.seed, ns_salt=_DECOY_NS_SALT)
    return dtree


def obf_func(src, options: ObfOptions | None = None, *, sourcemap_out: dict | None = None):
    options = options or ObfOptions()
    tree = _to_tree(src)
    _warn_docstrings(tree, options)
    tree = _FUNC_PIPELINE.run(tree, options)
    return emit(tree, options, sourcemap_out=sourcemap_out, layer="function")


def obf_module(src, options: ModuleObfOptions | None = None, *, sourcemap_out: dict | None = None,
               publish_runtime: bool = False, shared_oracle_decouple: bool = False,
               runtime_registry: dict | None = None):
    options = options or ModuleObfOptions()
    if publish_runtime and not getattr(options, "attest", False):
        # The shared multi-module runtime publishes the attestation oracle (and the decrypt fn keyed
        # on the same selector) into builtins; without attest there is no oracle/selector machinery
        # to publish. obf_project always sets attest for protected projects.
        raise ValueError(
            "publish_runtime=True requires attest=True (the entry publishes the attestation oracle "
            "+ shared decrypt function into builtins). It also inherits attest's requirement of "
            "pack_body=True, key_from_cff=True and output text/pyc.")
    # Fail-loud: attest needs the packer to (a) install the oracle into the body's globals and
    # (b) patch the CORRECTION markers in the body. Both happen in pack_module, which runs only
    # when pack_body+key_from_cff are set AND output is text/pyc. Emitting gated gotos without
    # that machinery leaves unpatched __pyobf_corr_* placeholders / a missing oracle -> the body
    # breaks even on the genuine path. Reject the broken combos up front rather than at runtime.
    if getattr(options, "attest", False):
        if not (options.pack_body and options.key_from_cff):
            raise ValueError(
                "attest=True requires pack_body=True and key_from_cff=True — "
                "the launcher installs the oracle into the body's globals before exec(). "
                "Without the packer there is no oracle provider and gated gotos would break "
                "even the genuine path.")
        if options.output not in (OutputFormat.TEXT, OutputFormat.PYC):
            raise ValueError(
                "attest=True requires output='text' or 'pyc' — the packer (pack_module), which "
                "patches the attestation CORRECTION markers and installs the oracle, runs only for "
                "those outputs. With output='ast' the body keeps unpatched __pyobf_corr_* "
                "placeholders and raises NameError at runtime.")
    if getattr(options, "body_cohash", False):
        # body_cohash rides the attest gates (it folds H into the oracle transition) and is PYC-only
        # (a TEXT body is recompiled by the end user's interpreter -> its co_code would not match the
        # baked H_build -> the genuine path would decode the decoy). Reject the broken combos up front
        # rather than shipping a launcher that fails even on the honest path.
        if not getattr(options, "attest", False):
            raise ValueError(
                "body_cohash=True requires attest=True — the body self-hash is folded into the "
                "oracle-gated state transitions, so without attestation there are no gates to carry it.")
        if options.output is not OutputFormat.PYC:
            raise ValueError(
                "body_cohash=True requires output='pyc' — it hashes the body's compiled co_code, which "
                "is version-locked. A TEXT body is recompiled by the end user's (possibly different) "
                "interpreter, so its co_code would not match the baked hash and the genuine path would "
                "decode the DECOY. Use PYC (already version-locked), or disable body_cohash for TEXT.")
    tree = _to_tree(src)
    _warn_docstrings(tree, options)
    _warn_version_lock(options)
    tree = _MODULE_PIPELINE.run(tree, options)
    tree = wrap_module(tree, options)
    packed = options.pack_body and options.output in (OutputFormat.TEXT, OutputFormat.PYC)
    if packed:
        # Obfuscate the decoy with the same pipeline so a decrypted decoy is indistinguishable.
        decoy_tree = _obfuscate_decoy(options) if getattr(options, "pack_decoy", False) else None
        tree = pack_module(tree, options, sourcemap_out=sourcemap_out, decoy_tree=decoy_tree,
                           publish_runtime=publish_runtime,
                           shared_oracle_decouple=shared_oracle_decouple,
                           runtime_registry=runtime_registry)
    # require_min_python: a PLAINTEXT min-version guard in the OUTERMOST layer (TEXT-only — a .pyc/ast
    # is already locked to its build version by its magic). Enforces MIN_SUPPORTED_PYTHON so a too-old
    # interpreter gets a clean "requires Python X.Y+" message instead of a cryptic failure.
    req_min = bool(getattr(options, "require_min_python", False))
    if req_min and options.output is not OutputFormat.TEXT:
        warnings.warn(
            "pyobfuscator: require_min_python is TEXT-only and is ignored for output=%r — a .pyc/ast "
            "is already locked to its build version by its magic number." % options.output.value,
            UserWarning, stacklevel=2)
        req_min = False
    compress = (getattr(options, "compress_output", False)
                and options.output in (OutputFormat.TEXT, OutputFormat.PYC))
    if req_min and not compress:
        # No outer bootstrap to prepend to -> emit the guard inside the (uncompressed) TEXT tree, after
        # any docstring/__future__, so it is the first thing that runs and stays __future__-safe.
        _insert_version_guard(tree)
    result = emit(tree, options, sourcemap_out=sourcemap_out,
                  layer="launcher" if packed else "module")
    # Final distribution wrap (zlib + rolling-XOR + b85, optionally recursive): shrink + speed-bump.
    if compress:
        import random
        from .protect.outerpack import outer_compress
        from .cff.emit import _to_pyc
        result = outer_compress(result, _to_pyc, rounds=getattr(options, "compress_rounds", 1),
                                decoy=True, rng=random.Random((options.seed or 0) ^ 0x0C0FFEE))
        if req_min:   # result is the outermost plaintext TEXT bootstrap (str) -> prepend the guard above it
            result = _version_guard_src() + result
    return result
