"""Project-level multi-module obfuscation orchestration (``obf_project``).

Drives the single-module packer across a source tree: one **entry** module publishes a shared
protection runtime (decrypt + oracle) into ``builtins``; **protected** modules ship as a small
stub + encrypted blob that decrypt through that runtime; all other modules are copied **plaintext**.
One ``seed`` makes the oracle, key (``s_correct = f(seed)``) and names agree across every file, so
files build independently in any order.
"""
from __future__ import annotations

import ast
import enum
import fnmatch
import os
import shutil


class Role(enum.Enum):
    ENTRY = "entry"
    PROTECT = "protect"
    PLAINTEXT = "plaintext"


def _walk_py(root: str):
    """Yield every ``.py`` file under ``root`` as a forward-slash relative path."""
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".py"):
                full = os.path.join(dirpath, f)
                yield os.path.relpath(full, root).replace(os.sep, "/")


def classify_files(root: str, *, entry: str, protect) -> dict:
    """Return ``{rel_path -> Role}`` for every ``.py`` under ``root``.

    ``entry`` is one relative path; ``protect`` is a list of relative paths / globs (``fnmatch``).
    The entry is never classified PROTECT even if a protect pattern also matches it. Fail-loud if the
    entry is missing or a protect pattern matches nothing (a silent no-op build is worse than an error).
    """
    entry = entry.replace(os.sep, "/")
    all_py = sorted(_walk_py(root))
    if entry not in all_py:
        raise ValueError(f"entry {entry!r} not found under {root!r}")
    protect_set = set()
    for pat in (protect or []):
        pat = pat.replace(os.sep, "/")
        matched = [p for p in all_py if p == pat or fnmatch.fnmatch(p, pat)]
        if not matched:
            raise ValueError(f"protect pattern {pat!r} matched no .py files under {root!r}")
        protect_set.update(matched)
    protect_set.discard(entry)
    out = {}
    for p in all_py:
        out[p] = (Role.ENTRY if p == entry else
                  Role.PROTECT if p in protect_set else Role.PLAINTEXT)
    return out


def _emit_to(out_path: str, payload) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if isinstance(payload, bytes):
        open(out_path, "wb").write(payload)
    else:
        open(out_path, "w", encoding="utf-8").write(payload)


def _module_id(rel: str) -> str:
    """Dotted module name for a relative path: ``app/secret.py`` -> ``app.secret``,
    ``app/__init__.py`` -> ``app``, ``main.py`` -> ``main``."""
    parts = rel[:-3].split("/") if rel.endswith(".py") else rel.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _out_rel(rel: str, options) -> str:
    """Output relative path for an OBFUSCATED file. For PYC output the artifact is a sourceless
    ``.pyc`` (``python main.pyc`` runs it; ``import app.secret`` loads ``app/secret.pyc`` when no
    ``app/secret.py`` shadows it). Plaintext files keep their ``.py`` name (copied verbatim)."""
    from ..options import OutputFormat
    if options.output is OutputFormat.PYC and rel.endswith(".py"):
        return rel[:-3] + ".pyc"
    return rel


def obf_project(*, root: str, out: str, entry: str, protect=None, options=None,
                import_hook: bool = False, shared_oracle_decouple: bool = False) -> dict:
    """Obfuscate a multi-module project rooted at ``root`` into ``out``; return a
    ``{rel_path -> Role.value}`` manifest.

    ``entry`` is the entry module (relative path); ``protect`` is a list of relative paths / globs to
    obfuscate; all other ``.py`` files are copied verbatim.

    **Shared-runtime mode** (when ``options`` enable the attestation stack — ``attest`` + ``pack_body``
    + ``key_from_cff`` + text/pyc output — and there are protected files): the ENTRY publishes a shared
    decrypt function + oracle into ``builtins``; each protected module ships as a small stub + encrypted
    blob that decrypts through it. ``shared_oracle_decouple=True`` selects the alpha binding (build-
    constant selector) over the default beta (runtime selector; tampering the entry diverts every
    satellite to its decoy).

    **Self-contained fallback** (attestation stack off): each protected/entry module is built as an
    independent single-module launcher (no shared runtime). A protected file imported without the
    entry then still self-decrypts; under shared-runtime mode it fails loud (entry-bound).
    """
    from .. import obf_module, _obfuscate_decoy, _MODULE_PIPELINE
    from ..options import ModuleObfOptions, OutputFormat
    from ..cff.module_wrap import wrap_module
    from ..cff.emit import emit
    from ..cff.attest import MAGIC as _attest_MAGIC, dec_name as _attest_dec_name
    from . import core
    options = options or ModuleObfOptions()
    roles = classify_files(root, entry=entry, protect=protect)
    has_protect = any(r is Role.PROTECT for r in roles.values())
    shared = bool(has_protect and getattr(options, "attest", False)
                  and options.pack_body and options.key_from_cff
                  and options.output in (OutputFormat.TEXT, OutputFormat.PYC))

    if import_hook and not shared:
        raise ValueError(
            "import_hook=True requires the shared-runtime stack (attest + pack_body + key_from_cff + "
            "text/pyc output) and at least one protected module — the entry-installed finder serves "
            "satellites through the published shared decrypt function.")

    s_correct = magic = dec_name_str = decoy_tree = None
    if shared:
        s_correct = core.project_s_correct(options)
        magic = _attest_MAGIC(options.seed or 0)
        dec_name_str = _attest_dec_name(options.seed or 0)
        decoy_tree = _obfuscate_decoy(options) if getattr(options, "pack_decoy", False) else None

    # Satellites + plaintext first (so the import-hook registry is complete before the entry); the
    # entry is emitted LAST. `s_correct = f(seed)` means satellites don't actually depend on the entry
    # build — the entry-last order is only needed to collect the import-hook registry.
    registry: dict = {}
    entry_rel = next(r for r, role in roles.items() if role is Role.ENTRY)
    for rel, role in roles.items():
        if role is Role.ENTRY:
            continue
        src_path = os.path.join(root, rel)
        out_path = os.path.join(out, *rel.split("/"))
        if role is Role.PLAINTEXT:
            os.makedirs(os.path.dirname(out_path) or out, exist_ok=True)
            shutil.copyfile(src_path, out_path)
            continue
        # PROTECT
        src = open(src_path, encoding="utf-8").read()
        if not shared:
            sc_out = os.path.join(out, *_out_rel(rel, options).split("/"))
            _emit_to(sc_out, obf_module(src, options))     # self-contained fallback
            continue
        mid = _module_id(rel)
        tree = ast.parse(src)
        tree = _MODULE_PIPELINE.run(tree, options)
        tree = wrap_module(tree, options)
        stub, blob, table, default = core.build_satellite(
            tree, options, module_id=mid, s_correct=s_correct, magic=magic,
            dec_name_str=dec_name_str, decoy_tree=decoy_tree)
        if import_hook:
            registry[mid] = (blob, table, default)         # centralized: served by the entry's finder
        else:
            sat_out = os.path.join(out, *_out_rel(rel, options).split("/"))
            _emit_to(sat_out, emit(stub, options, layer="module"))    # stub mode: ship per-file

    entry_src = open(os.path.join(root, entry_rel), encoding="utf-8").read()
    entry_out = os.path.join(out, *_out_rel(entry_rel, options).split("/"))
    if shared:
        _emit_to(entry_out, obf_module(entry_src, options, publish_runtime=True,
                                       shared_oracle_decouple=shared_oracle_decouple,
                                       runtime_registry=(registry if import_hook else None)))
    else:
        _emit_to(entry_out, obf_module(entry_src, options))
    return {rel: role.value for rel, role in roles.items()}
