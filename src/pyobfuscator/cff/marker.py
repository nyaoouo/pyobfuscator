"""Marker decorators recognized by pyobfuscator. At runtime they are identity (no-ops), so
annotated source runs normally; the obfuscator strips them and acts on the annotation."""
from __future__ import annotations


def local_call(fn):
    """Mark a function so the obfuscator renames it to an opaque name (and inlines it at a single
    safe call site). Identity at runtime."""
    return fn


def precompile(x):
    """Mark an expression for BUILD-TIME evaluation: the obfuscator evaluates the argument expression
    at build time and replaces the `precompile(...)` call with the resulting constant (which then flows
    through the literal-obfuscation passes and gets encrypted). Identity at runtime, so un-obfuscated
    source still runs. The expression must be evaluable at build (module-level functions/imports/
    literals; not function parameters) and yield a literal-representable value."""
    return x


def precompile_arg(key, default=None):
    """Mark a build-script-injected value: the obfuscator replaces `precompile_arg(key, default)` with
    the value supplied for `key` in `options.precompile_args` (folded as a constant), or `default`.
    Lets a build/CI inject secrets (license keys, endpoints, build IDs) that never appear in the source.
    Returns `default` at runtime, so un-obfuscated source runs with a dev placeholder. With only the
    `key` argument (no default), the value is REQUIRED at build (fail-loud if not provided)."""
    return default
