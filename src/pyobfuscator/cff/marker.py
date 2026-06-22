"""Marker decorators recognized by pyobfuscator. At runtime they are identity (no-ops), so
annotated source runs normally; the obfuscator strips them and acts on the annotation."""
from __future__ import annotations


def local_call(fn):
    """Mark a function so the obfuscator renames it to an opaque name (and inlines it at a single
    safe call site). Identity at runtime."""
    return fn


def precompile(x):
    """Mark a value for BUILD-TIME evaluation. Two forms, both folded by `PrecompilePass`:

    * **Expression** — `precompile(expr)`: the obfuscator evaluates `expr` at build time and replaces
      the call with the resulting constant (which then flows through the literal-obfuscation passes and
      gets encrypted). At runtime it returns `expr` unchanged, so un-obfuscated source still runs.
    * **Decorator** — `@precompile` on a module-level zero-argument function: the obfuscator runs the
      function at build time and binds its name to the returned constant (`NAME = <const>`), replacing
      the `def`. A thunk (loops, locals) can compute a build constant, not just a single expression.

    At runtime, the decorator form CALLS the thunk and binds the result, so the un-obfuscated name holds
    the SAME value the obfuscator folds in (consistency, not just no-op identity). Detection: a plain
    zero-argument function argument is called; any other value is returned unchanged — so the
    `precompile(expr)` form is unaffected (its argument is an already-evaluated value, not a thunk).

    The build value must be evaluable at build (module-level functions/imports/literals; not a function
    parameter) and be a literal-representable constant."""
    import types
    if isinstance(x, types.FunctionType):
        co = x.__code__
        required_pos = co.co_argcount - len(x.__defaults__ or ())
        required_kw = co.co_kwonlyargcount - len(x.__kwdefaults__ or {})
        if required_pos <= 0 and required_kw <= 0:   # callable with no arguments -> a build-time thunk
            return x()
    return x


def precompile_arg(key, default=None):
    """Mark a build-script-injected value: the obfuscator replaces `precompile_arg(key, default)` with
    the value supplied for `key` in `options.precompile_args` (folded as a constant), or `default`.
    Lets a build/CI inject secrets (license keys, endpoints, build IDs) that never appear in the source.
    Returns `default` at runtime, so un-obfuscated source runs with a dev placeholder. With only the
    `key` argument (no default), the value is REQUIRED at build (fail-loud if not provided)."""
    return default
