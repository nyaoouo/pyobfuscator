"""PrecompilePass — build-time partial evaluation of the `precompile` / `precompile_arg` markers.

Runs FIRST in the pipeline. It computes constants at build time and folds them in:

  * ``precompile(expr)``            -> evaluate ``expr`` at build (running the module's own code) and
                                       replace the OUTERMOST marker call with the resulting constant.
  * ``precompile_arg(key[, dflt])`` -> the value the build script injected in ``options.precompile_args``
                                       for ``key`` (or ``dflt``; required if no default is given).
  * ``@precompile`` on a module-level zero-argument function -> run the function at build and replace the
                                       whole ``def`` with ``NAME = <const>`` (a thunk: loops/locals can
                                       compute a build constant, not just one expression).

Build-time evaluation runs the user's module in an ISOLATED SUBPROCESS (side effects and crashes are
contained); standalone ``precompile_arg`` with a literal key/default is resolved in-process (no module
exec needed). Nested markers (e.g. ``precompile(f(precompile_arg("K")))``) resolve during the subprocess
eval — only the outermost call is replaced. For a thunk, the ``@precompile`` decorator is stripped in the
build source so the subprocess defines a plain function and evaluates ``NAME()`` with build-aware markers
(so ``precompile_arg`` injection works inside the thunk). The markers are no-ops at runtime — the
expression forms return their value and the decorator CALLS the thunk — so un-obfuscated source still
runs and yields the same constant.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import subprocess
import sys

from ..gate import SupportSet
from ...options import ObfOptions
from .flatten import FLATTEN_ALLOWED
from .normalize import _MATCH_NODES as _NM_NODES

_MARKERS = ("precompile", "precompile_arg")
_DEFAULT_TIMEOUT = 30.0  # seconds; overridable via options.precompile_timeout

# Process-level cache of batched build-eval results, keyed by (module source, injected args, exprs).
# Build-eval is deterministic for pure exprs (the documented contract), so identical re-builds in one
# process — determinism checks, partial-update rebuilds, obf_project re-runs — reuse the result instead
# of re-spawning the subprocess. Module-level so it resets per process (no cross-run staleness).
_CACHE: dict[str, list[str]] = {}
_subprocess_spawns = 0  # instrumentation for tests (count of actual subprocess launches)


def _cache_key(module_src: str, build_args: dict, exprs: list[str]) -> str:
    h = hashlib.sha256()
    h.update(module_src.encode("utf-8"))
    h.update(repr(sorted((k, repr(v)) for k, v in build_args.items())).encode("utf-8"))
    h.update(repr(exprs).encode("utf-8"))
    return h.hexdigest()

# Subprocess driver: exec the module (so its functions/imports are available), then eval each marker
# expression with build-aware `precompile`/`precompile_arg` bound in the namespace. JSON in/out.
_DRIVER = (
    "import sys, json, ast\n"
    "data = json.load(sys.stdin)\n"
    "ns = {'__name__': '<precompile>'}\n"
    "try:\n"
    "    exec(compile(data['module_src'], '<precompile-module>', 'exec'), ns)\n"
    "except BaseException as e:\n"
    "    print(json.dumps({'fatal': '%s: %s' % (type(e).__name__, e)})); sys.exit(0)\n"
    "_args = {}\n"
    "for _k, _vr in data['build_args'].items():\n"
    "    try: _args[_k] = ast.literal_eval(_vr)\n"
    "    except Exception: pass\n"
    "ns['precompile'] = lambda x: x\n"
    "ns['precompile_arg'] = lambda key, default=None: _args[key] if key in _args else default\n"
    "out = []\n"
    "for _ex in data['exprs']:\n"
    "    try:\n"
    "        _v = eval(compile(_ex, '<precompile-expr>', 'eval'), ns)\n"
    "        out.append({'ok': True, 'repr': repr(_v)})\n"
    "    except BaseException as e:\n"
    "        out.append({'ok': False, 'err': '%s: %s' % (type(e).__name__, e)})\n"
    "print(json.dumps({'results': out}))\n"
)


def _build_marker_resolver(tree: ast.AST):
    """Return ``resolve(call) -> 'precompile'|'precompile_arg'|None``, alias-aware.
    Tracks ``from pyobfuscator import precompile [as x]`` and ``import pyobfuscator [as p]``."""
    from_aliases: dict[str, str] = {}   # local name -> marker name
    pkg_aliases: set[str] = set()       # local names bound to the pyobfuscator package
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "pyobfuscator":
            for a in node.names:
                if a.name in _MARKERS:
                    from_aliases[a.asname or a.name] = a.name
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == "pyobfuscator":
                    pkg_aliases.add(a.asname or a.name.split(".")[0])

    def resolve_ref(f):
        """Resolve a bare reference (a decorator node: ``Name`` or ``Attribute``) to a marker name."""
        if isinstance(f, ast.Name) and f.id in from_aliases:
            return from_aliases[f.id]
        if (isinstance(f, ast.Attribute) and f.attr in _MARKERS
                and isinstance(f.value, ast.Name) and f.value.id in pkg_aliases):
            return f.attr
        return None

    def resolve(call: ast.Call):
        return resolve_ref(call.func)

    resolve.ref = resolve_ref   # decorator-ref resolution shares the same alias tables
    return resolve


def _string_literal(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_literal(node) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except Exception:
        return False


def _literal_node(repr_str: str, desc: str) -> ast.expr:
    """Validate that `repr_str` is a literal-representable constant and return its AST node."""
    try:
        ast.literal_eval(repr_str)
    except Exception:
        raise ValueError(
            "precompile: result of %s is not a literal-representable constant: %s" % (desc, repr_str))
    return ast.parse(repr_str, mode="eval").body


class _Collect(ast.NodeVisitor):
    """Collect OUTERMOST marker calls (do not descend into a marker call's args — nested markers
    are resolved during the eval and subsumed by replacing the outer call). Skip the bodies of
    ``@precompile`` thunks (``skip_ids``): the whole thunk is build-eval'd and replaced wholesale, so
    its inner marker calls must not be collected/folded separately."""

    def __init__(self, resolve, skip_ids=frozenset()):
        self.resolve = resolve
        self.skip = skip_ids
        self.found: list[tuple[ast.Call, str]] = []

    def visit_FunctionDef(self, node):
        if id(node) in self.skip:
            return  # thunk body handled wholesale
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        m = self.resolve(node)
        if m is not None:
            self.found.append((node, m))
            return  # outermost only
        self.generic_visit(node)


class _Replace(ast.NodeTransformer):
    """Replace folded marker calls with their constant, and ``@precompile`` thunk ``def``s with the
    ``NAME = <const>`` assignment computed for them."""

    def __init__(self, call_nodes: dict[int, ast.expr], func_nodes: dict[int, ast.stmt] | None = None):
        self.call_nodes = call_nodes
        self.func_nodes = func_nodes or {}

    def visit_Call(self, node):
        rep = self.call_nodes.get(id(node))
        if rep is not None:
            return ast.copy_location(rep, node)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        rep = self.func_nodes.get(id(node))
        if rep is not None:
            return ast.copy_location(rep, node)
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


def _strip_marker_imports(tree: ast.AST):
    """Drop precompile/precompile_arg from `from pyobfuscator import ...`, and a now-unused
    `import pyobfuscator [as p]` (the attr-form `pyobfuscator.precompile(...)` has been folded away).
    Run AFTER folding so references are already gone; an `import pyobfuscator` alias that is still
    referenced (a genuine non-marker use) is kept, so this never breaks a real dependency."""
    # Names still loaded somewhere -> decides whether an `import pyobfuscator` alias is now dead.
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    for node in ast.walk(tree):
        for _field, value in ast.iter_fields(node):
            if not (isinstance(value, list) and value):
                continue
            remove = []
            for i, stmt in enumerate(value):
                if isinstance(stmt, ast.ImportFrom) and stmt.module == "pyobfuscator":
                    stmt.names = [a for a in stmt.names if a.name not in _MARKERS]
                    if not stmt.names:
                        remove.append(i)
                elif isinstance(stmt, ast.Import):
                    stmt.names = [a for a in stmt.names
                                  if not (a.name.split(".")[0] == "pyobfuscator"
                                          and (a.asname or a.name.split(".")[0]) not in used)]
                    if not stmt.names:
                        remove.append(i)
            for i in reversed(remove):
                value.pop(i)


def _decorated_thunks(tree: ast.AST, resolve) -> list:
    """Return the module-level functions decorated with a bare ``@precompile`` (validated, fail-loud).
    Each is build-eval'd as ``NAME()`` and its ``def`` is replaced with ``NAME = <const>``."""
    toplevel = {id(n) for n in getattr(tree, "body", [])}
    thunks = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(resolve.ref(d) == "precompile" for d in node.decorator_list):
            continue
        if id(node) not in toplevel:
            raise ValueError("precompile: @precompile is only supported on module-level functions "
                             "(found on nested function %r)" % node.name)
        if isinstance(node, ast.AsyncFunctionDef):
            raise ValueError("precompile: @precompile cannot decorate the async function %r "
                             "(its result is a coroutine, not a constant)" % node.name)
        if len(node.decorator_list) != 1:
            raise ValueError("precompile: @precompile must be the only decorator on %r" % node.name)
        a = node.args
        if a.args or a.posonlyargs or a.kwonlyargs or a.vararg or a.kwarg:
            raise ValueError("precompile: the @precompile function %r must take no arguments "
                             "(it is a build-time thunk)" % node.name)
        thunks.append(node)
    return thunks


def _assign_node(name: str, value: ast.expr) -> ast.Assign:
    return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value)


def _build_eval_src(tree: ast.AST) -> str:
    """Unparse the module for build-eval with bare ``@precompile`` decorators removed from every
    function, so the subprocess defines plain functions and ``NAME()`` is evaluated with the driver's
    build-aware ``precompile``/``precompile_arg`` (so ``precompile_arg`` injection works inside a thunk,
    independent of the decorator's runtime semantics)."""
    copy_tree = copy.deepcopy(tree)
    r = _build_marker_resolver(copy_tree)
    for node in ast.walk(copy_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
            node.decorator_list = [d for d in node.decorator_list if r.ref(d) != "precompile"]
    return ast.unparse(copy_tree)


class PrecompilePass:
    name = "precompile"

    def supports(self) -> SupportSet:
        # Runs before NormalizePass, so accept the pre-normalization node set (incl. Match).
        return SupportSet(allowed=FLATTEN_ALLOWED | _NM_NODES)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        resolve = _build_marker_resolver(tree)
        build_args = dict(getattr(options, "precompile_args", None) or {})

        thunks = _decorated_thunks(tree, resolve)   # validates @precompile decorator usage (fail-loud)
        has_calls = any(resolve(n) for n in ast.walk(tree) if isinstance(n, ast.Call))
        # Fast no-op: no markers at all (no calls and no decorated thunks).
        if not thunks and not has_calls:
            return tree

        # Every injected value must be a literal-representable constant.
        for k, v in build_args.items():
            try:
                ast.literal_eval(repr(v))
            except Exception:
                raise ValueError("precompile: precompile_args[%r] is not a literal-representable "
                                 "constant: %r" % (k, v))

        # Validate every marker call (incl. nested, incl. inside thunk bodies) before folding any.
        self._validate(tree, resolve, build_args)

        thunk_ids = {id(f) for f in thunks}
        collector = _Collect(resolve, skip_ids=thunk_ids)
        collector.visit(tree)

        reprs: dict[int, str] = {}        # id(call) -> repr string
        batch: list[ast.Call] = []        # calls needing the subprocess
        for call, marker in collector.found:
            if marker == "precompile_arg":
                got = self._inproc_arg(call, build_args)
                if got is not None:
                    reprs[id(call)] = got
                    continue
            batch.append(call)            # precompile, or precompile_arg w/ non-literal default

        thunk_reprs: dict[int, str] = {}  # id(funcdef) -> repr string
        if batch or thunks:
            module_src = _build_eval_src(tree)     # thunk decorators stripped -> plain functions
            call_exprs = [ast.unparse(c) for c in batch]
            thunk_exprs = [f.name + "()" for f in thunks]
            timeout = float(getattr(options, "precompile_timeout", _DEFAULT_TIMEOUT))
            results = self._run_subprocess(module_src, call_exprs + thunk_exprs, build_args, timeout)
            for call, r in zip(batch, results[:len(call_exprs)]):
                reprs[id(call)] = r
            for f, r in zip(thunks, results[len(call_exprs):]):
                thunk_reprs[id(f)] = r

        call_nodes = {cid: _literal_node(r, "a precompile expression") for cid, r in reprs.items()}
        name_by_id = {id(f): f.name for f in thunks}
        func_nodes = {fid: _assign_node(name_by_id[fid],
                                        _literal_node(r, "@precompile function %r" % name_by_id[fid]))
                      for fid, r in thunk_reprs.items()}
        new_tree = _Replace(call_nodes, func_nodes).visit(tree)
        _strip_marker_imports(new_tree)
        ast.fix_missing_locations(new_tree)
        return new_tree

    def _validate(self, tree, resolve, build_args):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            marker = resolve(node)
            if marker is None:
                continue
            if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
                raise ValueError("precompile: %s(...) must use only positional, non-* arguments" % marker)
            if marker == "precompile":
                if len(node.args) != 1:
                    raise ValueError("precompile(expr) takes exactly one argument")
            else:  # precompile_arg
                if len(node.args) not in (1, 2):
                    raise ValueError("precompile_arg(key[, default]) takes one or two arguments")
                key = _string_literal(node.args[0])
                if key is None:
                    raise ValueError("precompile_arg: the key must be a string literal")
                if len(node.args) == 1 and key not in build_args:
                    raise ValueError(
                        "precompile_arg(%r): required build value not provided in precompile_args "
                        "(pass a default to make it optional)" % key)

    def _inproc_arg(self, call, build_args) -> str | None:
        """Resolve a standalone precompile_arg in-process; return its repr, or None to defer to the
        subprocess (a missing key whose default is a non-literal expression)."""
        key = _string_literal(call.args[0])
        if key in build_args:
            return repr(build_args[key])
        # key missing -> use the default (validation guarantees a default exists here)
        default = call.args[1]
        if _is_literal(default):
            return repr(ast.literal_eval(default))
        return None  # non-literal default -> subprocess

    def _run_subprocess(self, module_src, exprs, build_args, timeout) -> list[str]:
        key = _cache_key(module_src, build_args, exprs)
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
        payload = {"module_src": module_src, "exprs": exprs,
                   "build_args": {k: repr(v) for k, v in build_args.items()}}
        global _subprocess_spawns
        _subprocess_spawns += 1
        try:
            proc = subprocess.run([sys.executable, "-c", _DRIVER], input=json.dumps(payload),
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ValueError("precompile: build-time evaluation timed out after %ss "
                             "(raise options.precompile_timeout)" % timeout)
        if proc.returncode != 0:
            raise ValueError("precompile: build-eval subprocess failed:\n%s" % proc.stderr.strip()[-1000:])
        try:
            data = json.loads(proc.stdout)
        except Exception:
            raise ValueError("precompile: could not parse build-eval output:\n%s" % proc.stdout.strip()[-1000:])
        if "fatal" in data:
            raise ValueError("precompile: the module failed to execute at build time: %s" % data["fatal"])
        out = []
        for ex, res in zip(exprs, data["results"]):
            if not res.get("ok"):
                raise ValueError("precompile: failed to evaluate `%s` at build time: %s"
                                 % (ex, res.get("err")))
            out.append(res["repr"])
        _CACHE[key] = out
        return out
