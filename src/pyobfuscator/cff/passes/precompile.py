"""PrecompilePass — build-time partial evaluation of the `precompile` / `precompile_arg` markers.

Runs FIRST in the pipeline. For each OUTERMOST marker call it computes a constant at build time and
replaces the call with that constant (which the downstream literal passes then encrypt):

  * ``precompile(expr)``            -> evaluate ``expr`` at build (running the module's own code).
  * ``precompile_arg(key[, dflt])`` -> the value the build script injected in ``options.precompile_args``
                                       for ``key`` (or ``dflt``; required if no default is given).

Build-time evaluation of ``precompile`` runs the user's module in an ISOLATED SUBPROCESS (side effects
and crashes are contained); standalone ``precompile_arg`` with a literal key/default is resolved
in-process (no module exec needed). Nested markers (e.g. ``precompile(f(precompile_arg("K")))``) resolve
during the subprocess eval — only the outermost call is replaced. Both markers are identity/default at
runtime, so un-obfuscated source still runs.
"""
from __future__ import annotations

import ast
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

    def resolve(call: ast.Call):
        f = call.func
        if isinstance(f, ast.Name) and f.id in from_aliases:
            return from_aliases[f.id]
        if (isinstance(f, ast.Attribute) and f.attr in _MARKERS
                and isinstance(f.value, ast.Name) and f.value.id in pkg_aliases):
            return f.attr
        return None

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
    are resolved during the eval and subsumed by replacing the outer call)."""

    def __init__(self, resolve):
        self.resolve = resolve
        self.found: list[tuple[ast.Call, str]] = []

    def visit_Call(self, node):
        m = self.resolve(node)
        if m is not None:
            self.found.append((node, m))
            return  # outermost only
        self.generic_visit(node)


class _Replace(ast.NodeTransformer):
    def __init__(self, nodes: dict[int, ast.expr]):
        self.nodes = nodes

    def visit_Call(self, node):
        rep = self.nodes.get(id(node))
        if rep is not None:
            return ast.copy_location(rep, node)
        return self.generic_visit(node)


def _strip_marker_imports(tree: ast.AST):
    """Drop precompile/precompile_arg from `from pyobfuscator import ...`; remove an emptied import."""
    for node in ast.walk(tree):
        for _field, value in ast.iter_fields(node):
            if not (isinstance(value, list) and value):
                continue
            remove = []
            for i, stmt in enumerate(value):
                if not (isinstance(stmt, ast.ImportFrom) and stmt.module == "pyobfuscator"):
                    continue
                stmt.names = [a for a in stmt.names if a.name not in _MARKERS]
                if not stmt.names:
                    remove.append(i)
            for i in reversed(remove):
                value.pop(i)


class PrecompilePass:
    name = "precompile"

    def supports(self) -> SupportSet:
        # Runs before NormalizePass, so accept the pre-normalization node set (incl. Match).
        return SupportSet(allowed=FLATTEN_ALLOWED | _NM_NODES)

    def transform(self, tree: ast.AST, options: ObfOptions) -> ast.AST:
        resolve = _build_marker_resolver(tree)
        build_args = dict(getattr(options, "precompile_args", None) or {})

        # Fast no-op: any marker calls at all?
        if not any(resolve(n) for n in ast.walk(tree) if isinstance(n, ast.Call)):
            return tree

        # Every injected value must be a literal-representable constant.
        for k, v in build_args.items():
            try:
                ast.literal_eval(repr(v))
            except Exception:
                raise ValueError("precompile: precompile_args[%r] is not a literal-representable "
                                 "constant: %r" % (k, v))

        # Validate every marker call (incl. nested) before folding any.
        self._validate(tree, resolve, build_args)

        collector = _Collect(resolve)
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

        if batch:
            module_src = ast.unparse(tree)
            exprs = [ast.unparse(c) for c in batch]
            timeout = float(getattr(options, "precompile_timeout", _DEFAULT_TIMEOUT))
            for call, r in zip(batch, self._run_subprocess(module_src, exprs, build_args, timeout)):
                reprs[id(call)] = r

        nodes = {cid: _literal_node(r, "a precompile expression") for cid, r in reprs.items()}
        new_tree = _Replace(nodes).visit(tree)
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
