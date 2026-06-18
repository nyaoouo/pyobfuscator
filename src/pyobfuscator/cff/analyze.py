"""Debug visualizer: turn the obfuscation of some source into a self-contained
HTML page — one SVG control-flow "mind map" per scope, mapped to original source.

`build_model(src)` produces the structured data (JSON-serializable). `analyze_html(src)`
inlines the pre-written renderer (`viz/analyze.js` + `viz/analyze.css`) plus a data
`<script>` block. The schema is versioned and grows as later stages add term kinds.
"""
from __future__ import annotations

import ast
import copy
import difflib
import json
import re
from dataclasses import replace
from pathlib import Path

from .cfg import build_blocks, _render, alloc_names, Goto, CondGoto, Ret, RaiseTerm, HandlerDispatch, SubExit
from .names import Namer, collect_names
from ..options import ObfOptions

SCHEMA = 1
_VIZ = Path(__file__).parent / "viz"


# ---- model building ------------------------------------------------------
def _up(node) -> str:
    """ast.unparse, robust to synthetic nodes lacking source locations.
    Operates on a copy so original line numbers stay intact for _stmt_lines."""
    return ast.unparse(ast.fix_missing_locations(copy.deepcopy(node)))


def _block_lines(block):
    """Min/max original source line over a block's real statements AND its
    terminator's expressions (cond test / return value). None if synthetic-only."""
    nodes = list(block.stmts)
    t = block.term
    if isinstance(t, CondGoto):
        nodes.append(t.test)
    elif isinstance(t, Ret) and t.value is not None:
        nodes.append(t.value)
    elif isinstance(t, RaiseTerm) and t.exc is not None:
        nodes.append(t.exc)
    nums = []
    for s in nodes:
        for n in ast.walk(s):
            for attr in ("lineno", "end_lineno"):
                v = getattr(n, attr, None)
                if v:
                    nums.append(v)
    return [min(nums), max(nums)] if nums else None


def _block_models(blocks) -> list:
    """Per-block JSON model. Called AFTER the scope's single finalize rename, so the block stmt /
    terminator nodes (shared with the rendered tree) already carry their final _pyobf_<hex> names."""
    return [
        {
            "id": b.id,
            "lines": _block_lines(b),
            "stmts": [_up(s) for s in b.stmts],
            "term": _term_model(b.term),
        }
        for b in blocks
    ]


def _term_exprs(term) -> list:
    """The expr nodes a terminator carries (so the shared rename can reach names inside them).
    Mirrors the cases _term_model stringifies."""
    out = []
    if isinstance(term, CondGoto) and term.test is not None:
        out.append(term.test)
    elif isinstance(term, Ret) and term.value is not None:
        out.append(term.value)
    elif isinstance(term, RaiseTerm):
        if term.exc is not None:
            out.append(term.exc)
        if term.cause is not None:
            out.append(term.cause)
    elif isinstance(term, HandlerDispatch):
        out.extend(t for t, _ in term.handlers if t is not None)
    return out


def _term_model(term) -> dict:
    if isinstance(term, Goto):
        return {"kind": "goto", "target": term.target}
    if isinstance(term, CondGoto):
        return {"kind": "cond", "test": _up(term.test),
                "then": term.then, "orelse": term.orelse}
    if isinstance(term, Ret):
        return {"kind": "ret",
                "value": _up(term.value) if term.value is not None else None}
    if isinstance(term, RaiseTerm):
        return {"kind": "raise", "exc": _up(term.exc) if term.exc is not None else None,
                "cause": _up(term.cause) if term.cause is not None else None}
    if isinstance(term, HandlerDispatch):
        return {"kind": "handler_dispatch",
                "handlers": [[(_up(t) if t is not None else None), hid] for t, hid in term.handlers]}
    if isinstance(term, SubExit):
        return {"kind": "sub_exit"}
    return {"kind": "unknown", "repr": type(term).__name__}


def _flat_block_lines(flattened: str, state_name: str) -> dict:
    """Map block id -> [start,end] line range in the flattened output.

    Each block renders as a guard `if <state> == <id>:` at the dispatcher indent;
    the region runs from that line to just before the next guard. The state var is a
    unique fresh name, so `if <state> == N:` matches only dispatcher guards (not user
    code, not a nested function's own dispatcher which uses a different state name)."""
    lines = flattened.split("\n")
    pat = re.compile(r"^\s*if " + re.escape(state_name) + r" == (\d+):")
    guards = [(i, int(m.group(1)))
              for i, line in enumerate(lines, 1) for m in [pat.match(line)] if m]
    ranges = {}
    for idx, (ln, bid) in enumerate(guards):
        end = guards[idx + 1][0] - 1 if idx + 1 < len(guards) else len(lines)
        ranges[bid] = [ln, end]
    return ranges


def _all_funcs(tree):
    """Top-level functions plus every nested function — each is its own scope,
    matching how FlattenPass produces one dispatcher per scope."""
    out = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append(child)
            visit(child)

    visit(tree)
    return out


def _qualname(tree, fn):
    """Dotted path of `fn` within `tree` (e.g. outer.inner)."""
    path = []

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                if child is fn:
                    path.append(name)
                visit(child, name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return path[0] if path else fn.name


# ---- pass timeline (per-plugin snapshots) --------------------------------
# The analyzer reads the framework's canonical pipeline object at runtime and observes a copy.
# Reorder/add/remove a pass elsewhere and the timeline follows automatically; if the object
# can't be found the timeline degrades to empty.
_PASS_LABEL = {
    "original": "Original", "localcall": "LocalCall", "dictindirect": "DictIndirect",
    "normalize": "Normalize", "stackcall": "StackCall", "slotvar": "SlotVar",
    "dataobf": "DataObf", "flatten": "Flatten", "wrap_module": "WrapModule",
}


def _label(name: str) -> str:
    return _PASS_LABEL.get(name, name)


def _numbered(text: str) -> list:
    return [{"n": i, "text": t} for i, t in enumerate(text.splitlines(), 1)]


def _changed(prev: str, cur: str) -> list:
    """1-based new-side line numbers in `cur` that differ from `prev` (replace/insert opcodes)."""
    out = []
    sm = difflib.SequenceMatcher(None, prev.splitlines(), cur.splitlines())
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "insert"):
            out.extend(range(j1 + 1, j2 + 1))
    return out


def _unparse_fixed(tree, seed=0) -> str:
    """Unparse a location-fixed deepcopy so synthetic nodes don't break and the input stays pristine.
    Applies the final seeded rename (finalize_names) to the copy so the visualizer shows the same
    uniform `_pyobf_<hex>` names the real emitter produces — and stays deterministic across calls:
    Namer.fresh() hands out a process-global monotonic counter (`_pyobf_g<n>`) that advances between
    builds, so two snapshots of the same seed only match AFTER the rename collapses those counter
    values to seed-derived hex (determinism is in the rename, not the counter)."""
    from .rename import finalize_names
    return ast.unparse(finalize_names(ast.fix_missing_locations(copy.deepcopy(tree)), seed))


def _live_pipeline():
    """The framework's canonical pipeline object (lazy import → no cycle). None on failure."""
    try:
        from .. import _MODULE_PIPELINE
        return _MODULE_PIPELINE
    except Exception:  # noqa: BLE001
        try:
            from .. import _FUNC_PIPELINE
            return _FUNC_PIPELINE
        except Exception:  # noqa: BLE001
            return None


def build_pass_timeline(tree, pipeline, options, post_steps=()) -> list:
    """Snapshot the whole-module source after each pass that changes it. `tree` is consumed
    (mutated in place by the passes) — pass a deepcopy. Mirrors the framework's trivial run loop
    (`enforce` then `transform`); `post_steps` are named `(label, fn)` applied after the pipeline.
    Returns step dicts; a failing pass yields a terminal `{error}` step."""
    from .gate import enforce
    seed = getattr(options, "seed", 0)
    steps = []
    cur = _unparse_fixed(tree, seed)
    steps.append({"name": "original", "label": "Original", "lines": _numbered(cur), "changed": []})

    def record(name, t):
        nonlocal cur
        try:
            txt = _unparse_fixed(t, seed)
        except Exception as exc:  # noqa: BLE001
            steps.append({"name": name, "label": _label(name), "error": f"{type(exc).__name__}: {exc}"})
            return "STOP"
        if txt != cur:
            steps.append({"name": name, "label": _label(name),
                          "lines": _numbered(txt), "changed": _changed(cur, txt)})
            cur = txt
        return None

    for p in pipeline.passes:
        try:
            enforce(tree, p.supports(), options.on_unsupported)
            tree = p.transform(tree, options)
        except Exception as exc:  # noqa: BLE001
            steps.append({"name": p.name, "label": _label(p.name), "error": f"{type(exc).__name__}: {exc}"})
            return steps
        if record(p.name, tree) == "STOP":
            return steps
    for label, fn in post_steps:
        tree = fn(tree)
        if record(label, tree) == "STOP":
            return steps
    return steps


def build_model(src: str, options: ObfOptions | None = None) -> dict:
    options = options or ObfOptions()
    tree = ast.parse(src)
    src_lines = src.splitlines()
    scopes = []
    for fn in _all_funcs(tree):
        scope = {
            "name": fn.name,
            "qualname": _qualname(tree, fn),
            "source_lines": [
                {"n": i, "text": src_lines[i - 1]}
                for i in range(fn.lineno, (fn.end_lineno or fn.lineno) + 1)
                if 1 <= i <= len(src_lines)
            ],
        }
        try:
            from .rename import finalize_names
            fcopy = copy.deepcopy(fn)
            namer = Namer(options.seed, collect_names(fcopy))
            names = alloc_names(namer)
            blocks, entry_id, low = build_blocks(fcopy, namer, names)
            scope["entry"] = entry_id
            scope["supported"] = True
            # Namer.fresh() hands out a process-global monotonic counter (_pyobf_g<n>) that
            # advances between builds. The final seeded rename (finalize_names) collapses those to
            # deterministic _pyobf_<hex>; running it ONCE per scope over the tree the views unparse
            # (and reading its out_map) keeps every view consistent and byte-identical across two
            # same-seed builds. Block stmt/term nodes are the SAME objects inside `fcopy`, so they
            # are renamed in place by the single finalize — block_models are built AFTER it.
            rmap: dict = {}
            if len(blocks) < options.min_blocks:
                # matches FlattenPass: too few logical blocks -> emitted unchanged
                scope["flattened"] = False
                scope["skip_reason"] = (
                    f"{len(blocks)} block(s) < min_blocks {options.min_blocks}"
                    " — left unobfuscated"
                )
                # Wrap fcopy + the (detached) block nodes so the single finalize reaches both.
                _bag = ast.Module(
                    body=[fcopy] + [s for b in blocks for s in b.stmts]
                         + [n for b in blocks for n in _term_exprs(b.term)],
                    type_ignores=[])
                finalize_names(ast.fix_missing_locations(_bag), options.seed, out_map=rmap)
                block_models = _block_models(blocks)
                for bm in block_models:
                    bm["flat_lines"] = None
                unchanged = ast.unparse(fcopy)  # body untouched by build_blocks (now renamed)
                scope["blocks"] = block_models
                scope["flattened_source"] = unchanged
                scope["flattened_lines"] = [
                    {"n": i, "text": t} for i, t in enumerate(unchanged.splitlines(), 1)
                ]
            else:
                scope["flattened"] = True
                fcopy.body = _render(blocks, entry_id, names, low.needs_sentinel, low.needs_exc)
                ast.fix_missing_locations(fcopy)
                # Single finalize over the rendered tree: renames block stmts/terms (shared nodes),
                # the dispatcher scaffolding, AND the state var — all consistently.
                finalize_names(fcopy, options.seed, out_map=rmap)
                state_name = rmap.get(names.state, names.state)
                block_models = _block_models(blocks)
                flattened = ast.unparse(fcopy)
                flat_ranges = _flat_block_lines(flattened, state_name)
                for bm in block_models:
                    bm["flat_lines"] = flat_ranges.get(bm["id"])
                scope["blocks"] = block_models
                scope["flattened_source"] = flattened
                scope["flattened_lines"] = [
                    {"n": i, "text": t} for i, t in enumerate(flattened.splitlines(), 1)
                ]
        except Exception as exc:  # noqa: BLE001 - report, don't crash the whole page
            scope["supported"] = False
            scope["reason"] = f"{type(exc).__name__}: {exc}"
        scopes.append(scope)

    # Per-plugin timeline (whole-module, only-changed). Never crashes the page.
    passes = []
    pipe = _live_pipeline()
    if pipe is not None:
        try:
            passes = build_pass_timeline(copy.deepcopy(tree), pipe, options)
            for s in reversed(passes):
                if s.get("name") == "flatten":
                    s["has_cfg"] = True
                    break
        except Exception:  # noqa: BLE001 - the scopes view is independent and still renders
            passes = []
    return {"schema": SCHEMA, "scopes": scopes, "passes": passes}


# ---- HTML assembly -------------------------------------------------------
_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
<h1>{title}</h1>
<div id="pyobf-root"></div>
<script>
{js}
</script>
<script>
window.__PYOBF__ = {data};
PYOBF.render(document.getElementById("pyobf-root"), window.__PYOBF__);
</script>
</body>
</html>
"""


def _read(name: str) -> str:
    return (_VIZ / name).read_text(encoding="utf-8")


def analyze_html(src: str, options: ObfOptions | None = None,
                 title: str = "pyobfuscator analyze") -> str:
    """Return a self-contained HTML page visualizing the obfuscation of `src`."""
    model = build_model(src, options)
    data = json.dumps(model, ensure_ascii=False).replace("</", "<\\/")  # safe inside <script>
    return _HTML.format(title=title, css=_read("analyze.css"), js=_read("analyze.js"), data=data)


# ---- protect (shell) visualizer ------------------------------------------
# The launcher carries the already-obfuscated module as a compressed+encrypted blob and
# decrypts+execs it at runtime. This is a SEPARATE page from the CFF analyze view. Everything
# here uses read-only imports from `protect` (no modification). The layer/size breakdown and
# final launcher are computed now; the per-plugin launcher timeline and region annotation are
# attached automatically once `protect.core._assemble_launcher` exists.

def _serialize_for_size(tree, fmt: str) -> bytes:
    """Mirror the packer's pre-compression serialization, for the size breakdown only (read-only)."""
    import marshal
    if fmt == "source":
        return ast.unparse(tree).encode("utf-8")
    return marshal.dumps(compile(ast.fix_missing_locations(tree), "<pyobf>", "exec"))


def _regions_to_lines(module, regions, seed=0) -> list:
    """Map (label, stmt_start, stmt_end) statement-index ranges to 1-based line ranges over the
    full-module unparse (cumulative unparse → robust boundaries; module body is tiny)."""
    body = list(module.body)
    bounds = [0]
    for k in range(1, len(body) + 1):
        sub = ast.Module(body=body[:k], type_ignores=[])
        bounds.append(len(_unparse_fixed(sub, seed).splitlines()))
    out = []
    for item in regions:
        label, i0, i1 = item[0], item[1], item[2]
        i0 = max(0, min(i0, len(body)))
        i1 = max(i0, min(i1, len(body)))
        start, end = bounds[i0] + 1, bounds[i1]
        if end >= start:
            out.append({"label": label, "lines": [start, end]})
    return out


def _launcher_detail(base_tree, vopts, assemble) -> dict:
    """Return the pre-flatten launcher, its region map, and a per-plugin timeline of how the
    launcher itself gets flattened. Only called when `protect.core._assemble_launcher` exists."""
    from .module_wrap import wrap_module
    res = assemble(copy.deepcopy(base_tree), vopts)
    module = res[0]
    regions = res[2] if len(res) > 2 else []
    lopts = replace(vopts, obf_strings=False, pack_body=False, attest=False)
    pipe = _live_pipeline()
    post = [("wrap_module", lambda t: wrap_module(t, lopts))]
    lp = build_pass_timeline(copy.deepcopy(module), pipe, lopts, post_steps=post) if pipe is not None else []
    _lseed = getattr(vopts, "seed", 0)
    return {
        "assembled_lines": _numbered(_unparse_fixed(module, _lseed)),
        "regions": _regions_to_lines(module, regions, _lseed),
        "launcher_passes": lp,
    }


def build_protect_model(src: str, options=None) -> dict:
    """Structured data for the shell visualizer: byte-size layers (serialize→zlib→encrypt→encode→
    launcher) plus the final launcher source. Forces the packer path on for visualization; attest
    is disabled (it doesn't change the packaging layers shown here). JSON-serializable."""
    import base64
    from ..options import ModuleObfOptions, OutputFormat
    from ..protect.core import pack_module
    from ..protect.templates import _body_bytes, _resolve_format
    from .module_wrap import wrap_module

    options = options or ModuleObfOptions()
    vopts = replace(options, pack_body=True, key_from_cff=True, attest=False)
    fmt = _resolve_format(vopts)

    pipe = _live_pipeline()
    base_tree = pipe.run(ast.parse(src), vopts) if pipe is not None else ast.parse(src)
    base_tree = wrap_module(base_tree, vopts)
    # Finalize the body's monotonic temp names (_pyobf_g<n>) to seed-stable hex BEFORE measuring
    # sizes / packing, mirroring the real emit path (pack_module finalizes the body before
    # serialization). Without this the size layers + launcher source would drift run-to-run as the
    # global counter advances. base_tree is reused below (deepcopied), so one finalize suffices.
    from .rename import finalize_names
    finalize_names(base_tree, getattr(vopts, "seed", 0))

    raw = _serialize_for_size(copy.deepcopy(base_tree), fmt)
    comp = _body_bytes(copy.deepcopy(base_tree), fmt)
    enc_bytes = len(base64.b85encode(comp)) if vopts.output is OutputFormat.TEXT else len(comp)
    launcher_src = _unparse_fixed(pack_module(copy.deepcopy(base_tree), vopts), getattr(vopts, "seed", 0))

    layers = [
        {"name": "serialize", "bytes": len(raw),
         "note": "ast.unparse(body).encode()" if fmt == "source" else "marshal.dumps(code)"},
        {"name": "zlib", "bytes": len(comp), "ratio": round(len(comp) / max(1, len(raw)), 4),
         "note": "zlib.compress(.,9)"},
        {"name": "encrypt", "bytes": len(comp), "note": "keystream XOR (length-preserving)"},
        {"name": "encode", "bytes": enc_bytes,
         "note": "base64.b85" if vopts.output is OutputFormat.TEXT else "raw bytes literal"},
        {"name": "launcher", "bytes": len(launcher_src), "note": "final launcher source (chars)"},
    ]
    out = {"schema": SCHEMA, "format": fmt, "layers": layers, "launcher_source": launcher_src}

    # Auto-hook: once protect.core exposes _assemble_launcher, attach the launcher timeline + regions.
    try:
        from ..protect.core import _assemble_launcher
    except Exception:  # noqa: BLE001
        _assemble_launcher = None
    if _assemble_launcher is not None:
        try:
            out.update(_launcher_detail(base_tree, vopts, _assemble_launcher))
        except Exception:  # noqa: BLE001 - detail is best-effort; layers always render
            pass
    return out


_HTML_PROTECT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
<h1>{title}</h1>
<div id="pyobf-root"></div>
<script>
{js}
</script>
<script>
window.__PYOBF_PROTECT__ = {data};
PYOBF.renderProtect(document.getElementById("pyobf-root"), window.__PYOBF_PROTECT__);
</script>
</body>
</html>
"""


def protect_html(src: str, options=None, title: str = "pyobfuscator protect") -> str:
    """Return a self-contained HTML page visualizing the launcher/shell packaging of `src`."""
    model = build_protect_model(src, options)
    data = json.dumps(model, ensure_ascii=False).replace("</", "<\\/")  # safe inside <script>
    js = _read("analyze.js") + "\n" + _read("protect.js")    # analyze.js exports renderTimeline
    css = _read("analyze.css") + "\n" + _read("protect.css")
    return _HTML_PROTECT.format(title=title, css=css, js=js, data=data)
