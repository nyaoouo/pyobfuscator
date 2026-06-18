"""Detection-aggregate plugin framework.

Each detector's ``term(ctx)`` returns an AST **expression** that evaluates to **0 in a clean
environment** and **> 0** when its condition triggers (from a real-code template in
``_templates.py``, instantiated via ``astutil``). ``build_detection`` computes each enabled
detector's signal into its own launcher variable, exposes them to the user handler as
``M.<magic_name>``, and sums the ``key_safe`` ones into the aggregate ``D`` that folds into the key
selector under ``key_binds_env`` — any trigger ⇒ wrong key ⇒ branchless decoy. The build assumes a
clean env (``D == 0``).

Add a detector by subclassing :class:`Detector`, decorating with :func:`register`, and returning
an expression from a ``t_detect_*`` template. Set ``key_safe = False`` for FP-prone signals
(timing, etc.) that should reach only the user handler, never the key fold.
"""
from __future__ import annotations

import ast

from .astutil import emit_expr, emit_body, import_stmt, add_chain, name


class _Ctx:
    """Shared emission context handed to each detector's ``term``."""
    def __init__(self, namer):
        self.namer = namer
        self.sys = None   # launcher's `sys` alias, allocated once if any detector needs it
        self.poison_cell = None  # audit-tripwire cell name (allocated by core.py), for AuditDetector
        self.compress_output = False  # outer compress_output wrap is on -> detect_stack walks extra frames
        self.compress_rounds = 1      # number of outer wrap layers (each adds one exec frame)


class Detector:
    flag = None          # ObfOptions attribute name that enables this detector
    needs_sys = False    # True if `term` references ctx.sys
    entry_only = False   # True if only sound for a run-as-__main__ entry (FP otherwise)
    magic_name = None    # exposed to the user handler as M.<magic_name>
    key_safe = True      # fold into the key aggregate D (False = expose to handler only)

    def term(self, ctx) -> ast.expr:
        """An AST expression: 0 in a clean env, > 0 when triggered."""
        raise NotImplementedError


# Ordered registry of detector instances.
DETECTORS = []


def register(cls):
    DETECTORS.append(cls())
    return cls


@register
class TraceDetector(Detector):
    flag = "detect_trace"
    needs_sys = True
    magic_name = "TRACE"

    def term(self, ctx):
        return emit_expr("t_detect_trace", SYS=ctx.sys)


@register
class AuditDetector(Detector):
    """Reads the audit-tripwire poison cell — set by our own ``sys.addaudithook`` when anyone
    calls ``sys.settrace``/``sys.setprofile`` (the event fires on the real C call, so it catches a
    late tracer attached during the inner ``exec`` — the launcher->body TOCTOU). 0 in a clean env.
    The cell + hook are shared infra emitted by ``protect/core.py`` (also read by the attest oracle
    and the set-API neuter); core passes the cell name via ``ctx.poison_cell``."""
    flag = "detect_audit"
    magic_name = "AUDIT"

    def term(self, ctx):
        return emit_expr("t_detect_audit", CELL=ctx.poison_cell)


@register
class ToolsDetector(Detector):
    """Debugger / coverage fingerprint via sys.modules. 0 in a clean process."""
    flag = "detect_tools"
    needs_sys = True
    magic_name = "TOOLS"
    _MODS = ("pydevd", "debugpy", "_pydevd_bundle", "coverage")

    def term(self, ctx):
        return emit_expr("t_detect_tools", SYS=ctx.sys, MVAR=ctx.namer.fresh("m"), TOOLS=self._MODS)


@register
class EnvDetector(Detector):
    """Interpreter-tamper fingerprint: breakpointhook replaced (debuggers do this) or the
    interpreter started in inspect mode (PYTHONINSPECT / -i). 0 in a clean process."""
    flag = "detect_env"
    needs_sys = True
    magic_name = "ENV"

    def term(self, ctx):
        return emit_expr("t_detect_env", SYS=ctx.sys)


@register
class StackDetector(Detector):
    """ENTRY-ONLY. A genuine ``python file.py`` run places the launcher at a KNOWN stack depth: the
    entry module has no Python caller (``f_back is None``), and the ``compress_output`` bootstrap execs
    the launcher exactly ``compress_rounds`` nested-exec frames below it. So a clean run has its chain
    EXACTLY ``rounds`` deep. A foreign ``exec`` / ``import`` / ``runpy`` / ``-m`` either sits DEEPER
    (a harness caller below the chain) or SHALLOWER (the launcher peeled out of its compress wrappers
    and exec'd directly by a static layer-peeler). We assert the chain is exactly ``rounds`` deep and
    trip on either deviation. Catches harnesses that exec the script to rip it even when they fake
    ``__name__ == '__main__'``. FP-prone -> opt-in, not in any preset, subprocess-tested.
    """
    flag = "detect_stack"
    needs_sys = True
    entry_only = True
    magic_name = "STACK"

    def term(self, ctx):
        # Genuine `python file.py`: the launcher sits EXACTLY `rounds` exec-frames below the entry
        # module (rounds = 0 when not outer-compressed; each compress round adds one nested-exec frame,
        # see outerpack._layer_src). So in a clean run, walking `rounds+1` f_back links from the launcher
        # lands on None (nothing above the entry) AND walking `rounds` links lands on the entry module
        # (NOT None). We assert BOTH and trip (>0) if EITHER fails:
        #   * frame[rounds+1] is not None  -> a caller sits BELOW the expected chain: exec'd / imported /
        #                                     runpy'd from a harness DEEPER than genuine.
        #   * frame[rounds]   is None      -> the chain is SHALLOWER than genuine: the launcher was peeled
        #                                     out of its compress wrappers and exec'd directly, so the
        #                                     none-safe walk floors to None before reaching `rounds`.
        # The second probe closes the bypass where a single fixed-depth point-probe let a SHALLOW foreign
        # exec read as clean — a deep walk on a short stack floors to None, identical to the genuine
        # "None above the entry" verdict. (depth==1 / uncompressed: the launcher IS the entry module and
        # has no genuine ancestor, so only the first probe applies; byte-identical to the original.)
        depth = (ctx.compress_rounds + 1) if ctx.compress_output else 1

        def _getframe():
            return ast.Call(func=ast.Attribute(value=name(ctx.sys), attr="_getframe", ctx=ast.Load()),
                            args=[], keywords=[])

        if depth == 1:
            # f_back is always valid (None or a frame); byte-identical to the original single probe.
            cmp = ast.Compare(left=ast.Attribute(value=_getframe(), attr="f_back", ctx=ast.Load()),
                              ops=[ast.IsNot()], comparators=[ast.Constant(value=None)])
            return ast.Call(func=ast.Name(id="int", ctx=ast.Load()), args=[cmp], keywords=[])

        def _walk(n):
            # NONE-SAFE walk: `getattr(x, 'f_back', None)` nested n times. A stack shorter than n floors
            # to None (no None.f_back AttributeError / f_back-chain traceback leak), which is exactly the
            # signal the SHALLOW probe below reads.
            e = _getframe()
            for _ in range(n):
                e = ast.Call(func=ast.Name(id="getattr", ctx=ast.Load()),
                             args=[e, ast.Constant(value="f_back"), ast.Constant(value=None)],
                             keywords=[])
            return e

        # frame[depth] is not None  -> deeper than genuine (a foreign caller below the chain)
        too_deep = ast.Call(
            func=ast.Name(id="int", ctx=ast.Load()),
            args=[ast.Compare(left=_walk(depth), ops=[ast.IsNot()],
                              comparators=[ast.Constant(value=None)])], keywords=[])
        # frame[depth-1] is None    -> shallower than genuine (launcher peeled out + exec'd directly)
        too_shallow = ast.Call(
            func=ast.Name(id="int", ctx=ast.Load()),
            args=[ast.Compare(left=_walk(depth - 1), ops=[ast.Is()],
                              comparators=[ast.Constant(value=None)])], keywords=[])
        return ast.BinOp(left=too_deep, op=ast.Add(), right=too_shallow)


def build_detection(options, namer, poison_cell=None):
    """Emit the detection prologue as AST statements.

    Returns ``(stmts, dvar_name_or_None, magic)`` where ``magic`` maps each active detector's
    ``magic_name`` to its launcher signal variable (for the user handler). ``D`` (``dvar``) sums
    only the ``key_safe`` signals. Active only when ``key_binds_env``.

    ``poison_cell`` is the name of the audit-tripwire cell (allocated by ``core.py`` when
    ``detect_audit`` is active); the :class:`AuditDetector` term reads it.
    """
    if not getattr(options, "key_binds_env", False):
        return [], None, {}
    active = [d for d in DETECTORS if getattr(options, d.flag, False)]
    ctx = _Ctx(namer)
    ctx.poison_cell = poison_cell
    ctx.compress_output = getattr(options, "compress_output", False)
    ctx.compress_rounds = getattr(options, "compress_rounds", 1)
    stmts = []
    if any(d.needs_sys for d in active):
        ctx.sys = namer.fresh("sys")
        stmts.append(import_stmt(ctx.sys, "sys", options))
    magic = {}
    key_vars = []
    for d in active:
        sig = namer.fresh("sig")
        stmts += emit_body("t_assign", NAME=sig, VALUE=d.term(ctx))
        if d.magic_name:
            magic[d.magic_name] = sig
        if d.key_safe:
            key_vars.append(sig)
    n_d = namer.fresh("d")
    dexpr = add_chain([name(v) for v in key_vars]) if key_vars else ast.Constant(0)
    stmts += emit_body("t_detect_assign", DVAR=n_d, DEXPR=dexpr)
    return stmts, n_d, magic
