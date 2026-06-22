"""Launcher code templates, written as REAL Python so they are syntax-checked and lintable.

`astutil.py` parses this module ONCE, then for each template: renames placeholder identifiers,
substitutes placeholder *loads* with values / AST nodes, and splices the result into the launcher.
These functions are NEVER executed — the UPPERCASE placeholder names are intentionally undefined.

Conventions:
  * a function whose name is a placeholder (`t_ks`, `t_kdf`) is emitted as a renamed `def`;
  * `t_*` whose BODY is the payload is emitted as inline statements (the def is just a container);
  * `t_detect_*` return an expression — emitted as a bare expression node.
"""
# flake8: noqa  -- placeholders (UPPERCASE / undefined names) are intentional; never executed


# ---- functions emitted as (renamed) defs ----
def t_ks(data, key):
    out = bytearray(len(data))
    x = key & 0xFFFFFFFFFFFFFFFF
    if x == 0:
        x = 0x9E3779B97F4A7C15
    for i in range(len(data)):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        out[i] = data[i] ^ (x & 0xFF)
    return bytes(out)


def t_kdf(s):
    s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = s
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF


# ---- statement-block templates (emit body) ----
def t_seed():
    ACC = SEED0


def t_step():
    ACC = (ACC * M + C) & 0xFFFFFFFFFFFFFFFF


def t_bi_bt():
    BT = type(''.join)


def t_bi_rel():
    # relative integrity term: 1 in a clean env; 0 if X was replaced by a non-builtin-typed object
    return type(X) is BT


def t_bi_abs():
    # absolute "is X a Python-defined function?" term: 1 in a clean env (native builtin has no
    # __code__); 0 if X was replaced by a Python def/lambda (which always has __code__). Independent
    # of any reference builtin, so uniform replacement of EVERY builtin still trips each term.
    return int(not hasattr(X, '__code__'))


def t_assign():
    NAME = VALUE


def t_capture_globals():
    # Capture the launcher's globals dict ONCE (reusable). Used by the builtin-integrity terms and the
    # exec tail to read the EFFECTIVE compile/exec binding (G.get("exec", exec)): the genuine builtin
    # when un-shadowed, or a GLOBAL shadow (e.g. a compile/exec-hooking peeler) when present.
    G = globals()


def t_assign_b85():
    # TEXT output: embed the blob as a compact ASCII b85 literal (decoded at load) instead of a
    # b'\xNN' bytes literal (~2.87x larger in source). B64 = base64 module alias; ASCII = b85 bytes.
    NAME = B64.b85decode(ASCII)


def t_obf_import():
    ALIAS = __import__(''.join(map(chr, CODES)))


def t_oracle_caps():
    # Precompute the runtime-signal sources into plain locals so the oracle-install statement's
    # captured args stay simple names (not nested attribute/`type()` calls). The launcher flatten with
    # stack_calls/hide_external_args mishandles complex call-args inside the install call; statement-
    # level calls like `type(''.join)` survive (the builtin-integrity prologue uses the same form).
    GT = SYS.gettrace
    GP = SYS.getprofile
    PW = pow
    BT = type(''.join)


def t_single_set_s():
    S = SEXPR
    ACC = KDF(S)


def t_single_tail_src():
    # XF/CF/GLB are the exec/compile/globals refs: either bare builtins (plain) or the global-effective
    # form G.get("exec", exec) (so a compile/exec-hooking peeler's fake-compile captures the payload).
    XF(CF(ZLIB.decompress(KS(BLOB, KEY)).decode('utf-8'), FNAME, 'exec'), GLB)


def t_single_tail_bc():
    XF(MAR.loads(ZLIB.decompress(KS(BLOB, KEY))), GLB)


def t_decoy_set_s():
    # ENT = (offset, length, kmask, flag); real & decoy ciphertexts share one BIGBLOB.
    S = SEXPR
    ENT = TABLE.get(KDF(S ^ SALT_SEL), DEFAULT)
    KEY = (ENT[2] ^ (S * ENT[3])) & 0xFFFFFFFFFFFFFFFF


def t_decoy_tail_src():
    XF(CF(ZLIB.decompress(KS(BLOB[ENT[0]:ENT[0] + ENT[1]], KEY)).decode('utf-8'), FNAME, 'exec'), GLB)


def t_decoy_tail_bc():
    XF(MAR.loads(ZLIB.decompress(KS(BLOB[ENT[0]:ENT[0] + ENT[1]], KEY))), GLB)


# ---- shared multi-module runtime: the decrypt-and-exec factory published into builtins ----
# FACTORY FORM: emitted as a top-level def spliced in AFTER the launcher flatten (like the cohash
# guard), so its body is never run through the pipeline (no call-routing corruption). The CALL site
# `<builtins>.<dec> = t_mkdec(S, ks, kdf, oracle, oname, zlib, SALT_SEL, MASK, fname)` lives inside the
# flattened launcher, so it captures the RUNTIME selector S (n_S) — beta binding — or a build constant
# (alpha). The returned `_d(blob, table, default, module_id, g)` mirrors t_decoy_set_s + t_decoy_tail:
# select the real/decoy slice via the shared selector, inject the oracle into the SATELLITE's own
# globals `g` (so the body's `globals().setdefault(oname, fallback)` finds it — globals() excludes
# builtins), then exec the body into `g`. Per-module key salt is already baked into the table's kmask.
def t_mkdec(S, KS, KDF, O, ON, ZL, SS, MK, FN):
    def _d(blob, table, default, module_id, g):
        ent = table.get(KDF((S ^ SS) & MK), default)
        key = (ent[2] ^ (S * ent[3])) & MK
        src = ZL.decompress(KS(blob[ent[0]:ent[0] + ent[1]], key)).decode('utf-8')
        g[ON] = O
        exec(compile(src, FN, 'exec'), g)
    return _d


def t_mkdec_bc(S, KS, KDF, O, ON, ZL, SS, MK, MAR):
    # Bytecode-format variant: the body slice is a marshalled code object, not source.
    def _d(blob, table, default, module_id, g):
        ent = table.get(KDF((S ^ SS) & MK), default)
        key = (ent[2] ^ (S * ent[3])) & MK
        code = MAR.loads(ZL.decompress(KS(blob[ent[0]:ent[0] + ent[1]], key)))
        g[ON] = O
        exec(code, g)
    return _d


# ---- optional import-hook mode: a sys.meta_path finder that serves registered satellites ----
# FACTORY FORM (like t_mkdec): a top-level def spliced post-flatten. Called as
# `t_meta_finder(REG, DEC)` inside the launcher; the installed finder closes over REG (the
# {module_id: (blob, table, default)} registry embedded in the entry) and DEC (the shared decrypt).
# On `import <registered_id>` it builds the module and decrypts the body into it via the shared dec.
def t_meta_finder(REG, DEC):
    import sys as _pyx_s
    import importlib.util as _pyx_u

    class _F:
        def find_spec(self, name, path=None, target=None):
            if name in REG:
                return _pyx_u.spec_from_loader(name, self)
            return None

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            _e = REG[module.__name__]
            DEC(_e[0], _e[1], _e[2], module.__name__, module.__dict__)

    _pyx_s.meta_path.insert(0, _F())


def t_detect_assign():
    DVAR = DEXPR


# ---- co_code integrity: a non-flattened guard fn + a hash fn + the runtime hash ----
def t_hashfn(b):
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h ^ c) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def t_guard(v):
    return ((v * 0x2545F4914F6CDD1D) ^ (v >> 17)) & 0xFFFFFFFFFFFFFFFF


def t_cohash():
    HVAR = HFN(GUARD.__code__.co_code)


# ---- audit-hook tripwire (persistent poison cell set on trace-set audit events) ----
def t_audit_cell():
    # a 1-element list so the audit hook / oracle / neuter can mutate it by reference (captured at
    # definition time, so it survives the launcher flatten regardless of global/local scoping).
    CELL = [0]


def t_audit_install():
    # Our own audit hook: when ANYONE calls sys.settrace / sys.setprofile (CPython raises these
    # audit events on the real C call, even if sys.gettrace was swapped), set the poison cell. This
    # bridges the launcher->body TOCTOU: the attacker arms on the inner `exec` event and only THEN
    # calls sys.settrace — that call trips this hook, and the cell is read at use-time by the oracle.
    SYS.addaudithook(lambda _e, _a, _c=CELL: _c.__setitem__(0, 1) if _e in ('sys.settrace', 'sys.setprofile') else None)


# ---- detection terms (emit the returned expression) ----
def t_detect_audit():
    # 0 in a clean env; 1 once the audit tripwire has seen a trace-set event.
    return CELL[0]


def t_detect_trace():
    return (SYS.gettrace() is not None) + (SYS.getprofile() is not None)


def t_detect_tools():
    return sum(1 for MVAR in TOOLS if MVAR in SYS.modules)


def t_detect_env():
    return int(SYS.breakpointhook is not SYS.__breakpointhook__) + int(bool(SYS.flags.inspect))


def t_detect_stack():
    return int(SYS._getframe().f_back is not None)


# ---- neuter the debug set-APIs (block a tracer install; allow settrace(None) cleanup) ----
def t_neuter_factory_blackhole(_real, _c):
    # MK(real, cell): returns a guard that passes None through to the real API (harmless cleanup)
    # but blackholes any real tracer/profiler/hook install and trips the poison cell. A late
    # `sys.settrace(tracer)` therefore installs NOTHING and additionally poisons the run (the
    # runtime-bound oracle diverges on the next gated goto).
    def _g(fn=None, *_a, **_k):
        if fn is None:
            return _real(None)
        _c[0] = 1
        return None
    return _g


def t_neuter_factory_honeypot(_real, _c):
    # Stricter MK: a tracer-install attempt poisons AND exits (raised even through the attacker's
    # `try/except Exception` since SystemExit is not an Exception).
    def _g(fn=None, *_a, **_k):
        if fn is None:
            return _real(None)
        _c[0] = 1
        raise SystemExit(0)
    return _g


def t_neuter_set():
    SYS.settrace = MK(SYS.settrace, CELL)
    SYS.setprofile = MK(SYS.setprofile, CELL)
    SYS.addaudithook = MK(SYS.addaudithook, CELL)


def t_neuter_threading():
    THREADING.settrace = MK(THREADING.settrace, CELL)
    THREADING.setprofile = MK(THREADING.setprofile, CELL)


def t_neuter_monitoring_safe():
    # PEP 669 (3.12+). Best-effort: sys.monitoring may not exist (try/except is the cross-version
    # guard for the source/text build) or may reject attribute assignment; either way we degrade.
    try:
        SYS.monitoring.set_events = lambda *_a, **_k: CELL.__setitem__(0, 1)
        SYS.monitoring.set_local_events = lambda *_a, **_k: CELL.__setitem__(0, 1)
        SYS.monitoring.register_callback = lambda *_a, **_k: CELL.__setitem__(0, 1)
    except Exception:
        pass


def t_neuter_selfcheck():
    # PASSIVE install check (must NOT call the patched settrace — that would self-trip the poison):
    # after patching, sys.settrace is a Python function; if it is still a native builtin the patch
    # did not take (tamper / restored) -> poison. type(''.join) is the builtin reference type.
    if type(SYS.settrace) is type(''.join):
        CELL[0] = 1
