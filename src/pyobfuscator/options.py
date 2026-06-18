from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OutputFormat(Enum):
    PYC = "pyc"
    AST = "ast"
    TEXT = "text"


class UnsupportedPolicy(Enum):
    STRICT = "strict"      # (default): collect ALL diagnostics, raise, reject whole unit
    # Reserved (not implemented):
    # REPORT = "report"
    # SKIP = "skip"


def _coerce_output(value) -> OutputFormat:
    if isinstance(value, OutputFormat):
        return value
    return OutputFormat(value)


# protect_level presets — convenience bundles over the individual protection flags.
_PROTECT_PRESETS = {
    "off": {},
    # static protection + decoy-on-tamper, NO anti-trace -> the program stays debuggable
    "light": dict(pack_body=True, key_from_cff=True, integrity_selfcheck=True,
                  pack_decoy=True, obf_imports=True),
    # everything + anti-trace honeypot (debugger / settrace / coverage at load -> decoy)
    "full": dict(pack_body=True, key_from_cff=True, integrity_selfcheck=True,
                 pack_decoy=True, obf_imports=True, detect_trace=True,
                 detect_tools=True, detect_env=True, key_binds_env=True),
}


def _apply_protect_level(opts) -> None:
    """Expand a `protect_level` preset onto the individual protection flags. "off" (default)
    leaves the individual flags untouched (fine-grained control); "light"/"full" SET the bundle
    (a preset overrides individual protection flags)."""
    level = getattr(opts, "protect_level", "off")
    if level not in _PROTECT_PRESETS:
        raise ValueError(f"invalid protect_level: {level!r} (expected off|light|full)")
    for k, v in _PROTECT_PRESETS[level].items():
        setattr(opts, k, v)


@dataclass
class ObfOptions:
    output: OutputFormat = OutputFormat.PYC
    strip_debug: bool = False
    on_unsupported: UnsupportedPolicy = UnsupportedPolicy.STRICT
    seed: int | None = None
    emit_sourcemap: bool = False  # opt-in: assemble a JSON deobfuscation map into a caller-supplied sink (obf_*/emit `sourcemap_out`). NEVER embedded in the artifact; output stays byte-identical when on
    max_block_stmts: int | None = None
    min_blocks: int = 2  # skip flattening functions with fewer basic blocks (no real control flow)
    safe_mode: bool = True  # finally strategy: True=hybrid (real try/finally), False=full-flatten (not yet implemented)
    obf_strings: bool = True   # obfuscate str/bytes constants into runtime-decode expressions
    obf_ints: bool = False     # obfuscate int constants (opt-in; bloats; skips abs(n) <= 1)
    shuffle_states: bool = True   # remap dispatcher state ids to random ints + shuffle guards
    opaque_predicates: bool = True   # wrap goto-assignments in always-true predicates
    bogus_blocks: bool = True        # inject unreachable bogus dispatcher states
    bogus_clone_ratio: float = 1.0  # fraction of bogus blocks built by MIRRORING a real block (cloned, all vars renamed to fresh randoms); the rest use a realistic synthesized body. (0=all synthesized) — default 1.0 so bogus reads like real branches, never obvious junk
    slot_vars: bool = False   # map safe function locals to indices of a fresh `_slots` list
    stack_calls: bool = False  # internal-function calls pass args via a global stack (opt-in)
    hide_external_args: bool = False  # route external/native calls' positional args via the hidden stack
    split_calls: bool = False  # spread push/pop/call of hidden-arg calls across >=2 dispatcher blocks
    return_var: bool = False   # rewrite `return x` -> `_r = x; return _r` (bare -> `_r = None`)
    dedup: bool = False        # merge byte-identical dispatcher blocks (fixpoint)
    state_delta: bool = False   # relative state transitions: `state = T` -> `state += (T - k)`
    dispatch_tree: bool = False # binary-search-tree dispatch instead of a flat if-chain
    junk_code: bool = False  # insert REACHABLE junk blocks (dead computation) on real Goto edges
    dict_indirect: bool = False  # route internal-function references through a per-scope _D[key] dict
    const_archive: bool = False  # pool int/float/str/bytes literals into ONE encrypted blob + a _get(off,sz,key,cast) accessor (supersedes inline obf_strings/obf_ints encoding when on)
    name_vault: bool = False  # route referenced builtins through a per-module vault _D[k]=getattr(builtins,name), bootstrapped from __import__(charcode 'builtins'); name strings get pooled by const_archive (runs after). Excludes super/dunders/shadowed/decorator-position names
    name_vault_attrs: bool = False  # requires name_vault; route attribute READS obj.attr -> getattr(obj,'attr') via the vault bootstrap, pooling attr-name strings (Load-only; decorator-position attributes kept bare)
    hide_compares: bool = False  # rewrite user `expr == CONST` / `!= CONST` (int, |CONST|>1) to `_h(expr) <op> <baked>` where _h = splitmix64(zigzag) and <baked>=_h(CONST) at build — the constant never appears plaintext at runtime, so an AST-instrumentation differential reads only the digest. Portable (pure int math). Bar-raiser (small CONSTs brute-forceable); fully closed paired with body-self-cohash on PYC

    # --- Python-layer kernel protection ---
    pack_body: bool = False     # wrap obfuscated body in an encrypted blob + launcher
    pack_format: str = "auto"   # "auto" (.py->source / .pyc->bytecode) | "source" | "bytecode"
    key_from_cff: bool = False  # derive packer key from launcher control-flow fold; else temp key
    integrity_selfcheck: bool = False  # fold builtin-identity into the selector (anti-monkeypatch)
    cohash_integrity: bool = False     # fold a hash of a non-flattened guard fn's co_code into the selector
    body_cohash: bool = False          # PYC-ONLY: the BODY self-verifies — each oracle-gated transition folds H=FNV(guard.__code__.co_code) recomputed at runtime; protect bakes H_build into the correction so the genuine path cancels and ANY body tamper that recompiles co_code (an AST-instrumentation differential / bytecode rewrite) flips H -> wrong state -> decoy. Extends integrity to the body (cohash_integrity only guards the launcher). Requires attest=True; rejected for TEXT (a TEXT body is recompiled by the end user's interpreter, so co_code would not match H_build — that is exactly what TEXT portability needs, hence PYC-only)
    pack_decoy: bool = False           # tamper/wrong-path -> branchlessly decrypt+run a DECOY body
    key_binds_env: bool = False        # let detection signals into the selector (default off = no FP)
    detect_trace: bool = False  # fold sys.gettrace()/getprofile() activity into the detection aggregate D
    detect_tools: bool = False  # fold sys.modules debugger/coverage fingerprint into D
    detect_env: bool = False    # fold breakpointhook-replaced / interpreter-inspect-mode into D
    detect_stack: bool = False  # ENTRY-ONLY: foreign exec/import/runpy of the entry -> D; FP-prone
    obf_imports: bool = False  # route the launcher's own imports (sys/marshal) through __import__
    protect_level: str = "off"  # preset: "off" (use individual flags) | "light" | "full"
    compress_output: bool = False  # FINAL distribution wrap: zlib+rolling-XOR the whole emitted payload (launcher/module), exec'd by a tiny bootstrap (TEXT -> b85 source wrapper; PYC -> marshalled-code wrapper). Shrinks the distributed file + a static-extraction speed bump that lures exec-hooking into the builtin-integrity honeypot. detect_stack adapts to the extra wrapper frame(s).
    compress_rounds: int = 1  # compress_output recursion depth: wrap N times (payload decompressed+exec'd N times). N>1 doesn't shrink further but forces peeling N layers; each round adds one exec frame (detect_stack walks rounds+1).
    require_min_python: bool = False  # TEXT-only: emit a PLAINTEXT guard in the OUTERMOST layer (compress_output -> top of the bootstrap; else top of the source, after any docstring/__future__) that SystemExits if the runtime Python < MIN_SUPPORTED_PYTHON (the obfuscator's declared floor). Gives a clean "requires Python X.Y+" message instead of a cryptic failure on a too-old interpreter. No-op + warns for PYC/AST (a .pyc is already version-locked by its magic).
    attest: bool = False         # cff<->python oracle attestation: gated state transitions require the launcher oracle (requires pack_body+key_from_cff)
    attest_density: float = 0.3  # fraction of dispatcher gotos to gate via the oracle
    attest_inflate: bool = True  # inflate small/low-complexity units with DEAD clone blocks (reusing the bogus-clone machinery) so attest_density resolves even on tiny functions; clones never run (no-op unless attest is active)
    attest_target_blocks: int = 10  # per flattened unit, inflate up to this many dispatcher blocks when attest_inflate
    builtin_checks: tuple = ("compile", "exec", "pow", "sum", "open", "len")  # builtins whose identity folds into the integrity term (relative type check); configurable
    builtin_spot_count: int = 3  # per build, additionally spot-check this many (random subset) for being a Python-defined function (absolute __code__ check) — defends uniform replacement of all builtins
    # --- anti-TOCTOU defenses: close the audit-hook + late-settrace gap. All OFF by default and
    # OUT of the presets (they can false-positive under coverage/profilers). ---
    detect_audit: bool = False          # install a sys.addaudithook tripwire; a sys.settrace/setprofile event sets a persistent poison cell (folds into D under key_binds_env)
    attest_runtime_bind: bool = False   # the installed attest oracle folds a RUNTIME signal (gettrace/getprofile/audit-poison/pow-recheck) into its key, re-evaluated on every gated goto (requires attest); clean env -> signal 0 -> byte-identical genuine path
    anti_trace_neuter: bool = False     # before exec'ing the body, neuter the debug set-APIs (sys.settrace/setprofile, threading.settrace/setprofile, sys.monitoring 3.12+, sys.addaudithook). settrace(None) is allowed; a non-None tracer install is blackholed (default) and sets the poison cell
    anti_trace_neuter_honeypot: bool = False  # reaction to a blocked tracer-install: True = run honeypot/decoy then SystemExit; False (default) = silent blackhole + poison

    def __post_init__(self):
        self.output = _coerce_output(self.output)
        _apply_protect_level(self)


@dataclass
class ModuleObfOptions(ObfOptions):
    emit_pyi: bool = False
    single_file_interface: bool = False
    exports: list[str] = field(default_factory=list)
    exports_from_all: bool = True
    decoy_src: str | None = None       # decoy program source (build-workflow input); None -> sentinel fallback
    handler_src: str | None = None     # user honeypot handler (build-input): reads M.* signals, sets M.POISON
    decoy_obf_overrides: dict | None = None  # pack_decoy: optional per-flag CFF overrides for the EMBEDDED decoy's obfuscation (keys = ObfOptions field names, e.g. dict(opaque_predicates=False, obf_strings=False)). None -> the decoy inherits the body's flags. attest/attest_runtime_bind/body_cohash/cohash_integrity are ALWAYS forced off for the decoy: it is reached BECAUSE anti-debug fired, so it must run under the very debugger that selected it. "const based on state" (key_consts) stays on while obf_ints/const_archive/name_vault remain on
