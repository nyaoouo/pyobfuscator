# pyobfuscator — Options Reference

Every obfuscation and protection knob lives on two dataclasses in
[`src/pyobfuscator/options.py`](../src/pyobfuscator/options.py):

- **`ObfOptions`** — used by `obf_func`; the full obfuscation + protection surface.
- **`ModuleObfOptions(ObfOptions)`** — used by `obf_module`; adds module-level options (decoy source,
  honeypot handler, exports).

```python
from pyobfuscator import obf_module, ModuleObfOptions
out = obf_module(src, ModuleObfOptions(output="text", seed=1, pack_body=True, key_from_cff=True))
```

Conventions used below:

- **Effect** — what the flag changes in the output.
- **Impact** — cost/consequence (artifact size, runtime overhead, determinism, portability). Measured figures are in §15.
- **Limitations** — preconditions, fail-loud rejections, false-positive risk, and interactions.

Two global properties hold for every flag:

- **Deterministic.** Same `source + seed + flags` ⇒ byte-identical output. With `seed=None` a random
  seed is drawn per call.
- **Equivalence-gated.** On the untampered path the obfuscated program is behaviour-identical to the
  original (return value, exception type+message, stdout, argument mutation). Anything the engine cannot
  provably preserve is rejected fail-loud (see `on_unsupported`).

---

## 1. Core / output

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `output` (`"pyc"`) | Output format: `"pyc"` (PEP-552 hash-based, unchecked, **sourceless** `.pyc` bytes), `"text"` (obfuscated source string), `"ast"` (an `ast.Module`). | `pyc` is compact and runs without a source file; `text` is portable across Python versions; `ast` is for further programmatic processing. | A `.pyc` is **version-locked** by its magic number (runs only on the build interpreter's Python version). `output="ast"` skips the packer entirely, so `pack_body`/`attest`/etc. do nothing. |
| `seed` (`None`) | Seed for every randomized decision (state ids, name finalization, key derivation, RSA params). | Controls reproducibility. | `None` ⇒ a fresh random seed each call ⇒ non-reproducible output. Set an int for reproducible builds. |
| `strip_debug` (`False`) | Resets all AST source positions to line 1 / col 0. | Removes line-number information from tracebacks; marginally smaller. | None. |
| `on_unsupported` (`STRICT`) | Policy for constructs the gate cannot preserve. `STRICT` collects all diagnostics and raises, rejecting the whole unit. | Fail-loud — never silently ships a wrong transform. | Only `STRICT` is implemented; `REPORT`/`SKIP` are reserved. |
| `min_blocks` (`2`) | Skip flattening a function whose body lowers to fewer than this many basic blocks. | Avoids bloating trivial functions that have no real control flow. _Measured (§15): higher values shrink the artifact (e.g. 12 KB → 8 KB at `min_blocks=8`)._ | A function below the threshold is emitted unflattened (still subject to other passes). |
| `max_block_stmts` (`None`) | Cap statements per dispatcher block; oversized blocks are split across states. | Prevents any single state from being a large, recognizable tell. | `None` = no cap. The launcher flatten applies a default cap of 12 regardless. |
| `emit_sourcemap` (`False`) | Assemble a JSON deobfuscation map into a caller-supplied `sourcemap_out` sink. | Build-time only; a debugging/audit aid. | **Never embedded** in the artifact; output stays byte-identical whether on or off. Requires passing `sourcemap_out=` to `obf_*`/`emit`. |

---

## 2. Control-flow flattening (dispatcher structure)

The core transform turns each function / method / module body into a `while True` state-machine
dispatcher. These flags shape that dispatcher. All are deterministic and behaviour-preserving.

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `safe_mode` (`True`) | `try/finally` strategy. `True` = hybrid (keeps a real `try/finally`); `False` = full-flatten using a continuation-stack unwind model. | `False` flattens finally bodies more deeply. | `False` rejects `return`/`break`/`continue` inside a `finally` block (fail-loud). |
| `shuffle_states` (`True`) | Remap dispatcher state ids to random ints and shuffle the guard order. | Removes sequential state numbering as a tell. _Measured (§15): within run-to-run noise._ | None. |
| `opaque_predicates` (`True`) | Wrap goto-assignments in always-true opaque predicates (a family of ≥5 true / ≥5 false integer identities per site, random polarity, fed by live `state`). | Larger, harder-to-simplify dispatcher. _Measured (§15): runtime +~5–10%, size +~1 KB._ | None (behaviour-preserving by construction). |
| `bogus_blocks` (`True`) | Inject unreachable bogus dispatcher states via never-taken edges. | Adds plausible dead states. _Measured (§15): +~4 KB and a real runtime cost (≈+35% on cpu) — the flat dispatcher skips more guards._ | Behaviour-preserving (unreachable). |
| `bogus_clone_ratio` (`1.0`) | Fraction of bogus blocks built by **cloning + mutating a real block** (vs synthesizing a realistic body). `0.0` = all synthesized. | At `1.0` bogus states read like real branches instead of obvious junk. | Cloning requires real blocks on the genuine flow; falls back to synthesis when none exist. Clones go only into unreachable bogus states. |
| `dedup` (`False`) | Merge byte-identical dispatcher blocks (fixpoint). | Smaller dispatcher. _Measured (§15): negligible._ | Skips blocks that need a per-block key (`needs_k`), e.g. attest/key-const blocks. |
| `state_delta` (`False`) | Relative transitions: `state = T` becomes `state += (T - k)`. | Hides absolute target states. _Measured (§15): negligible._ | None. |
| `dispatch_tree` (`False`) | Replace the flat `if state == k` chain with a binary-search-tree dispatch (no `state == k` leaves). | Removes the equality-comparison signature of the dispatcher. _Measured (§15): runtime FASTER than the flat chain (cpu ×2.5 vs ×4.5 baseline)._ | None. |
| `junk_code` (`False`) | Insert **reachable** inert junk blocks (dead computation) on real goto edges. | Adds runtime-executed but effect-free work. _Measured (§15): runtime +~15%, size +~1 KB._ | Behaviour-preserving; small runtime cost. |
| `return_var` (`False`) | Rewrite `return x` → `_r = x; return _r` (bare `return` → `_r = None`). | Normalizes return sites. _Measured (§15): negligible._ | None. |

---

## 3. Data & constant obfuscation

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `obf_strings` (`True`) | Encode `str`/`bytes` literals as runtime-decoded expressions via a pow/RSA-style codec (`pow(m,e,n)`, helper `_dec`). | No plaintext string/bytes literals in the output; modest size + runtime cost. _Measured (§15): ≈free on numeric code, ≈×26 runtime on string-heavy code (data-dependent)._ | Superseded by `const_archive` when that is on. Docstrings are **not** encoded (they stay plaintext — see warnings). |
| `obf_ints` (`False`) | Encode integer constants as state-keyed expressions (`enc - (state & mask)`, per-block key). | Hides numeric literals. _Measured (§15): runtime +~10%, size +~0.6 KB._ | Opt-in because it bloats. Skips `abs(n) <= 1`. Eager-path only. |
| `const_archive` (`False`) | Pool **all** `int`/`float`/`str`/`bytes` literals into one layered-encrypted blob plus a `_get(off,sz,key,cast)` accessor. | One opaque data package instead of many inline literals; supersedes inline `obf_strings`/`obf_ints` encoding. _Measured (§15): largest data footprint (+~10 KB), but decodes strings cheaper than `obf_strings` (str ×5.7 vs ×26)._ | Larger fixed blob; accessor adds a small per-read cost. Skips tiny ints (`abs(v) <= 1`) and nodes marked no-archive. |
| `hide_compares` (`False`) | Rewrite user `expr == CONST` / `!= CONST` (integer, `|CONST| > 1`) to `_h(expr) <op> <baked>`, where `_h` is a bijective `splitmix64(zigzag)` and `<baked>` is `_h(CONST)` computed at build. | The constant never appears in plaintext at the comparison site, so an instrumentation differential reads only the 64-bit digest. Pure integer math ⇒ **portable** (TEXT + PYC, cross-version). _Measured (§15): near-free unless the code has many eligible compares._ | Bar-raiser only: small constants remain brute-forceable from the digest. Fully closed when paired with `body_cohash` on PYC. Does not touch the dispatcher's own `state == k` comparisons (it runs before flattening). |

---

## 4. Call & name hiding

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `stack_calls` (`False`) | Route eligible internal-function call arguments through a hidden `threading.local` push/pop/invoke stack instead of direct call syntax. | Hides call arity/argument wiring. _Measured (§15): near-free at runtime, size +~2 KB._ | Only safe, resolvable calls (unique non-method def, no complex arg forms) are routed. |
| `hide_external_args` (`False`) | Also route external/native calls' positional args through the hidden stack. | Extends arg-hiding to library/builtin calls. _Measured (§15): heavy on call-dense code (str ×8.9), size +~3 KB._ | Disabled on the launcher when anti-TOCTOU machinery is present (it would corrupt the oracle/audit closures). |
| `split_calls` (`False`) | Spread the push/pop/call of a hidden-arg call across ≥2 dispatcher blocks. | De-signatures call sites further. _Measured (§15): same cost as `hide_external_args`._ | Requires `stack_calls`/`hide_external_args` to have an effect. |
| `slot_vars` (`False`) | Map safe function locals to indices of a fresh `_slots` list (`_slots[i]`). | Removes local variable names. _Measured (§15): near-free._ | Only provably-safe locals (not params, captures, `global`/`nonlocal`, comprehension/with/except targets). |
| `dict_indirect` (`False`) | Route internal-function (and const-like global) references through a per-scope `_D[key]` dict. | Hides callable identity behind a subscript. _Measured (§15): negligible._ | Excludes methods, exports, and `del`-targeted names. |
| `name_vault` (`False`) | Route referenced builtins + simple top-level imports through a per-module vault (`_D[k] = getattr(builtins, name)` / `__import__(mod)`), bootstrapped from a char-code `__import__('builtins')`. | Builtin/import names become integer-keyed lookups; the name strings are then pooled by `const_archive`. _Measured (§15): runtime +~10–30%, size +~2 KB._ | Excludes `super` (needs the lexical `__class__` cell), dunders, shadowed names, and decorator-position names. Name strings only become non-plaintext when `const_archive` is also on (it runs after). |
| `name_vault_attrs` (`False`) | Also route attribute reads `obj.attr` → `getattr(obj, "attr")` (and writes/deletes via `setattr`/`delattr`) through the vault, pooling attribute-name strings. | Hides the `.attr` surface (e.g. the `sys.settrace`/`monitoring` anti-debug attribute names). _Measured (§15): ≈same as `name_vault`._ | **Requires `name_vault`.** Load-context reads + single-target writes/deletes only; decorator-position attributes are kept bare. |

---

## 5. Packer & control-flow-derived key

The packer wraps the obfuscated body in an encrypted blob carried by a launcher that decrypts and
`exec`s it. These run only for `output` `"text"`/`"pyc"`.

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `pack_body` (`False`) | Wrap the obfuscated body in a compressed + encrypted blob with a launcher that reconstructs and `exec`s it in its own globals. | The body is no longer directly readable; the launcher carries it. _Measured (§15): build +~28 ms; +~10–20 ms one-time startup; the zlib-compressed blob is often smaller than the inline body._ | No effect for `output="ast"`. Body is zlib-compressed before encryption (automatic). |
| `pack_format` (`"auto"`) | Body serialization: `"auto"` (`.py`→source / `.pyc`→bytecode), `"source"`, `"bytecode"`. | `bytecode` is compact and version-locked; `source` is portable. | `auto` follows `output`. |
| `key_from_cff` (`False`) | Derive the decryption key from a fold over the launcher's own correct dispatch path (`KDF(fold)`), not a stored constant. | Tampering with the flattened control flow ⇒ wrong key ⇒ garbage/decoy. _Measured (§15): negligible over `pack_body`._ | Without it a temporary hardcoded key is used (much weaker). Required by `attest`. |
| `obf_imports` (`False`) | Route the launcher's own imports (`sys`/`marshal`/`zlib`/`base64`) through `__import__(''.join(map(chr,…)))`. | No greppable/editable `import` statements in a text distribution. _Measured (§15): negligible._ | None. |

---

## 6. Integrity & decoy

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `integrity_selfcheck` (`False`) | Fold builtin-identity checks (`type(sum/open/len/…) is builtin_type`) into the key selector. | A monkeypatched builtin ⇒ wrong key ⇒ decoy. _Measured (§15): negligible._ | See `builtin_checks`/`builtin_spot_count` for what is checked. |
| `cohash_integrity` (`False`) | Fold a runtime hash of a non-flattened guard function's `co_code` into the selector. | Patching the guard's bytecode ⇒ wrong key ⇒ decoy. _Measured (§15): size +~2 KB, negligible runtime._ | **Version-locking on TEXT** (hashes version-specific bytecode) — a genuine run on a different Python version decodes the decoy. Warns on TEXT; use PYC (already version-locked) for portability. |
| `body_cohash` (`False`) | The body self-verifies: each oracle-gated transition folds `H = hash(guard.__code__.co_code)` recomputed at runtime; the build bakes `H_build` into the correction so the genuine path cancels and any body recompile/instrumentation flips `H` → decoy. | Extends integrity from the launcher to the body. _Measured (§15): near-zero on top of `attest` (+~0.3 KB)._ | **Requires `attest=True` and `output="pyc"`** (fail-loud `ValueError` otherwise) — a TEXT body is recompiled by the end user, so its `co_code` would not match the baked hash. |
| `pack_decoy` (`False`) | On tamper/wrong-path, branchlessly decrypt and run a **decoy** body instead of failing. Real and decoy share one ciphertext; selection is a `dict.get` + arithmetic with no patchable boolean. The real key is stored only as `K_real ^ S_correct`. | Detection becomes a honeypot: the attacker reaches a believable decoy. _Measured (§15): +~0.6 KB build cost (the decoy is obfuscated too); negligible runtime._ | Uses `decoy_src` if provided, else a built-in sentinel decoy. The embedded decoy is obfuscated through the same pipeline (see `decoy_obf_overrides`). |

---

## 7. Detection (anti-debug signals)

Each detector contributes a term that is `0` in a clean process and `> 0` when triggered. Folding into
the key requires `key_binds_env`; without it, signals are still computed and exposed to a `handler_src`
but do not affect the key.

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `key_binds_env` (`False`) | Let enabled detection signals fold into the key selector (any trigger ⇒ wrong key ⇒ decoy). | Turns detection into key-binding. _Measured (§15): negligible._ | Off by default to avoid false positives. Build assumes a clean environment (aggregate `== 0`). |
| `detect_trace` (`False`) | Fold `sys.gettrace()` / `getprofile()` activity into the detection aggregate. | Catches debuggers / `settrace`-based tracers / coverage at load. _Measured (§15): negligible._ | Can false-positive under coverage/profilers. |
| `detect_tools` (`False`) | Fold a `sys.modules` fingerprint (pydevd/debugpy/coverage) into the aggregate. | Catches common debug/coverage tooling. _Measured (§15): negligible._ | Module-name based. |
| `detect_env` (`False`) | Fold "breakpointhook replaced" / interpreter inspect-mode (`-i`/`PYTHONINSPECT`) into the aggregate. | Catches debugger-set hooks and inspect mode. _Measured (§15): negligible._ | — |
| `detect_stack` (`False`) | **Entry-only.** Fold "the entry was reached via a foreign `exec`/`import`/`runpy`/`-m` rather than `python file`" into the aggregate. | Catches harnesses that exec/import the script to rip it, even when faking `__name__ == "__main__"`. _Measured (§15): negligible._ | **FP-prone and entry-only** — not in any preset. Makes `import <module>` serve the decoy by design (a genuine entry is `python <module>`). Adapts to `compress_output` wrapper frames. |
| `builtin_checks` (`("compile","exec","pow","sum","open","len")`) | Which builtins get a relative identity term in the integrity fold. | Configurable anti-monkeypatch surface. | `compile`/`exec` are additionally checked via their effective (global-or-builtin) binding to catch a global shadow. |
| `builtin_spot_count` (`3`) | Per build, additionally spot-check this many random builtins with an absolute "is this a Python-defined function?" (`__code__`) term. | Catches **uniform** replacement of every builtin (the blind spot of relative-only checks). | Clamped to `len(builtin_checks)`. |

---

## 8. Attestation (cff ↔ python oracle)

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `attest` (`False`) | The launcher installs an oracle `O(s) = mix(s, S_correct, MAGIC)` into the body globals; a subset of dispatcher gotos become `state = O(state) ^ CORRECTION`, so the next state needs the runtime state **and** the launcher key **and** the magic. A body dumped without the oracle diverges — defeats offline dump-and-replay. | Strong defense against extracting and replaying the body blob. _Measured (§15): the costliest flag — ≈2× body runtime and ≈7× build time._ | **Requires `pack_body=True`, `key_from_cff=True`, and `output` `"text"`/`"pyc"`** (fail-loud `ValueError` otherwise — the packer is what installs the oracle and patches the corrections). |
| `attest_density` (`0.3`) | Fraction of dispatcher gotos to gate through the oracle (deterministic target, floor-guaranteed). | Higher = more gates = more tamper coverage, larger output. _Measured (§15): runtime scales with density — cpu ×11.6 → ×30 from 0.1 → 1.0._ | Needs enough blocks; see `attest_inflate`. |
| `attest_inflate` (`True`) | Inflate small/low-complexity units with dead clone blocks so density resolves even on tiny functions. | Lets density take effect on small functions. | No-op unless `attest` is active; clones never run. |
| `attest_target_blocks` (`10`) | Per flattened unit, inflate up to this many dispatcher blocks when `attest_inflate`. | Controls inflation budget. | — |
| `attest_runtime_bind` (`False`) | The installed oracle's key additionally folds a **runtime** signal (`gettrace`/`getprofile`/audit-poison/`pow`-recheck), re-evaluated on every gated goto. | A tracer attached at **any** time (even mid-body) makes the next gated transition diverge. _Measured (§15): a little more runtime than `attest` alone (cpu ×19.5)._ | **Requires `attest`.** FP-prone (coverage/profilers); off by default and out of presets. Clean env ⇒ signal `0` ⇒ byte-identical genuine path. |

---

## 9. Anti-TOCTOU (load-time → run-time gap)

All default **off** and **out of the presets** — they can false-positive under coverage/profilers.

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `detect_audit` (`False`) | Install an `sys.addaudithook` tripwire that sets a persistent poison cell on any `sys.settrace`/`setprofile` event. | Catches a tracer attached **after** the one-time bootstrap checks; folds into the aggregate under `key_binds_env`, and is read by `attest_runtime_bind` and the neuter. _Measured (§15): negligible._ | FP-prone. |
| `anti_trace_neuter` (`False`) | Before `exec`ing the body, neuter the debug set-APIs (`sys`/`threading` settrace/setprofile, `sys.addaudithook`, `sys.monitoring` on 3.12+). `settrace(None)` still passes; a non-None tracer install is blackholed (default) and poisons the cell. | Actively blocks tracer installation. _Measured (§15): roughly doubles the launcher size (+~7.6 KB), build +~22 ms; runtime unchanged._ | FP-prone. |
| `anti_trace_neuter_honeypot` (`False`) | Reaction mode for the neuter: `True` = run the decoy then `SystemExit` on a tracer-install attempt; `False` (default) = silent blackhole + poison. | Louder vs stealthier response. _Measured (§15): ≈same as the neuter._ | Requires `anti_trace_neuter`. |

---

## 10. Output wrapping & distribution

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `compress_output` (`False`) | Final distribution wrap: zlib + rolling-XOR the whole emitted payload, re-`exec`'d by a tiny bootstrap (TEXT → b85 source wrapper; PYC → marshalled-code wrapper). | Shrinks the distributed file and adds a static-extraction speed bump that lures exec-hooking into the integrity honeypot. _Measured (§15): ≈−36% size; runtime/startup unchanged._ | `output` `"text"`/`"pyc"` only. `detect_stack` adapts to the added wrapper frame(s). |
| `compress_rounds` (`1`) | Recursion depth of `compress_output`: wrap N times (payload decompressed + `exec`'d N times). | `N > 1` does not shrink further but forces an extractor to peel N layers; each round adds one `exec` frame (`detect_stack` walks `rounds + 1`). _Measured (§15): +~0.3 KB per round, no runtime change._ | Requires `compress_output`. |
| `require_min_python` (`False`) | Emit a plaintext guard in the outermost layer that `SystemExit`s with a clean "requires Python X.Y+" message if the runtime is below `MIN_SUPPORTED_PYTHON` (`(3, 11)`). | Friendly failure on too-old interpreters instead of a cryptic error. _Measured (§15): negligible._ | **TEXT-only** — no-ops and warns for PYC/AST (a `.pyc` is already version-locked by its magic). The message deliberately does not name the tool. |

---

## 11. Presets

| Option (default) | Effect |
|---|---|
| `protect_level` (`"off"`) | Convenience bundle over the individual protection flags. `"off"` = use individual flags (no preset). `"light"` = `pack_body + key_from_cff + integrity_selfcheck + pack_decoy + obf_imports` (static protection + decoy, still debuggable). `"full"` = `light` + `detect_trace + detect_tools + detect_env + key_binds_env` (adds the anti-trace honeypot). A non-`off` preset **sets** those flags (overriding individual values). `detect_stack` and the anti-TOCTOU flags are never in a preset. _Measured (§15): `light`/`full` ≈ the `pack_body` base + ~10 ms startup; the packed body is smaller than uncompressed defaults._ |

---

## 12. Module-only options (`ModuleObfOptions`)

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `decoy_src` (`None`) | Source of the decoy program used by `pack_decoy`. | A realistic, build-authored decoy. | `None` ⇒ a built-in sentinel decoy. |
| `decoy_obf_overrides` (`None`) | Per-flag CFF overrides for the embedded decoy's obfuscation (e.g. drop opaque predicates / string obfuscation so a triggered decoy is legible). | Tune the decoy's strength independently of the body. | Applied on top of the body's flags. `attest`/`attest_runtime_bind`/`body_cohash`/`cohash_integrity`/pack/compress are **always forced off** for the decoy (it runs under the very debugger that selected it). |
| `handler_src` (`None`) | Inline a build-authored honeypot handler that reads detection signals as `M.TRACE/TOOLS/ENV/STACK` and may set `M.POISON`. | Custom policy + a safe outlet for FP-prone signals that should not touch the key. | `POISON` folds into the selector like the detection aggregate; build assumes `POISON == 0`. |
| `exports` (`[]`) | Names to treat as the module's public interface. | Kept callable/visible from outside. | — |
| `exports_from_all` (`True`) | Treat `__all__` as exports. | Honors the module's declared public surface. | — |
| `emit_pyi` (`False`) | Emit a `.pyi` stub interface. | Type-checker-visible surface. | — |
| `single_file_interface` (`False`) | Single-file interface mode. | — | — |

---

## 12b. `obf_project` — multi-module project obfuscation

```python
from pyobfuscator import obf_project, ModuleObfOptions

manifest = obf_project(
    root="src/myapp",
    out="dist/myapp",
    entry="main.py",
    protect=["app/secret.py", "app/logic/*.py"],
    options=ModuleObfOptions(
        output="pyc", seed=42,
        pack_body=True, key_from_cff=True,
        attest=True, pack_decoy=True,
    ),
)
# manifest == {"main.py": "entry", "app/secret.py": "protect",
#              "app/__init__.py": "plaintext", ...}
```

`obf_project` obfuscates an entire Python source tree. It mirrors the tree into `out`, obfuscating
selected files and copying the rest verbatim. It returns a `{relative_path → role}` manifest where
`role` is `"entry"`, `"protect"`, or `"plaintext"`.

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `root` | — | Source tree root directory. |
| `out` | — | Output directory. The source tree layout is mirrored into it. |
| `entry` | — | Relative path of the entry module (e.g. `"main.py"`). Must exist under `root`. Fail-loud if missing. |
| `protect` | `None` | List of relative paths and/or `fnmatch` glob patterns selecting files to obfuscate. The entry is never in this set even if a pattern matches it. Each pattern must match at least one file (fail-loud otherwise). `None` or `[]` means no satellites. |
| `options` | `ModuleObfOptions()` | A `ModuleObfOptions` instance (the same options object as `obf_module`). The same `seed` is shared across all files, which is what makes the selector `s_correct = f(seed)` agree everywhere without a build-ordering dependency. |
| `import_hook` | `False` | When `True`, satellite blobs are embedded in a registry inside the entry and the entry installs a `sys.meta_path` finder that decrypts satellites on `import`. Per-file stub `.py`/`.pyc` files are **not** emitted for satellites; plaintext package files (e.g. `app/__init__.py`) still are. Requires shared-runtime mode (raises `ValueError` otherwise). |
| `shared_oracle_decouple` | `False` | Oracle binding mode. `False` (default, **beta**): the shared `dec` function closes over the entry's runtime selector — tampering the entry's dispatcher makes every satellite decode its decoy. `True` (**alpha**): `dec` closes over the build-time constant selector, so satellites are independent of the entry's runtime integrity (useful for incremental build pipelines). Satellite blobs are byte-identical between both modes. |

### Two operating modes

**Shared-runtime mode** activates when `options` enables the full attestation stack (`attest=True`
+ `pack_body=True` + `key_from_cff=True` + `output` in `"text"`/`"pyc"`) and there is at least one
protected file. In this mode:

- The entry is built with an additional step that publishes a shared `dec` function (decrypt +
  decompress + exec) and the attestation oracle into `builtins`.
- Each protected module ships as a small **stub** + an encrypted blob. The stub calls the published
  `dec`, which decrypts the real or decoy body, injects the oracle into the satellite's own module
  globals, and `exec`s it there. A normal `import app.secret` (or `from app.secret import x`) works
  transparently, including reverse-imports from plaintext modules.
- Because `s_correct = f(seed)` depends only on the seed (and `builtin_checks` options), not on
  any file's source, files build **independently in any order**. Rebuilding a single satellite with
  the same seed and dropping it into the existing output is sufficient — the unchanged entry will
  run it correctly.

**Self-contained fallback** activates when the attestation stack is not enabled (or there are no
protected files). Each protected and entry file is built as an independent self-contained
single-module launcher with no shared runtime. A protected file can then self-decrypt even if the
entry has not run.

### Entry-bound fail-loud

Under **shared-runtime mode**, importing a satellite without the entry having first published the
shared `dec` into `builtins` fails loudly at runtime — the satellite stub's call to the absent
`dec` raises `AttributeError`. Satellites are not designed to be run or imported standalone.

### PYC output

Obfuscated files are emitted as sourceless `.pyc` files when `options.output == "pyc"`: `main.py`
→ `main.pyc` (run with `python main.pyc`); `app/secret.py` → `app/secret.pyc` (imported as `import
app.secret`). Plaintext files always keep their `.py` name.

### Scope and known limits

Supported: regular packages (`app/__init__.py` listed in `protect` is obfuscated; otherwise it is
copied plaintext), reverse imports from plaintext modules into satellites, and circular imports
(standard Python semantics apply).

Not supported: namespace packages (no `__init__.py`), C extensions (`.pyd`/`.so`), and running a
satellite directly with `python -m <satellite>`.

A runnable demo is available at `sample/project_test/` (build with `build_project.py`); the
single-file showcase is at `sample/single_file/`.

---

## 13. Fail-loud precondition summary

The API rejects these combinations up front (rather than shipping a launcher that breaks on the honest
path):

| If you set… | You must also set… | Otherwise |
|---|---|---|
| `attest=True` | `pack_body=True` **and** `key_from_cff=True` | `ValueError` |
| `attest=True` | `output` in `{"text", "pyc"}` | `ValueError` |
| `body_cohash=True` | `attest=True` | `ValueError` |
| `body_cohash=True` | `output="pyc"` | `ValueError` |
| `attest_runtime_bind=True` | `attest=True` | (no effect without it) |
| `name_vault_attrs=True` | `name_vault=True` | (no effect without it) |
| `import_hook=True` (in `obf_project`) | shared-runtime mode (`attest` + `pack_body` + `key_from_cff` + text/pyc + ≥1 protected file) | `ValueError` |

Warnings (not errors):

- `cohash_integrity=True` with `output="text"` — version-locks the TEXT launcher (warns).
- `require_min_python=True` with `output` `"pyc"`/`"ast"` — ignored (warns).
- Any plaintext docstring that will survive into the output — warns so you can remove sensitive ones.

---

## 14. Portability quick reference

| Goal | Use | Avoid |
|---|---|---|
| Cross-version source distribution | `output="text"` + portable flags (`hide_compares`, `attest`, `pack_decoy`, detection) | `cohash_integrity`, `body_cohash` (they version-lock) |
| Version-locked compact binary | `output="pyc"` + `body_cohash` + `cohash_integrity` | — (a `.pyc` is already magic-locked) |
| Importable / runnable single file | `output="pyc"` named `<module>.pyc` (see `sourceless_pyc_name`) | `detect_stack` if you need `import <module>` to work (it serves the decoy on import by design) |

---

## 15. Measured performance

The numbers below are produced by [`bench/benchmark.py`](../bench/benchmark.py) and are
**machine-dependent** — regenerate them on your target machine with:

```
.venv/Scripts/python bench/benchmark.py            # full matrix
.venv/Scripts/python bench/benchmark.py --quick     # smaller subset (dev)
```

This run: Python 3.14.4, Windows 11 (x86-64), `seed=20260618`; build = median of 3,
runtime = median of 4 killable-subprocess runs.

**What is measured** (per configuration, against an unobfuscated baseline):

- **build** — wall time of `obf_module()`.
- **size** — bytes of the emitted artifact.
- **runtime (×)** — the artifact's own hot loop, run in a subprocess, as a multiple of the
  unobfuscated source's runtime.
- **startup** — `subprocess_wall − body_runtime − empty-interpreter boot`: the one-time launcher
  decrypt + `exec` (+ decompress) cost.

Two workloads are used because runtime overhead is **strongly data-type-dependent**: `cpu`
(integer / branch / loop heavy, baseline 68.8 ms) and `str` (string / bytes heavy, baseline
48.7 ms). All 106 configurations produced a behaviour-identical result (matching checksum) — a
runtime corroboration of the equivalence gate.

**Caveats.** Run-to-run noise is ≈±10% — do not over-read sub-10% differences. `startup` is a
derived estimate (a subtraction of three timings near the interpreter-boot magnitude), so treat
it as indicative (±several ms), not exact.

### 15.1 Control-flow flattening (CFF) layer

`build`/`size` are for the `cpu` workload; `runtime` is shown for both. Marginal over plain
flattening (all CFF flags off).

| Config | build (ms) | size (B) | cpu runtime (×) | str runtime (×) |
|---|---|---|---|---|
| baseline (plain flatten) | 10 | 6248 | 4.5 | 2.5 |
| defaults (`obf_strings`+`shuffle_states`+`opaque_predicates`+`bogus_blocks`) | 25 | 11978 | 9.0 | 28.2 |
| `obf_strings` | 13 | 6780 | 4.5 | 25.6 |
| `obf_ints` | 13 | 6859 | 5.0 | 2.7 |
| `shuffle_states` | 11 | 6674 | 3.4 | 3.3 |
| `opaque_predicates` | 13 | 7289 | 4.8 | 2.6 |
| `bogus_blocks` | 18 | 10170 | 6.1 | 4.0 |
| `slot_vars` | 13 | 6465 | 4.9 | 2.7 |
| `stack_calls` | 15 | 8612 | 4.5 | 2.5 |
| `hide_external_args` | 16 | 9386 | 4.5 | 8.9 |
| `split_calls` (+`hide_external_args`) | 16 | 9386 | 4.5 | 8.9 |
| `return_var` | 10 | 6310 | 4.5 | 2.5 |
| `dedup` | 11 | 6248 | 4.5 | 2.5 |
| `state_delta` | 11 | 6268 | 4.6 | 2.7 |
| `dispatch_tree` | 10 | 6891 | 2.5 | 2.1 |
| `junk_code` | 12 | 7502 | 5.1 | 2.8 |
| `dict_indirect` | 12 | 6338 | 4.5 | 2.5 |
| `const_archive` | 29 | 16711 | 9.2 | 5.7 |
| `name_vault` | 15 | 8024 | 4.9 | 3.3 |
| `name_vault_attrs` (+`name_vault`) | 16 | 8072 | 5.0 | 3.3 |
| `hide_compares` | 12 | 6907 | 5.3 | 2.5 |

Highlights: `dispatch_tree` runs **faster** than the flat chain (fewer comparisons per step);
`obf_strings` is near-free on numeric code but ≈×26 on string-heavy code; `const_archive` decodes
strings more cheaply than `obf_strings` (×5.7 vs ×26) but is the largest data footprint (+10 KB);
`bogus_blocks` adds real runtime even though unreachable, because the flat dispatcher must skip
more guards (`dispatch_tree` removes that signature and that cost).

### 15.2 Protection layer

Marginal over `pack_body`+`key_from_cff` (the `cpu` workload). The packed body runs at the
obfuscation defaults' speed; only `attest` changes body runtime. Packing adds a one-time startup
of ≈10–20 ms.

| Config | build (ms) | size (B) | cpu runtime (×) |
|---|---|---|---|
| base (`pack_body`+`key_from_cff`) | 39 | 7722 | 9.0 |
| `integrity_selfcheck` | 43 | 8303 | 8.9 |
| `cohash_integrity` (text: version-locks) | 43 | 9822 | 8.9 |
| `pack_decoy` | 41 | 8304 | 9.0 |
| `obf_imports` | 41 | 7803 | 9.0 |
| `detect_trace` (+`key_binds_env`) | 40 | 7957 | 9.0 |
| `detect_tools` (+`key_binds_env`) | 41 | 8005 | 9.0 |
| `detect_env` (+`key_binds_env`) | 41 | 7996 | 9.0 |
| `detect_stack` (+`key_binds_env`) | 40 | 7919 | 9.0 |
| `detect_audit` | 42 | 8047 | 9.0 |
| `anti_trace_neuter` | 61 | 15320 | 9.0 |
| `anti_trace_neuter` + `honeypot` | 62 | 15810 | 9.0 |
| `attest` (density 0.3) | 74 | 10825 | 17.1 |
| `attest` + `attest_runtime_bind` | 79 | 11726 | 19.5 |
| `compress_output` | 39 | 4916 | 9.0 |
| `compress_output` rounds=2 | 40 | 5207 | 9.0 |
| `require_min_python` | 39 | 7896 | 9.0 |
| `body_cohash` (pyc, over `attest`) | 75 | 11814 | 18.4 |

Highlights: `attest` is the costliest flag — ≈2× body runtime and ≈7× build time;
`attest_runtime_bind` adds a little more. `anti_trace_neuter` roughly doubles the launcher size.
`compress_output` **shrinks** the artifact by ≈36% with no runtime change. `body_cohash` is
near-free on top of `attest` (the pyc `attest` base measures ×18.2). Everything else
(integrity / detection / decoy / imports) stays within build/size noise.

### 15.3 Presets (`protect_level`)

Cumulative, `cpu` workload, output `text`.

| protect_level | build (ms) | size (B) | startup (ms) | runtime (×) |
|---|---|---|---|---|
| off | 25 | 11978 | ~4 | 9.0 |
| light | 46 | 8928 | ~10 | 9.0 |
| full | 48 | 9564 | ~11 | 9.0 |

`light`/`full` are smaller than `off` because the packed body is zlib-compressed, whereas `off`
carries the obfuscation defaults inline.

### 15.4 Knob sweeps

`cpu` workload.

| Knob | value | size (B) | runtime (×) |
|---|---|---|---|
| `attest_density` | 0.1 | 10740 | 11.6 |
| `attest_density` | 0.3 | 10825 | 17.3 |
| `attest_density` | 0.6 | 10703 | 20.2 |
| `attest_density` | 1.0 | 10856 | 30.3 |
| `compress_rounds` | 1 | 4916 | 9.0 |
| `compress_rounds` | 2 | 5207 | 9.0 |
| `compress_rounds` | 3 | 5498 | 9.0 |
| `min_blocks` | 2 | 11978 | 8.9 |
| `min_blocks` | 4 | 9928 | 8.9 |
| `min_blocks` | 8 | 8134 | 8.9 |

`attest_density` trades runtime for tamper coverage (the dominant runtime knob). `compress_rounds`
adds ≈0.3 KB per extra peel layer with no runtime change. Higher `min_blocks` shrinks the artifact
by leaving more small functions unflattened.
