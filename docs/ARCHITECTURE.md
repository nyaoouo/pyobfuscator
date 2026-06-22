# pyobfuscator — Architecture & File Map

A navigation map of the package, intended for developers extending or maintaining it. It covers the
top-level data flow, the pass pipeline, the `protect → cff` dependency rule, and the role + provided
surface of **every** module under `src/pyobfuscator/`.

The package has two layers:

- **`cff/`** — the control-flow-flattening engine. Turns each function / method / module body into a
  `while True` state-machine dispatcher and applies hardening transforms.
- **`protect/`** — the Python-layer protection/packer. Wraps an already-obfuscated module in a launcher
  that carries the body as a compressed + encrypted blob and reconstructs it at runtime.

**Dependency rule:** `protect` may import from `cff`; **`cff` must never import `protect`** (notably
`cff/attest.py`, which shares the oracle `mix()` with the packer but stays self-contained).

---

## Top-level data flow

`obf_func(src, options)` ([`__init__.py`](../src/pyobfuscator/__init__.py)):

```
src → _FUNC_PIPELINE.run → emit(tree, options)
```

`obf_module(src, options)`:

```
src → (fail-loud precondition checks)
    → _MODULE_PIPELINE.run        # the pass pipeline
    → wrap_module                 # flatten the module body
    → pack_module                 # (if pack_body and output text/pyc) launcher + decoy + attest
    → _insert_version_guard       # (if require_min_python, uncompressed text)
    → emit                        # finalize names + render to text / pyc / ast
    → outer_compress              # (if compress_output) zlib + rolling-XOR + b85 bootstrap
```

The decoy (when `pack_decoy`) is obfuscated through the **same** pipeline (`_obfuscate_decoy`) so a
decrypted decoy is structurally indistinguishable from the real body.

`obf_project(*, root, out, entry, protect, options, import_hook, shared_oracle_decouple)`:

```
classify_files(root, entry, protect)   # → {rel_path → Role}
    ↓ shared-runtime mode?  (attest + pack_body + key_from_cff + text/pyc + ≥1 protected file)
    Yes → project_s_correct(options)   # one seed-derived selector shared by all files
          for each PROTECT file:
              _MODULE_PIPELINE.run → wrap_module
              build_satellite(tree, …) # stub + encrypted blob (s_correct = f(seed), no ordering dependency)
              → emit stub to <rel>.pyc  (or register in entry's import-hook registry)
          obf_module(entry_src, …, publish_runtime=True,
                     shared_oracle_decouple=…, runtime_registry=…)
                       # entry launcher additionally publishes shared dec + oracle into builtins
    No  → obf_module(each protected/entry file)   # self-contained single-module fallback
    for each PLAINTEXT file: shutil.copyfile verbatim
```

---

## The pass pipeline

`_FUNC_PIPELINE` and `_MODULE_PIPELINE` (identical order, defined in `__init__.py`) run these passes;
each enforces a default-deny node allowlist (`gate.py`) before transforming:

1. **`PrecompilePass`** — evaluate `precompile(expr)` / `precompile_arg(key[, dflt])` markers at build time and replace each call with the resulting constant. Runs **first** so folded constants then flow through all downstream literal-obfuscation passes. Marker resolution runs in an isolated subprocess for `precompile` expressions (so module-level code is exec'd safely); standalone `precompile_arg` with a literal key/default resolves in-process. Strips the marker imports after folding.
2. **`LocalCallPass`** — handle `@local_call` (inline/rename marked helpers, strip the marker import).
3. **`DictIndirectPass`** — route internal-function references through a per-scope `_D[key]` dict (`dict_indirect`).
4. **`NormalizePass`** — desugar `match` → if-chains; optional `return_var` rewrite (structural patterns fail-loud).
5. **`CmpHidePass`** — hide integer `==`/`!=` constants behind a bijective digest (`hide_compares`).
6. **`LocalRenamePass`** — rename user params/locals/comprehension targets to fresh names (always on).
7. **`StackCallPass`** (main phase) — route eligible call args through a hidden `threading.local` stack (`stack_calls`/`hide_external_args`).
8. **`SlotVarPass`** — map safe locals to `_slots[i]` (`slot_vars`).
9. **`NameVaultPass`** — route builtins + simple imports through a per-module vault (`name_vault`/`name_vault_attrs`).
10. **`ArchivePass`** — pool all literals into one encrypted blob + `_get` accessor (`const_archive`).
11. **`DataObfPass`** — pow/RSA-style codec for `str`/`bytes` literals (`obf_strings`).
12. **`StackCallPass`** (`phase="post_vault"`) — second, targeted arg-hiding pass over the archive `_get(...)` accessor call sites only.
13. **`FlattenPass`** — control-flow flatten every function via `cfg.flatten_function`, threading all feature RNGs/flags.

After the pipeline, `obf_module` runs `wrap_module` (flatten the module body), then (for text/pyc with
`pack_body`) `pack_module`, then `emit`.

---

## Root package

### `__init__.py`
- **Role:** Public API and orchestration. Defines the pipelines and wires `pipeline → wrap_module →
  pack_module → emit → outer_compress`, with fail-loud precondition checks.
- **Provides:** `obf_func`, `obf_module`, `obf_project` (entry points); re-exports
  `ObfOptions`/`ModuleObfOptions`/`OutputFormat`/`UnsupportedPolicy`, `local_call`, the
  analyze/visualizer functions; `cache_tag()`, `sourceless_pyc_name(module, *, tagged=False)`,
  `MIN_SUPPORTED_PYTHON`; internal `_FUNC_PIPELINE`/`_MODULE_PIPELINE`, `_obfuscate_decoy`,
  `_warn_docstrings`, `_warn_version_lock`, `_version_guard_src`, `_insert_version_guard`.
- **Interacts with:** imports every pass; the precondition checks guard `attest` / `body_cohash`;
  re-exports `obf_project` from `protect.project`.

### `options.py`
- **Role:** All configuration as dataclasses; the single source of truth for flags + defaults.
- **Provides:** `ObfOptions`, `ModuleObfOptions`, `OutputFormat`, `UnsupportedPolicy`,
  `_PROTECT_PRESETS`, `_apply_protect_level` (expands `protect_level` in `__post_init__`). See
  [`OPTIONS.md`](OPTIONS.md) for the per-flag reference.
- **Interacts with:** read throughout `cff` and `protect`.

### `packer.py`
- **Role:** Back-compat shim — the protection layer lives in `protect/`; this keeps the historic
  `pyobfuscator.packer` import surface working.
- **Provides:** re-exports `pack_module` and cipher primitives (`_ks_xor`, `_kdf`, `_fold`, `_MASK`,
  `_TEMP_KEY`) from `protect`.

---

## `cff/` — control-flow-flattening engine

### `cff/cfg.py`
- **Role:** The flattener. Lowers structured statements into basic blocks, renders them into a
  `while True` dispatcher, then applies the full hardening suite in place.
- **Provides:** `Block` + terminator dataclasses (`Goto`, `CondGoto`, `Ret`, `RaiseTerm`,
  `HandlerDispatch`, `SubExit`, `PopK`); `Lowerer` (statement → blocks); `desugar_with`; `build_blocks`;
  the entry points **`flatten_function`** and **`flatten_module_body`**; `_render` (blocks → dispatcher,
  attaches `_pyobf_scopemap`); and the post-render transforms `harden_states`, `dedup_blocks`,
  `key_consts`, `inject_attest`, `inflate_attest_blocks`, `inject_bogus`, `state_delta_transform`,
  `inject_opaque`, `dispatch_tree_transform`, `inject_junk_blocks`, `split_blocks`. Post-render order:
  `_render → dedup → harden → key_consts → inject_attest → inject_bogus → state_delta → inject_opaque →
  dispatch_tree`.
- **Interacts with:** uses `names.Namer`, `diagnostics`; lazily uses `attest` inside `inject_attest`.
  Called by `module_wrap` and `FlattenPass`.

### `cff/module_wrap.py`
- **Role:** Flatten the module-level body into a module dispatcher, keeping the docstring and
  `from __future__` imports first; coordinates module-level attestation + cohash def emission.
- **Provides:** **`wrap_module(tree, options)`**; preamble predicates `_is_docstring`/`_is_future`.
- **Interacts with:** calls `cfg.flatten_module_body`; records attest metadata on the tree; does not
  import `protect`.

### `cff/attest.py`
- **Role:** Build- and run-time attestation primitives: the oracle hash, seed-derived names/constants,
  oracle-gated-goto AST factories, the decoy oracle fallback, and the body self-cohash machinery.
- **Provides:** `mix(s,k,m)` (the oracle; also imported by `protect/core.py`), `oracle_name(seed)`,
  `MAGIC(seed)`, `ATTEST_MIN_GATES`, `name_to_charcode_expr`, `make_setdefault_binding`,
  `make_oracle_goto_absolute`/`make_oracle_goto_relative`, and cohash helpers `cohash_names`,
  `cohash_build_hash`, `make_cohash_guard_def`, `make_cohash_hashfn_def`, `make_cohash_binding`.
- **Interacts with:** imported by `cfg.inject_attest`, `module_wrap`, and `protect/core.py`. **Must not
  import `protect`.**

### `cff/lambdalift.py`
- **Role:** Replace every liftable `ast.Lambda` (including those generated by attest/anti-trace stages)
  with a named `def`, removing lambda tells.
- **Provides:** **`lift_lambdas(tree, namer)`** (fixpoint, closure-safe); helpers `_lift_one`, `_do_lift`,
  `_parent_map`, `_in_comprehension`, `_enclosing_stmt`.
- **Interacts with:** runs late (in `emit` and before body serialization in `core`); calls
  `localrename.rename_simple_helper_locals` on each lifted def.

### `cff/rename.py`
- **Role:** Final deterministic rename: every monotonic temp name (`_pyobf_g<n>`) → a seeded-random
  uniform `_pyobf_<hex>`, giving byte-identical output for the same input + seed.
- **Provides:** **`finalize_names(tree, seed, *, out_map=None, ns_salt=0)`**; internal `_Rewriter`.
- **Interacts with:** reads `names._GEN_ISSUED`; `ns_salt` keeps body / launcher / decoy namespaces
  disjoint; never touches the double-underscore attest names.

### `cff/names.py`
- **Role:** Process-global, collision-free name factory + name collection; the source of truth for
  issued temp names and their provenance (for the sourcemap).
- **Provides:** **`Namer`** (`fresh(hint, *, orig, scope, kind)`), `collect_names(node)`, `name_meta`,
  and the process-global `_GEN_COUNTER`/`_GEN_ISSUED`/`_GEN_META`.
- **Interacts with:** imported by virtually every `cff` module; `_GEN_ISSUED` is the cross-pass
  uniqueness contract.

### `cff/emit.py`
- **Role:** Final output stage — lambda-lift + finalize names, optional sourcemap, then render to AST /
  text / `.pyc`.
- **Provides:** **`emit(tree, options, *, sourcemap_out, layer, source, artifact)`**;
  `normalize_locations`; `_to_pyc(code, source_bytes)` (PEP-552 hash-based, unchecked, sourceless `.pyc`).
- **Interacts with:** calls `lambdalift.lift_lambdas`, `rename.finalize_names`, `sourcemap.build_sourcemap`.

### `cff/gate.py`
- **Role:** Default-deny allowlist gate — rejects any AST node a pass does not explicitly permit.
- **Provides:** `STRUCTURAL_NODES`, `SupportSet` (`.permits`), `GuardVisitor`, `collect_diagnostics`,
  **`enforce(tree, support, policy)`**.
- **Interacts with:** uses `diagnostics`; called by `Pipeline` before each pass's `transform`.

### `cff/diagnostics.py`
- **Role:** Shared error value types.
- **Provides:** `Severity`, `Diagnostic` (`.format()`), `UnsupportedConstructError`.
- **Interacts with:** no intra-package imports; consumed by `gate` and passes.

### `cff/marker.py`
- **Role:** Build-time marker functions (identity / default at runtime; recognized + acted on by the engine).
- **Provides:** `local_call(fn)` (identity decorator); `precompile(x)` (returns `x`); `precompile_arg(key, default=None)` (returns `default`). All three are exported from the top-level `pyobfuscator` package.
- **Interacts with:** `local_call` is acted on by `LocalCallPass`; `precompile`/`precompile_arg` are acted on by `PrecompilePass`.

### `cff/directives.py`
- **Role:** Parse `# pyobf:` inline source directives and bind them to the nearest `def`/`class`.
- **Provides:** `PREFIX`, `Directive`, `extract_directives(src)`, `map_to_defs(tree, directives)`.
- **Interacts with:** pure stdlib (`ast`, `tokenize`); consumed by passes needing per-unit opt-in/out.

### `cff/analyze.py`
- **Role:** Debug visualizers — build a JSON model of the pipeline and render standalone HTML.
- **Provides:** **`build_model`/`analyze_html`** (CFF view: per-scope CFG + per-pass source timeline),
  **`build_protect_model`/`protect_html`** (packer shell: layer/size breakdown + region-annotated
  launcher), `build_pass_timeline`, `SCHEMA`.
- **Interacts with:** uses `cfg`, `names`, `rename`, `gate`, `module_wrap`; renders the `viz/` assets;
  optionally hooks `protect.core` via the `_assemble_launcher` seam.

### `cff/sourcemap.py`
- **Role:** Assemble a JSON deobfuscation map from `finalize_names`' `out_map` + per-scope `_pyobf_scopemap`.
- **Provides:** `FORMAT`, **`build_sourcemap(...)`**, `dump_sourcemap(d, path)`.
- **Interacts with:** uses `names.name_meta`; called from `emit` when `emit_sourcemap` is set. **Never
  embedded in the artifact.**

### `cff/varstore.py`
- **Role:** Abstraction for variable read/write in the dispatcher (extension point for alternative
  storage strategies).
- **Provides:** `VarStore` (Protocol), `IdentityVarStore`.
- **Interacts with:** the interface `SlotVarPass` conceptually implements.

### `cff/__init__.py`
- **Role:** Package marker (docstring only).

### `cff/_runtime/__init__.py`
- **Role:** Empty package marker (reserved for runtime-support code).

### `cff/viz/` (package data, not Python)
- `analyze.js` / `analyze.css` — front-end for `analyze_html`.
- `protect.js` / `protect.css` — front-end for `protect_html`.
- Shipped via `pyproject.toml` `package-data`.

---

## `cff/passes/` — pipeline passes

### `passes/base.py`
- **Role:** Pass framework: the `Pass` protocol, the `Pipeline` runner (`enforce` then `transform` per
  pass), and a registry.
- **Provides:** `Pass` (Protocol), **`Pipeline`** (`run(tree, options)`), `register`, `get`, `all_passes`.

### `passes/precompile.py`
- **Role:** Build-time partial evaluation of `precompile` / `precompile_arg` markers. Runs **first** in the pipeline. For each outermost marker call it computes a constant at build time and replaces the call with that constant; the downstream literal-obfuscation passes then encrypt it.
- **Provides:** `PrecompilePass`; `_build_marker_resolver` (alias-aware marker detection from `from pyobfuscator import ...` and `import pyobfuscator` forms); `_Collect` (outermost marker-call collector, does not descend into nested marker args); `_Replace` (AST node replacer); `_strip_marker_imports` (removes the now-folded marker names from `from pyobfuscator import ...`); `_literal_node` (validates and parses a repr string); `_run_subprocess` (isolated-subprocess evaluation driver, JSON in/out); `_inproc_arg` (fast in-process resolution for standalone `precompile_arg` with literal key/default).
- **Interacts with:** must run before `LocalCallPass` and all literal-obfuscation passes; reads `options.precompile_args`; uses a subprocess (`subprocess.run`) to exec the module source and eval marker expressions in isolation (30 s timeout). Tolerates pre-normalization `match` nodes in `supports()`.

### `passes/localcall.py`
- **Role:** Handle `@local_call` helpers — inline at a single call site (alpha-renamed) or rename to an
  opaque fresh name; strip the marker decorator + dead import.
- **Provides:** `LocalCallPass`; helpers `_collect_marked`, `_AlphaRenamer`, `_WholeTreeRenamer`,
  `_resolve_positional`, `_remove_dead_marker_import`.
- **Interacts with:** runs second (after `PrecompilePass`); tolerates pre-normalization `match` nodes in `supports()`.

### `passes/dictindirect.py`
- **Role:** Route internal-function (and const-like global) references through a per-scope `_D[key]`
  dict (`dict_indirect`).
- **Provides:** `DictIndirectPass`; `_build_scope_tree`, `_collect_eligible_globals`, `_DictRewriter`.
- **Interacts with:** runs before `StackCallPass` so its helper infra is never indirected.

### `passes/normalize.py`
- **Role:** Desugar `match` → `if`/`elif` chains; optional `return_var` rewrite.
- **Provides:** `NormalizePass`; `_MATCH_NODES`, `_MatchDesugar`, `_pattern` (value/singleton/capture/
  guard/or patterns), `_ReturnVar`.
- **Interacts with:** must run before passes that declare the post-normalization allowlist; structural
  match patterns (sequence/mapping/class/star) fail-loud.

### `passes/stackcall.py`
- **Role:** Route call arguments through a hidden `threading.local` push/pop/invoke stack; two phases
  (`"main"` for eligible internal/bare-external calls, `"post_vault"` for marked accessor call sites).
- **Provides:** `StackCallPass(phase=...)`; `_eligible`, `_build_preamble`, `_Rewriter`, `_StmtSplitter`,
  `_is_routable_marked_call`, `_PostVaultRewriter`.
- **Interacts with:** main phase after `NormalizePass`; post-vault phase after `DataObfPass`; consumes
  `_pyobf_stackroute` markers set by `ArchivePass`/`NameVaultPass`.

### `passes/slotvar.py`
- **Role:** Map safe locals to `_slots[i]` (`slot_vars`).
- **Provides:** `SlotVarPass`; `_analyze` (slottable-name analysis), `_Rewriter`, `_slot_function`.
- **Interacts with:** runs after `NormalizePass`; no ordering dependency on stack/data passes.

### `passes/dataobf.py`
- **Role:** Encrypt `str`/`bytes` literals with a pow/RSA-style chunk codec + `_dec` helper (`obf_strings`).
- **Provides:** `DataObfPass`; `_rsa_params`, `_gen_prime`/`_is_prime` (Miller-Rabin), `_chunks_expr`,
  `_str_expr`/`_bytes_expr`, `_collect_skip`, `_Rewriter`, `_build_dec_helper`.
- **Interacts with:** `_rsa_params`/`_collect_skip` are reused by `ArchivePass`; injects its helper after
  the rewrite to avoid bootstrap recursion.

### `passes/flatten.py`
- **Role:** Drive control-flow flattening across every function/method via `cfg.flatten_function`.
- **Provides:** `FlattenPass`; **`S1_ALLOWED`** (the function-body node allowlist shared by downstream
  passes' `supports()`); `_flatten_scope`, `_flatten`, `_reject_finally`.
- **Interacts with:** the last pipeline pass; threads every feature RNG/flag (incl. the attestation
  requests) into `flatten_function`.

### `passes/archive.py`
- **Role:** Pool all eligible literals into one layered-encrypted blob + a `_get(off,sz,c,cast)` accessor
  (`const_archive`).
- **Provides:** `ArchivePass`; `_Collector`, `_eligible_value`, `_serialize`/`_deserialize`,
  `_build_archive`, `_emit_runtime`, `_RUNTIME_TMPL` (must mirror `protect/cipher.py` `_ks_xor`/`_kdf`).
- **Interacts with:** runs after `NameVaultPass` (honors `_pyobf_no_archive`); marks `_get(...)` calls
  `_pyobf_stackroute` for the post-vault stack pass; reuses `dataobf._rsa_params`/`_collect_skip`.

### `passes/cmphide.py`
- **Role:** Hide integer `==`/`!=` constants behind `splitmix64(zigzag)` digests + a `_h(x)` helper
  (`hide_compares`).
- **Provides:** `CmpHidePass`; `_mix_zz` (build-side bijection, must match the emitted `_h`), `_eligible`,
  `_HELPER_TMPL`, `_Rw`.
- **Interacts with:** runs before `FlattenPass` so it never touches dispatcher `state == k` comparisons.

### `passes/localrename.py`
- **Role:** Rename user params/locals/comprehension targets to fresh names via two-phase scope analysis
  (always on).
- **Provides:** `LocalRenamePass`; **`rename_simple_helper_locals(tree, namer=None)`** (reused by helper-
  injecting sites: archive, lambdalift, stackcall, dataobf); `_build_scope_tree`, `_function_is_unsafe`,
  `_decide_renames`, `_Rewriter`.
- **Interacts with:** runs before `FlattenPass` for user code; skips functions using `locals`/`vars`/
  `exec`/`eval`/`global`/`nonlocal`/`**kwargs`; keeps `self`/`cls` and keyword-called params.

### `passes/namevault.py`
- **Role:** Route builtins + simple top-level imports (and, with `name_vault_attrs`, attribute access)
  through a per-module vault (`name_vault`).
- **Provides:** `NameVaultPass`; `_build_boot` (vault bootstrap), `_BuiltinCollector`, `_routable_imports`,
  `_key_const` (marks vault keys `_pyobf_no_archive`), `_Rw`, `_BUILTIN_NAMES`.
- **Interacts with:** runs before `ArchivePass` (so the vault's name strings get pooled); excludes
  `super`/dunders/shadowed/decorator-position names.

### `passes/__init__.py`
- **Role:** Empty package marker.

---

## `protect/` — Python-layer protection / packer

### `protect/__init__.py`
- **Role:** Public surface of the protection layer + the detector extension model.
- **Provides:** re-exports `pack_module` (entry point) and `Detector`, `register`, `DETECTORS`,
  `build_detection` (detector-plugin hook).

### `protect/cipher.py`
- **Role:** Pure-Python, import-free crypto primitives shared by the build side (encrypt) and the
  generated launcher (decrypt) — must be embeddable verbatim into emitted code.
- **Provides:** constants `_TEMP_KEY`, `_SALT_SEL`, `_SALT_KEY`, `_SALT_DECOY`, `_BI_MAGIC`, `_D_MAGIC`,
  `_P_MAGIC`; `_kdf` (splitmix64 KDF), `_fold`, `_ks_xor` (xorshift keystream XOR; self-inverse),
  `_hash_bytes` (FNV-1a).
- **Interacts with:** runtime mirrors of `_kdf`/`_ks_xor` live in `_templates.py` and must stay in sync.

### `protect/astutil.py`
- **Role:** AST-based codegen — instantiate launcher snippets from real-code templates (no string
  concatenation).
- **Provides:** `emit_def`, `emit_body`, `emit_expr` (template instantiation); `xor_chain`, `add_chain`,
  `name`, `mul_const`, `import_stmt`; `resolve_magic` (wire a user handler's `M.<NAME>` to launcher vars);
  internal `_Subst`.
- **Interacts with:** parses `_templates.py` at import; used throughout `core` and `detectors`.

### `protect/templates.py`
- **Role:** Non-codegen packer helpers: format resolution, body/decoy serialization (with zlib compression
  before encryption), and the default decoy.
- **Provides:** `_DEFAULT_DECOY`, `_resolve_format`, `_body_bytes`, `_decoy_bytes`.

### `protect/_templates.py`
- **Role:** Library of launcher code **snippets written as real Python functions** (`t_*`), parsed once by
  `astutil` then instantiated (placeholders renamed/substituted) and spliced — never executed directly.
- **Provides:** cipher runtime (`t_ks`, `t_kdf`), key-fold (`t_seed`, `t_step`), builtin-integrity
  (`t_bi_bt`/`t_bi_rel`/`t_bi_abs`, `t_capture_globals`), blob embed (`t_assign_b85`), obfuscated import
  (`t_obf_import`), selectors + exec tails (`t_single_*`, `t_decoy_*`), audit tripwire (`t_audit_*`),
  detection terms (`t_detect_*`), cohash (`t_hashfn`/`t_guard`/`t_cohash`), and neuter (`t_neuter_*`).
- **Interacts with:** UPPERCASE identifiers are intentional placeholders; functions are never called.

### `protect/detectors.py`
- **Role:** Detector plugin framework — each detector contributes a term (`0` clean, `> 0` triggered)
  that folds into the key selector under `key_binds_env`.
- **Provides:** `Detector` (base/extension hook: `flag`, `needs_sys`, `entry_only`, `magic_name`,
  `key_safe`, `term(ctx)`), `register` (decorator), `DETECTORS`, **`build_detection(options, namer,
  poison_cell)`**; built-ins `TraceDetector`, `AuditDetector`, `ToolsDetector`, `EnvDetector`,
  `StackDetector` (entry-only).
- **Interacts with:** uses `astutil`; `_Ctx.poison_cell` is supplied by `core`.

### `protect/outerpack.py`
- **Role:** The `compress_output` wrap — zlib + rolling-XOR + b85 bootstrap layers (a static-extraction
  speed bump + honeypot for exec-hooking peelers).
- **Provides:** **`outer_compress(result, to_pyc, *, rounds, decoy, rng)`** (entry point);
  `outer_compress_text`, `outer_compress_pyc`, `decoy_head` (no-op layer, byte-shape-identical to a real
  round), `_layer_src`, `_xor_encrypt`, `_b85_literal_lines`.
- **Interacts with:** called by `obf_module` after `emit`; depends on no other `protect` module.

### `protect/core.py`
- **Role:** Launcher assembly + flatten orchestration — the heart of the packer.
- **Provides:** **`pack_module(tree, options, *, sourcemap_out, decoy_tree)`** (entry point);
  `_assemble_launcher` (pre-flatten launcher + regions), `_flatten_launcher`, `_emit_neuter`, `_emit_bi`,
  `_emit_blob_assign`, `_single_tail`, `_patch_attest_markers`, `_build_oracle_install_stmts`,
  `_guard_cohash`, `_choose_bi`, `_inner_fname`, `_needs_audit_cell`; salts `_BODY_NS_SALT`,
  `_DECOY_NS_SALT` (keep body/decoy/launcher names disjoint); multi-module helpers
  **`project_s_correct(options)`** (seed-derived selector shared by all files in a project),
  **`build_satellite(tree, options, *, module_id, s_correct, magic, dec_name_str, decoy_tree)`**
  (encrypt a protected module into a stub + blob), and
  **`_build_runtime_publish_stmts(...)`** (generate the entry's builtins-publish statements for the
  shared `dec` function and oracle).
- **Interacts with:** imports `cipher`/`templates`/`detectors`/`astutil`/`_templates`; lazily uses
  `cff.names`, `cff.attest` (including `dec_name`), `cff.rename`, `cff.module_wrap`, and
  `_MODULE_PIPELINE`.

### `protect/project.py`
- **Role:** Project-level multi-module obfuscation orchestration. Drives the single-module packer
  across a source tree, implementing the **Kernel + Satellites** model: one entry module (the kernel)
  publishes a shared protection runtime into `builtins`; protected modules (satellites) ship as a
  small stub + encrypted blob that decrypt through that runtime; all other files are copied verbatim.
- **Provides:** **`obf_project(*, root, out, entry, protect, options, import_hook,
  shared_oracle_decouple)`** (main entry point, returns `{rel_path → role_str}` manifest);
  `classify_files(root, *, entry, protect)` (walks the source tree and assigns each `.py` file a
  `Role`); `Role` (enum: `ENTRY` / `PROTECT` / `PLAINTEXT`); internal helpers `_walk_py`, `_module_id`,
  `_out_rel`, `_emit_to`.
- **Interacts with:** calls `obf_module` (from `__init__`) for entry and self-contained fallback
  builds; uses `_MODULE_PIPELINE` + `wrap_module` + `emit` directly for satellite builds; relies on
  `protect.core.project_s_correct`, `protect.core.build_satellite`, and
  `protect.core._build_runtime_publish_stmts` (via the `publish_runtime` path in `pack_module`);
  reads `cff.attest.MAGIC` and `cff.attest.dec_name` (the seed-derived name for the shared decrypt
  function published into `builtins`).

---

## Extension points

- **Add an obfuscation pass:** implement the `Pass` protocol (`name`, `supports() -> SupportSet`,
  `transform(tree, options)`) in `cff/passes/`, gate it on a new `options.py` flag, and insert it into
  `_FUNC_PIPELINE`/`_MODULE_PIPELINE` in `__init__.py`. Use `Namer.fresh()` for all generated names.
- **Add a detector:** subclass `Detector` in `protect/detectors.py`, decorate with `@register`, set
  `flag`/`magic_name`, and return a term from `term(ctx)` (0 clean, > 0 triggered). It folds into the key
  automatically under `key_binds_env`; route FP-prone signals to `handler_src` instead (`key_safe=False`).
- **Add a launcher snippet:** add a `t_*` function to `protect/_templates.py` (real Python, UPPERCASE
  placeholders) and instantiate it with `astutil.emit_def`/`emit_body`/`emit_expr` in `core.py`.
- **Add an option:** add a field to `ObfOptions`/`ModuleObfOptions` in `options.py` with a concise
  docstring-comment, thread it where consumed, and document it in [`OPTIONS.md`](OPTIONS.md).

---

## Tests

`tests/` holds ~2,255 differential + structural tests. Equivalence tests compile both the original and
the obfuscated program and compare return value / exception / stdout / argument mutation across seeds;
structural tests assert specific transforms and reject regressions. Wrong-path / dump-replay checks run
in killable subprocesses (a wrong dispatcher state can busy-loop). Run with
`.venv/Scripts/python -m pytest -q`.
