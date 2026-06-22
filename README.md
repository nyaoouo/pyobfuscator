# pyobfuscator

A source-level **Python control-flow-flattening obfuscator** with an optional, layered
**Python-layer software-protection stack** (compressing + encrypting packer → control-flow-derived key
→ branchless decoy → anti-trace honeypot → obfuscated imports → cff↔python runtime attestation).

> 中文版: [`README.chs.md`](README.chs.md) · Options: [`docs/OPTIONS.md`](docs/OPTIONS.md) ·
> Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

Every transformation is **differential-equivalence-gated against CPython**: on the untampered path the
obfuscated/packed program is behaviour-identical to the original (return value, exception type+message,
stdout, argument mutation, across seeds). It is **fail-loud**: a default-deny allowlist rejects any
construct it cannot provably preserve. Output is **deterministic** for a given source + seed + flags.

> **Honest threat model.** Pure-Python protection is **obfuscation-grade, not crypto-grade**: the
> decryptor must exist in visible launcher code, so a determined *dynamic* attacker (debugger,
> `exec`/`compile` hook, or a patched interpreter) who dumps memory at the *live* `exec(body)` still
> wins. Runtime **attestation** does close the *offline* variant — a body blob dumped and replayed
> *without* the launcher's oracle diverges — but the live in-process dump remains the job of a native /
> driver layer (out of scope here). This layer raises the bar against static reading, automated
> extraction (e.g. `sys.settrace`-based codec ripping), debuggers, coverage tools, and AI
> reverse-engineering — and turns detection into a *honeypot*.

---

## Requirements

- Python **3.11+** (the obfuscator and its output). The full TEXT stack is exercised on 3.12 and 3.14.
- No runtime dependencies. `pytest` for the test suite (`pip install -e .[dev]`).

## Quick start

```python
from pyobfuscator import obf_module, ModuleObfOptions

src = "import sys\nFLAG = 'secret'\ndef ok(k):\n    return k == FLAG\n"

# 1) Obfuscated source (portable across Python versions)
text = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1))

# 2) Sourceless .pyc bytes (compact; version-locked to the build interpreter)
pyc = obf_module(src, ModuleObfOptions(output="pyc", seed=1, min_blocks=1))

# 3) Full protection: encrypted body + control-flow key + decoy + attestation
hardened = obf_module(src, ModuleObfOptions(
    output="text", seed=1,
    pack_body=True, key_from_cff=True, pack_decoy=True,
    integrity_selfcheck=True, attest=True, obf_imports=True,
))
```

- `obf_module(src, opts)` returns obfuscated **source** (`output="text"`), **`.pyc`** bytes
  (`output="pyc"`), or an **`ast.Module`** (`output="ast"`). `obf_func` does the same for a single
  function.
- A `output="pyc"` artifact is a PEP-552 hash-based, unchecked, **sourceless** `.pyc`: written as
  `<module>.pyc` it is both runnable (`python <module>.pyc`) and importable (`import <module>`). Use the
  `cache_tag()` / `sourceless_pyc_name(module)` helpers for naming.

### `protect_level` presets

Instead of setting protection flags individually:

- `"off"` (default) — use individual flags.
- `"light"` — packer + control-flow key + builtin integrity + decoy + obfuscated imports (still debuggable).
- `"full"` — `light` + anti-trace honeypot (debugger / `settrace` / coverage at load → decoy).

```python
obf_module(src, ModuleObfOptions(output="pyc", seed=1, protect_level="full"))
```

See **[`docs/OPTIONS.md`](docs/OPTIONS.md)** for every option's effect, impact, and limitations.

### Multi-module projects

`obf_project` obfuscates an entire source tree at once: one entry module publishes a shared
decryption runtime into `builtins`; each protected module ships as a lightweight stub + encrypted
blob that runs through it. Plaintext files are copied verbatim.

```python
from pyobfuscator import obf_project, ModuleObfOptions

manifest = obf_project(
    root="src/myapp",
    out="dist/myapp",
    entry="main.py",                          # publishes the shared runtime
    protect=["app/secret.py", "app/logic.py"],# obfuscated as satellites
    # app/__init__.py is not listed → copied plaintext
    options=ModuleObfOptions(
        output="pyc", seed=42,
        pack_body=True, key_from_cff=True,
        attest=True, pack_decoy=True,
    ),
)
# Run: python dist/myapp/main.pyc
# Import works too: import app.secret   (loads app/secret.pyc transparently)
```

A runnable demo is at `sample/project_test/` (build with `build_project.py`). See
**[`docs/OPTIONS.md`](docs/OPTIONS.md)** (§12b) for the full parameter reference including
`import_hook` and `shared_oracle_decouple`.

### Build-time constants (`precompile` / `precompile_arg`)

Two markers let you fold a computed value into the obfuscated output as an encrypted constant at build
time. `precompile` works both as `precompile(expr)` and as a `@precompile` function decorator. At
runtime they are no-ops (expression forms return their value; the decorator calls the thunk), so
un-obfuscated source still runs and yields the same constant.

```python
from pyobfuscator import precompile, precompile_arg, obf_module, ModuleObfOptions

def _scramble(text):
    return tuple((ord(c) + i * 3) % 256 for i, c in enumerate(text))

def license_ok(key):
    # At build: _scramble("PROD-KEY") is evaluated; the tuple is folded in and encrypted.
    # Neither the key literal nor the scramble algorithm appears on the constant side in the output.
    return _scramble(key) == precompile(_scramble(precompile_arg("LICENSE_KEY")))

out = obf_module(open("secret.py").read(), ModuleObfOptions(
    precompile_args={"LICENSE_KEY": "PROD-KEY-1234"},
    const_archive=True,
))
```

- **`precompile(expr)`** — evaluates `expr` at build (in an isolated subprocess) and replaces the call
  with the resulting constant. `expr` must be module-scope-evaluable (not a function parameter).
- **`@precompile`** (decorator) — on a module-level zero-argument function: runs the thunk at build and
  replaces the `def` with `NAME = <const>`, so a thunk (loops/locals) can compute the constant. The
  decorator calls the thunk at runtime too, so the un-obfuscated name holds the same value.
- **`precompile_arg("KEY")`** — required: replaced with `precompile_args["KEY"]`; build fails loudly if
  absent. **`precompile_arg("KEY", default)`** — optional: uses `default` when `"KEY"` is absent.
  The key lives only in the build script; it never appears in the source.
- **`ObfOptions.precompile_args`** — dict passed to `obf_func` / `obf_module` / `obf_project` with
  the injected values.

The folded constant then flows through `const_archive` / `obf_ints` / `obf_strings` and gets
encrypted. See **[`docs/OPTIONS.md`](docs/OPTIONS.md)** (§0) for the full reference including
fail-loud conditions and determinism notes.

---

## What's in the box

**`cff/` — control-flow flattening engine.** Each function / method / module body becomes a `while True`
state-machine dispatcher. Supported: functions, nested functions + closures, class methods (MRO / `super`
/ `property` / `classmethod` preserved), module bodies, `try/except/else`, `try/finally`, `with`,
comprehensions + lambdas, `match` (→ if-chains), walrus, `assert`. Hardening: random state ids, opaque
predicate families, bogus blocks (cloned from real code), state-keyed constants, a constant archive,
a builtin/import name vault, string/int codecs, call-arg hiding, slot variables, BST dispatch, and more.
`yield`/generators/`async` are not supported (rejected fail-loud).

**`protect/` — Python-layer protection.** `pack_module` replaces an obfuscated module with a launcher
that carries the body as a compressed + encrypted blob and reconstructs it at runtime:

- **Packer + control-flow key** — the decryption key is derived from the launcher's own correct dispatch
  path, so tampering with the control flow yields the wrong key.
- **Branchless decoy** — real and decoy share one ciphertext; selection is a `dict.get` + arithmetic with
  no patchable boolean. Tamper/detection cleanly runs a believable decoy.
- **Integrity** — builtin-identity and guard-`co_code` hashes fold into the key (monkeypatch / bytecode
  patch → decoy); on PYC the body can self-verify its own `co_code`.
- **Detection → decoy** — `settrace`/profiler, debugger/coverage modules, replaced breakpointhook /
  inspect mode, or a foreign `exec`/`import` of the entry fold into the key (honeypot, opt-in).
- **Runtime attestation** — the launcher installs an oracle into the body globals; gated dispatcher
  transitions need it, so a body dumped without the launcher diverges (defeats offline dump-and-replay).
- **Obfuscated imports**, **compressed output** (zlib + rolling-XOR + b85 bootstrap), and a **min-version
  guard** round out the distribution wrap.

For the full module-by-module map and extension points, see
**[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## Repository layout

```
pyobfuscator/
├── src/pyobfuscator/      # the package: cff/ (engine) + protect/ (packer) + root API
├── tests/                 # ~2,255 differential + structural tests
├── docs/
│   ├── OPTIONS.md         # per-option reference (effect / impact / limitations)
│   └── ARCHITECTURE.md    # module-by-module map + extension points
├── README.md  /  README.chs.md
└── pyproject.toml
```

## Tests

```bash
.venv/Scripts/python -m pytest -q        # Windows venv layout (use bin/ on POSIX)
```

The suite is differential (compile original vs obfuscated, compare behaviour across seeds) and
structural (assert specific transforms). Wrong-path / dump-replay checks run in killable subprocesses,
since a wrong dispatcher state can busy-loop.
