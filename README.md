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

## Demo

A worked end-to-end example (a small challenge built with the full obfuscation + protection stack, a
realistic decoy, and verification that an untraced run behaves normally while a traced/dumped run is
diverted to the decoy) lives in a separate build workflow outside the shipped package — the policy and
secrets (decoy, markers) belong in the build workflow, never in the library.

## Status

The obfuscation pipeline and the protection stack are complete and independently verified; the library
is on the `feat/implementation` branch (not yet merged to master). Out of scope here: native / driver
protection layers (the live in-process dump ceiling noted in the threat model).
