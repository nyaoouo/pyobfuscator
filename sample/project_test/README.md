# Multi-module project demo (`obf_project`)

A runnable demo of pyobfuscator's **project-level** mode: one entry module hosts a shared protection
runtime; protected modules ship as encrypted-blob stubs that decrypt through it; other modules stay
plaintext for the user to edit.

## Layout

```
src/
  main.py          # entry — its launcher installs the shared runtime (decrypt + oracle) into builtins
  app/__init__.py  # plaintext (package marker)
  app/secret.py    # PROTECTED — core licensed logic (the key literal + transform live only here)
  app/logic.py     # plaintext business logic; reverse-imports app.secret (user-editable)
build_project.py   # build + self-verification
dist/              # build output (git-ignored)
```

## Build + verify

```sh
../../.venv/Scripts/python build_project.py
```

This obfuscates `src/` into `dist/` via `obf_project(...)` with the full protection stack, then
verifies against the shipped tree:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | `python dist/main.py PYOBF-PRO-2026 hello` | `OK:OLLEH`; wrong key → `DENIED` |
| 2 | reverse import (`app/logic.py` imports the protected `app/secret`) | works (covered by #1) |
| 3 | **update only `secret`** — rebuild `secret` alone (same seed), keep the old entry | old entry runs the new satellite |
| 4 | **tamper the entry** (corrupt `dist/main.py`) | genuine output gone |
| 5 | **tamper a satellite** (corrupt `dist/app/secret.py`) | that module breaks |
| 6 | **traced load** (debugger / `sys.settrace` at start) | decoy (real output gone) |
| 7 | **foreign import** (`import app.secret` without the entry) | fails loud (entry-bound) |

## Run it yourself

```sh
python dist/main.py PYOBF-PRO-2026 hello   # -> OK:OLLEH
python dist/main.py wrong-key hello        # -> DENIED
```

Override the build-time license key from the CLI (CI/build injection — the key never appears in the
shipped source):

```sh
python build_project.py --key "MY-CI-SECRET-9931"
```

## Analyze output

After verification passes, the build writes self-contained HTML visualizations to `build/`
(git-ignored), one pair per obfuscated module:

| File | View |
|------|------|
| `build/main_analyze.html`, `build/secret_analyze.html` | CFF "mind map" — per-scope control-flow + per-pass source timeline (`analyze_html`) |
| `build/main_protect.html`, `build/secret_protect.html` | packer shell — serialize→zlib→encrypt→encode→launcher size layers + the assembled launcher (`protect_html`) |

These use the same options as the build, so `precompile` / `precompile_arg` fold identically. They are
debug aids only — the *injected* license key is never in the source, so it never appears in them (the
source view shows only the dev placeholder default).

## Notes

- **`@precompile` decorator** — `app/secret.py` computes its license digest with a `@precompile` thunk
  (`_LICENSE_DIGEST`), folded to a constant tuple at build (the key and the scramble both vanish).

- **Shared oracle / key** come from one `seed`, so the entry and every satellite agree
  (`s_correct = f(seed)`) and build independently — updating one satellite needs only that rebuild.
- **β binding** (default): tampering the shipped entry diverts every satellite to its decoy. Pass
  `shared_oracle_decouple=True` for α (satellites independent of entry runtime integrity).
- **Entry-bound**: importing a satellite without the entry having published the runtime fails loud
  (it is not meant to run on its own).
- For a single-file demo with the full CFF + protection showcase, see `../single_file/`.
