# PyInstaller distribution

PyInstaller analyzes imports before the encrypted module body runs. It cannot see imports in that body. `write_pyinstaller_hook` generates a custom **runtime hook** from the original source tree. Its import statements live in a function that is never called: PyInstaller collects the modules, but the hook does not import them early or leave a Python caller frame above the protected entry.

## Single-file entry

```python
from pathlib import Path
from pyobfuscator import ModuleObfOptions, obf_module, write_pyinstaller_hook

source = Path("src/main.py")
out = Path("build/obf")
out.mkdir(parents=True, exist_ok=True)
options = ModuleObfOptions(output="text", pack_format="source", seed=42,
                           protect_level="full", detect_stack=True)
(out / "main.py").write_text(obf_module(source.read_text(encoding="utf-8"), options),
                             encoding="utf-8")
write_pyinstaller_hook(source, out / "pyi_rth_pyobfuscator.py")
# Add extra_imports=["my_dynamic_plugin"] when an import name is computed at runtime.
```

Copy any unprotected local modules needed by `main.py` into `build/obf`, then build:

```text
python -m PyInstaller --onedir --paths build/obf --runtime-hook build/obf/pyi_rth_pyobfuscator.py build/obf/main.py
# Use --onefile instead of --onedir for a single executable.
```

`extra_imports` covers runtime-computed import names. The hook names Python modules; add independent data files or libraries with PyInstaller's `--add-data`, `--add-binary`, or spec options. Keep the original source tree off PyInstaller's search path when it contains code you intend to protect. Module names listed in the hook can be recovered from the bundle even when `obf_imports` or `name_vault` hides them in the protected source.

PyInstaller compiles Python modules to bytecode inside the bundle. That does not mean a sourceless `.pyc` works as its **entry script**: with PyInstaller 6.21.0, passing this project's protected `.pyc` directly to `Analysis` failed with `UnicodeDecodeError` because script analysis decoded it as source. The same `.pyc` ran directly under CPython. For a precompiled protected body in a frozen app, keep `output="text"` for the entry and set `pack_format="bytecode"`. This locks the artifact to the build Python version and also permits `body_cohash=True` with `attest=True`. The TEXT launcher is only the outer entry; its encrypted body holds build-compiled bytecode.

## Multi-module project

```python
from pyobfuscator import ModuleObfOptions, obf_project, write_pyinstaller_hook

options = ModuleObfOptions(output="text", pack_format="source", seed=42,
                           pack_body=True, key_from_cff=True,
                           pack_decoy=True, attest=True, detect_stack=True,
                           key_binds_env=True)
manifest = obf_project(root="src/myapp", out="build/obf", entry="main.py",
                       protect=["app/secret.py"], options=options,
                       import_hook=True)
write_pyinstaller_hook("src/myapp", "build/pyi_rth_pyobfuscator.py",
                       manifest=manifest, import_hook=True)
```

Build `build/obf/main.py` with `--paths build/obf --runtime-hook build/pyi_rth_pyobfuscator.py`. Pass `import_hook=False` to both calls for per-module protected stubs. With `import_hook=True`, the generated hook omits embedded satellites from PyInstaller's import list while retaining their original code's dependencies. Do not place the original protected source tree on PyInstaller's search path or bundle it as data.

## Protection support

The statuses below are scoped to a **TEXT entry**, with source or bytecode body as noted. Frozen smoke tests used PyInstaller 6.21.0, Windows 11, Python 3.14.4. “Combined test” means the option was enabled in a real frozen bundle; it does not prove every input program or other platform. “Expected” means its transformation has no known frozen-specific dependency but was not individually exercised in a bundle.

| Strategy / options | PyInstaller support | Evidence or condition |
| --- | --- | --- |
| `obf_strings`, `obf_ints`, `hide_compares` | Combined test | Encoded literals and comparisons ran in `onedir`; string/int/default transforms also ran in `onefile`. |
| `const_archive`, `name_vault`, `name_vault_attrs` | Combined test | Launcher and body constant/name routing ran in both modes. |
| `shuffle_states`, `opaque_predicates`, `bogus_blocks`, `bogus_clone_ratio` | Combined test | Default CFF options were active in both modes. |
| `max_block_stmts`, `min_blocks`, `safe_mode` | Expected for non-default settings | These set build-time CFF boundaries; only defaults and `min_blocks=1` were frozen-tested. |
| `slot_vars`, `stack_calls`, `hide_external_args`, `split_calls` | Expected | Source-level rewrites; no separate frozen case yet. |
| `return_var`, `dedup`, `state_delta`, `dispatch_tree`, `junk_code`, `dict_indirect` | Expected | Dispatcher rewrites; no separate frozen case yet. |
| `precompile`, `precompile_arg`, `precompile_args`, `precompile_timeout` | Expected | Build-time only. Add imports to the hook only if the shipped code still needs them. |
| `strip_debug`, `on_unsupported`, `seed`, `emit_sourcemap` | Build-time or emission controls | `strip_debug` affects AST/PYC position metadata rather than the tested TEXT launcher. `on_unsupported` rejects unsupported constructs before packaging; seed and source map do not change frozen loading. |
| `pack_body`, `pack_format="source"` / `"bytecode"`, `key_from_cff` | Combined test | Both packed formats and the derived key ran in `onedir` and `onefile`. Bytecode format locks the body to the build Python version. |
| `integrity_selfcheck`, `builtin_checks`, `builtin_spot_count` | Combined test for defaults | Default builtin check and decoy selection ran in both modes; custom check lists were not tested. |
| `pack_decoy`, `decoy_src`, `decoy_obf_overrides` | Combined test for default decoy | Wrong-path behavior and custom decoys were not frozen-tested. |
| `obf_imports` | Combined test | Launcher dynamic imports were present; PyInstaller's base runtime supplied their standard-library modules in tested bundles. |
| `detect_trace`, `detect_tools`, `detect_env`, `key_binds_env` (`protect_level="full"`) | Combined test | Clean frozen launch selected the real body. Debuggers, coverage, and custom runtime hooks can deliberately select the decoy. |
| `protect_level="light"` / `"full"` | `full` combined test; `light` expected | `light` is a subset of `full` without environment detectors; it has no separate frozen case. |
| `detect_stack` | Combined test | Its signal was `0` and the real body ran in `onedir` and `onefile`, including two `compress_output` rounds. The hook returns before entry execution, leaving no caller frame. A Python `exec`/`runpy` wrapper is still a foreign entry and selects the decoy. |
| `attest`, `attest_density`, `attest_inflate`, `attest_target_blocks` | Combined test for defaults | Default attestation settings ran in both modes; custom density/targets were not separately frozen-tested. |
| `cohash_integrity` | Conditional, combined test | TEXT is tied to the build interpreter's bytecode version. Both frozen modes used that same interpreter; other Python versions require a rebuild. |
| `body_cohash` | Conditional, combined test | Use `attest=True`, `output="text"`, `pack_format="bytecode"`. Both frozen modes kept `STACKSIG 0` and ran the real body. Rebuild with each Python version. |
| `detect_audit`, `attest_runtime_bind`, `anti_trace_neuter` | Combined test | Clean launch worked in both modes. These opt-in process-wide defenses may interact with third-party runtime hooks; test the actual bundle. |
| `handler_src` | Combined test for a read-only stack signal | The diagnostic handler printed `STACKSIG 0` in both modes. Poisoning handlers need application-specific tests. |
| `anti_trace_neuter_honeypot` | Not frozen-tested | The aggressive response path needs application-specific tests. |
| `compress_output`, `compress_rounds` | Combined test | Two rounds ran in both modes; `detect_stack` accounted for both bootstrap frames. |
| `require_min_python` | Expected | TEXT-only guard runs before the compressed bootstrap; PyInstaller itself embeds the build interpreter. |
| `obf_project` with protected stubs | Frozen test | One entry, plaintext package/module, and protected satellite ran in `onedir` with source and bytecode bodies, including `body_cohash` for bytecode. |
| `obf_project(import_hook=True)` | Frozen test | Embedded satellite was omitted from collection; entry-installed finder served it in `onedir` with source and bytecode bodies. |
| `shared_oracle_decouple` | Not frozen-tested | Shared-runtime selector variant has no separate frozen case. |
| `emit_pyi`, `single_file_interface`, `exports`, `exports_from_all` | Build-time interface controls | Type stubs and export selection are not PyInstaller loading mechanisms; no frozen-specific check. |
| `output="pyc"` as entry | Direct entry rejected in tested PyInstaller | The `.pyc` itself works in CPython. PyInstaller's script analyzer raised `UnicodeDecodeError` on it; use a TEXT entry with an encrypted bytecode body for frozen distribution. |
| `output="ast"` as entry | Requires source emission | The API returns an AST, not a PyInstaller entry file; emit a `.py` entry before packaging. Not frozen-tested separately. |

For multi-file projects, the generated hook scans the entire original source tree. The matrix's single-entry combined tests do not imply every optional strategy was exercised in a protected satellite; the separate project tests cover protected stubs and embedded satellites, with source and bytecode bodies. Dynamically computed imports still need `extra_imports`.

These are Windows smoke results, not Linux/macOS certification. Build and test separately on each target OS. PyInstaller's executable includes the build interpreter and is platform-specific.

## Regression checks

```text
python -m pytest tests/test_pyinstaller.py -q
```

The integration cases need the optional `pyinstaller` extra (`pip install -e ".[dev,pyinstaller]"`); unit cases still run without it. PyInstaller runs and test temporary files need a writable build/temp directory.
