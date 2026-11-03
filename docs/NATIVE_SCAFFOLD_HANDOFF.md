# Native scaffold release handoff

Snapshot of `codex/native-scaffold` at `ba141cb` (2026-11-03), before the
publication cleanup. This is a release-facing status summary, not a development
tracker. For subsequent work, use the current project progress record and
implementation plans; do not resume a task from this snapshot or treat its
completion labels as newer evidence.

## What this branch contains

- A source-only C++ native SDK, backend operation boundary and Windows user-mode
  backend. Environment detection has registration and test fixtures, but no
  genuine production detector or TPM provider.
- A Clang/LLVM pass with explicit per-function CFF strategy selection and
  separate strategy implementations. The registered controls include baseline
  CFG flattening, normalizers, misleading transitions, and bounded runtime
  contribution sources. Unsupported shapes and lost required sites fail closed.
- An opt-in Windows demonstration that packages an already linked DLL with
  AES-GCM, performs pre-release checks, decrypts it, loads it through the
  Windows loader, and transfers an owned context into the payload. Its loader
  uses a temporary file. The encryption key material and release authority
  remain local to the demonstration.
- Typed archive storage, generated helpers, measured code subjects, reserved
  reference slots, independent owned observations, and selected mixed-source
  parent/child CFF routes. Bounded final PE checks and paired mutation tests
  exist for the selected profiles. The latest merged P112/P113 unit proves
  selected invoke and archive entry routes, not the whole call graph.

The documented, exercised native pipeline is Windows x64 with MSYS2 CLANG64,
matching LLVM tools, CMake/Ninja and Python. Source-only MSVC compatibility has
limited checks. Linux, macOS, kernel/HVCI and a general in-memory DLL loader are
not supported by an equivalent runtime/final-image acceptance suite. See
[native setup](../native/README.md), [recipes](NATIVE_RECIPES.md),
[bootstrap acceptance](NATIVE_BOOTSTRAP_ACCEPTANCE.md) and the
[D8 gap inventory](NATIVE_D8_GAP_INVENTORY.md) for scoped evidence.

## Open boundaries at this snapshot

- D5 Unit5b joint audit and D6/D7 closeout remain open. G3 local proofs cover
  selected builder-controlled inputs and routes; they do not prove all called
  body effects, arbitrary runtime memory, loaded-byte authenticity or full
  release authority. Final-manifest signing is not implemented.
- D7 request freshness, remaining archive decoder/cache and callback effects,
  and the full D8 support matrix, combined refusal cases, final artifact and
  cost acceptance remain open. Existing component tests do not close those
  stages.
- Device authorization, the Python bridge, genuine environment detection,
  function-level lazy decryption and cross-platform runtime backends remain
  future work. Runtime dumping and the temporary-file replacement window are
  outside this branch's demonstrated protection boundary.

The recorded P112/P113 joint option-on product passed its five focused
bound/retain/invoke/first-use/entry tests. The archive five-test suite passed
with serialized mutation testing, and the final Ninja rebuild reported no
work. These results apply to the recorded inputs and baseline revision; this
handoff does not claim a fresh release-wide build or D8 acceptance.

## Publication note

The development branch history includes local checkout/toolchain paths in
older documentation commits. Its current tree has portable examples. This
release snapshot is intended as a single commit based on `master`, without
the intermediate development history. Verify that ancestry before publishing.
