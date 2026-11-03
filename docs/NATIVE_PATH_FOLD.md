# Native path-fold arithmetic

The version1 finite-width primitive is a prerequisite for D5 path-bound release. It has a
portable C++ value model, an LLVM emitter and an independent Python build reference. The
opt-in registered `path-fold` component binds explicit whole/hybrid sites to actual CFF
state. The demo carries real initialization/environment/owned-support/pre-decrypt events,
then expands their actual runtime fold to reconstruct its transient AES key.
Optional [outer-decoy variants](NATIVE_DECOY.md) have four additional required owners and
separate invocation storage. They share the selected standard expansion implementation,
without reading or repairing the failed real fold.
The compiler marker interface is private and does not introduce a stable exported SDK ABI.
The [fixed release-record format and PE finalizer](NATIVE_RELEASE_RECORDS.md) are separate
components consumed by the main packer and runtime release.

## Defined arithmetic

The fold has eight unsigned32 lanes and ordered `(tag, word)` events. Each event captures
all eight old lanes before writing the next state. Addition and multiplication wrap modulo
2^32; rotations have defined counts. Tags and words feed distinct arithmetic terms, avoiding
the trivial cancellation caused by first XOR-combining a label and value into one input.
The canonical byte encoding is eight little-endian words,32 bytes, with version carried by
the containing format. There is no native-endian or pointer-based representation.

For a selected CFF site, the build computes
`encoded = normal_word XOR mix(expected_state XOR salt)`. Runtime emission computes
`encoded XOR mix(current_state XOR salt)`. Correct state recovers the normal word without
an equality test or embedding the raw expected state. Original marked sites retain source
accounting; this does not infer that all critical release paths cross those sites. The
bootstrap's four required event sites feed its pre-release key reconstruction.

## Registered sites and configuration

The private `path_fold/marker.hpp` declares init and step operations on an aligned eight-word
Storage reference. Seed, tag and normal word are fixed i32 descriptor values in version1.
This is not yet the general dynamic provider/source interface planned for later evidence.
Keep marker declarations in CFF input and compile the ordinary `marker.cpp` reference
separately when plain, unselected or disabled callers need it. Fully bound functions are
tested without linking that reference implementation. Missing ordinary providers fail at
linking; no implicit fallback definition is supplied by the plugin.

```json
{
  "schema_version": 1,
  "functions": {
    "critical": {
      "components": {"path-fold": "required"},
      "budgets": {"max_path_fold_sites": 32}
    }
  }
}
```

The component is off by default. Off keeps ordinary calls without coverage. Optional reports
unsupported sites while binding eligible ones; ordinary remaining calls need the reference
source. Required rejects unsupported, optimized-away, missing or zero eligible sites. The
per-function site budget defaults to256. Whole functions and normal-body sites in the existing
Windows GNU hybrid-EH model are supported; explicit regions and EH pad headers are rejected.
Only direct nounwind C calls with exact types, strong declarations, closed address uses and
the frontend's32-byte/alignment reference contract qualify. Those attributes are caller
preconditions, not runtime pointer attestation. Definitions, weak/imported targets, dynamic
descriptors, bundles, musttail and special control semantics fail eligibility.

Collect source requests before ordinary O2. A dedicated retention hook adds nomerge and
noduplicate to the reserved calls so separate points and loop events retain their identity.
Archive and ordinary import/frame routing exclude these compiler descriptors. Late binding
adds no CFG edges and leaves source EH behavior intact. A frozen source plan checks storage,
normal event, label and immutable body state; a separate serialized-IR proof checks the actual
state read, arithmetic, eight output spans and read-before-write snapshots. Consistent changes
to code and its descriptive metadata cannot substitute for the frozen source binding.
The frozen plan includes only admitted source sites. In optional mode, an unsupported EH-pad
site remains an ordinary call even after normalization moves it into a continuation body;
that move neither credits a binding nor creates a new required obligation.

This is ordered obfuscation arithmetic, not a cryptographic hash, MAC, KDF or secret. Its
public reference data can be reconstructed by a white-box attacker. Distinct-transcript
tests demonstrate named mutations; they are not a collision-resistance proof. Subsequent
key expansion must use its declared standard digest/KDF, while AES-GCM remains responsible
for refusing a wrong reconstructed key. Hardware/issuer authorization and D7 code measurements
keep their own authenticity/reference boundaries.

The LLVM helper uses eight volatile reads before eight volatile writes. The caller owns
aligned storage for eight words and keeps it private to one invocation or supplies external
synchronization. Volatile preserves compiler-visible accesses; it does not make concurrent
updates safe or protect memory from observation. Runtime adoption and close/drain still use
the [owned context contract](NATIVE_CONTEXT.md).

## Files and verification

The Windows backend supplies `PYOBF_NATIVE_SHA256(bytes, length, digest)` for key expansion.
The caller keeps its input stable and provides32 writable output
bytes. Empty input may be null; requests larger than ULONG_MAX and nonempty null input fail.
False erases a valid output span and must remain failure, never accepted clean-zero evidence.
Each invocation owns its algorithm/hash object with no global digest or observation cache.
Object storage uses the existing allocation/erasure macros and is destroyed after the hash
handle. This follows the [CNG object lifecycle](https://learn.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng)
and [fixed digest-size contract](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash).
The primitive alone does not authorize release. Its test boundary covers
actual CNG versus Python hashlib, four threads, input/output bounds and forced object-allocation
failure; arbitrary provider API failures are not injected. No kernel or non-Windows hash
backend is implemented by this addition.

The demo RuntimeContext owns its fold storage and erases it during whole-context cleanup.
`bootstrap/path_events.hpp` includes the private per-build generated descriptors. Required exact function
overrides bind initialization, accepted environment, successful owned support preparation
and the pre-decrypt release step. Environment/support use private transitional phases and
publish completion only after the fold update; CAS publication cannot overwrite retirement.
Observers do not supply these updates. Status verification and duplicate/retired operations
do not advance the transcript. Different sessions own different storage.

The actual decrypt boundary sees the completed release fold. Omitting environment or support
work while forging its lifecycle phase produces the independently expected wrong transcript.
The packer derives its mask from an independent build reference. Runtime reconstruction
serializes the actual fold, expands it through SHA-256 and unmasks the key; it never substitutes
an expected-fold global. Actual wrong-fold cases fail AES-GCM before loader/entry. Serialization
and transient key buffers are erased. Local events do not authenticate physical observations;
dynamic provider values and L2 measurement remain separate later units.
OFF/plain compilation explicitly links the ordinary marker implementation after source
collection; fully protected startup links without it. No implicit fallback is added when a
custom CFF recipe leaves a required real marker unresolved. Release is one attempt per
session; re-entering it adds another event and is not a supported decryption retry contract.

| File | Responsibility |
| --- | --- |
| `native/src/path_fold/value.hpp` | Internal constexpr unsigned32 value model, initialization, event fold and state-bound word encoding |
| `native/llvm/cff/path_fold.hpp`, `path_fold_emit.cpp` | LLVM arithmetic and invocation-storage emission; no OS calls |
| `native/src/path_fold/marker.{hpp,cpp}` | Private compiler ABI and separately linked ordinary reference |
| `native/llvm/cff/path_fold_marker.hpp`, `path_fold_sites.{hpp,cpp}` | Reserved names, ABI/closure/storage eligibility and bounded original-site discovery |
| `native/llvm/cff/path_fold_retain.cpp`, `path_fold_bind.cpp` | Pre-O2 identity retention and final-state event/store emission |
| `native/llvm/cff/path_fold_proof.cpp`, `path_fold_seal.cpp` | Serialized IR dataflow proof and independently frozen source/storage/event/body-state binding |
| `native/tools/path_fold_reference.py` | Independent build reference, strict word validation and canonical serialization |
| `native/llvm/tests/path_fold_fixture.cpp` | Actual production-emitter IR fixture and invalid-width boundary |
| `native/tests/path_fold_harness.cpp` | Executes emitted initialization/events/bindings and C++ value model against build references |
| `native/demo/check_cff_path_fold.py` | Boundary/random transcripts, skip/reorder/duplicate/site/value/state mutations, none/O2/IPO and deliberately altered IR |
| `native/llvm/tests/path_fold_seal.cpp` | Coherent metadata/code/storage/label/loss changes that require the independent frozen source plan |
| `native/tests/path_fold_sites{,_harness}.cpp`, `path_fold_plain_harness.cpp`, `path_fold_site_cases.py` | Actual whole/hybrid/loop source, ordinary-mode execution and valid-IR refusal/mutation inputs |
| `native/demo/check_cff_path_fold_sites.py`, `cff_path_fold_evidence.py` | Source/request/O2/runtime/IR-guard/final-image checks and function-scoped x86 presence |
| `native/demo/bootstrap/path_events.hpp`, `session.cpp`, `environment.cpp`, `lifecycle.cpp`, `release.cpp` | Private generated descriptors and actual context-owned startup sites |
| `native/demo/bootstrap/key_material.cpp`, `key_expansion.cpp`, `native/tools/release_plan.py` | Real-context adapter, shared runtime record/actual-fold expansion and strict per-child build inputs/reference |
| `native/demo/session_fold.cpp`, `session_fold_reference.py` | Real lifecycle/decrypt-boundary/omitted-step/isolation tests and independent build-reference/coverage validation |

Build with the existing LLVM/demo/smoke options. The CTest
`pyobf_native_demo_cff_path_fold_contract` compiles and executes the emitted IR. It checks
snapshot ordering, unsigned arithmetic, malformed reference inputs, serialization and loss
of an initialization store. This is arithmetic evidence, not final-image site coverage or
actual decryption-refusal evidence. Those gates remain required for D5 release completion.
The `pyobf_native_demo_cff_path_fold_sites` and `pyobf_native_cff_path_fold_seal` tests cover
registration, actual source execution, normal/catch/rethrow/loop paths, independent build
references, source retention, scope/budget/ABI failures, optional/off behavior, guard mutations
and current linked images. The final checker establishes function-scoped arithmetic presence;
it does not promote this to individual native-site proof. The separate
`pyobf-native-path-fold-verify` opt pipeline checks retained binding IR without reconstructing
the pre-transform source plan. Main demo key consumption/refusal has separate production-CNG
tests described in the [release record guide](NATIVE_RELEASE_RECORDS.md).

All instrumentation/CFF/optimization/linking must finish before executable reference hashes.
Expected folds, hash references or masked-key records must not feed back into the bytes they
measure. The later packer must finalize permitted reserved data without changing code/layout;
direct and cross-function hash-generation cycles remain unsupported.
