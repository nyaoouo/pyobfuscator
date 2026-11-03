# Measured release key primitive

The private `pyobf_native_measured_release` source target reconstructs a content key using
an actual [owned code observation](NATIVE_OBSERVATIONS.md). Its v2 record keeps the64-byte
layout but uses `PYOBF-RELKEY-v2`, version2 and a separate expansion domain. Required measured
reconstruction refuses v1; existing v1 packaging, parser and key code remain unchanged.

The fixed framing is SHA256 over the NUL-terminated ASCII domain
`pyobf.native.release.measured.v1`, eight little-endian32-bit fold words, the complete52-byte
[reference identity](NATIVE_CODE_REFERENCES.md), then all32 actual digest bytes. The late
build reference masks a content key with this expansion; runtime unmasks with the actual
observation. No expected digest lookup or self-canceling observation is used. The existing
identity validator checks bounded build/image/owner/subject/kind/stage/capacity fields.
Observation sequence, lifecycle epoch and module address do not enter this build-known
expansion; their legitimacy is checked through the retained snapshot instead.

`release::measured::reconstruct(fold, record, snapshot, output32)` checks that same immutable
snapshot before and after hashing. Expiry, origin closure/invalidation, malformed clocks
and other observation failures preserve the observer error. Hash failure stays a crypto
failure; record and argument errors remain separate. Unpublished expansion material and
failed output bytes are erased. Inputs must remain immutable and cannot alias the output.
The `Result.observation` field describes only an `observation_failed` result.

The caller must retain the snapshot through its key-consuming operation and establish actual
bootstrap phase authority with its live session/context. A record's stage tag is not that
authority. Checking the snapshot is a consumption checkpoint, not continuous integrity or
an atomic measurement of mutable executable memory. A reconstructed key alone cannot replace
payload AEAD authentication. Local masks and fold material do not establish issuer/hardware
authorization or prevent an arbitrary runtime writer from forging client data.

The primitive has native/controlled, CFF none/O2, parent-IPO and source-only MSVC validation.
The opt-in Windows outer integration below preserves
freeze-code -> hash -> data-only record fill -> verify exact final image -> package order.
Post-release per-site CFF binding and generated owner anti-merge remain separate required
work. No exported SDK, new platform/provider or automatic fallback is provided.

The real driver checks929 independent vectors (a baseline plus every bit of its116-byte
fold/identity/digest input), native status/output and an independent SHA256 framing oracle.
It then releases the same AEAD child through actual section, unwind-interval and closed
function observations, rejects malformed records/v1, and denies wrong fold or unavailable
origins. Controlled tests add dirty hash output, transient/published key erasure and hash-time
expiry, invalidation, close, frequency change, reentrant refresh and null/invalid inputs.

The CFF driver checks all112 authored functions in each actual real/fault image, plus plain
image report refusal. Its separate valid-IR mutant replaces Snapshot::check with unconditional
success and deliberately bypasses that build gate.928 changed actual input bits per live
subject must still fail to recover the AEAD key; the ordinary image refuses this bypass
fixture, and the patched image cannot obtain a passing final report. This demonstrates the
tested crypto data dependency despite a forged validation result. It does not protect against
an attacker replacing the complete key calculation, supplying a known key, or arbitrarily
forging runtime memory.

| File under `native/` | Responsibility |
| --- | --- |
| `src/release/measured.hpp`, `measured_internal.hpp` | Private result/error/input contract and internal expansion seam |
| `src/release/measured_expansion.cpp` | Complete fixed framing, standard SHA256 and transient material erasure |
| `src/release/measured_key.cpp` | v2-only record admission, before/after snapshot checks and key publication |
| `tools/measured_release.py` | Independent host v2 domain/record/reference calculation; v1 remains separate |
| `measurement/{CMakeLists.txt,Checks.cmake}` | Private source target and actual/CFF test registration |
| `tests/measurement/measured_key_probe.cpp`, `check_measured_key.py` | All-input-bit vectors, real AEAD child and actual mapped section/unwind/closed-function observation |
| `tests/measurement/measured_key_faults.cpp` | Existing controlled observer/backend fixtures for dirty hash/key erasure, hash-time expiry/close/invalidation/reentry and failure sources |
| `tests/measurement/check_observer_cff.py` | Existing final-image driver extended with explicit measured-key mode; three additional authored functions, ordinary mode retained |

Optional paired measurement reuses these actual/plain images and records seven batches of128
reconstructions. Timed work includes both observation checks, SHA and transient/output erasure
on a retained snapshot. Initial code reading, reference authentication, owner creation and
child decryption are outside this hot primitive scope. It does not measure bootstrap startup.

## Opt-in measured bootstrap

`PYOBF_NATIVE_DEMO_PRE_CODE_HASH=ON` builds the Windows x64 demo with actual outer-text
measurement before child decryption. The default remains v1 for existing consumers. This is
a build option, not a runtime downgrade switch. The session owns its separate observer and
snapshot, checks the actual expected bootstrap lease/generation and `support_prepared` phase,
then uses the complete observation with the release fold after its release event. Snapshot
and parent-stage admission are checked again before child AEAD. Retirement closes the
observer and clears the retained snapshot; the observer stores no lease back to its parent.

Private `code_stage_status` and `code_key_result` retain stage, acquisition/reference, digest,
record, crypto and clock failure sources. They are diagnostic results, not reusable authority
or public key/metadata exports. Public failure codes retain their existing integer boundary.
There is no public alternate export of the key calculation and no v1 fallback in this mode.
Shared backend hash/clock primitives remain dependencies: substituting them can forge an
observation. Independent caches and CFF do not turn this self measurement into attestation.

The build uses early material and target identity to freeze one self-text startup selection
and an opaque reference store. Complete bootstrap/SDK CFF and native linking precede all
measurements. The existing reference envelope and a v2 release mask then fill only reserved
non-executable data; a composed proof binds the actual final image and verifies code/layout
unchanged. Child packaging and early headers remain upstream of that final measurement.
An authenticated presealed-package input permits independent exact report reproduction
without regenerating nonces; it refuses incomplete indices, bad envelopes and replacement of
different finalized storage. It is not a reference-rebasing API.

The current startup subject is one whole `.text` owner per session. This does not complete
configured multi-owner peripheral CFF checks, function-selection handoff, post-release
integrity, challenge reporting or D5-D8 acceptance. Other modules retain their separate
ownership. Only the implemented Windows x64 backend is admitted; no kernel/device/TPM or
Python bridge support is added here.

| File under `native/` | Responsibility |
| --- | --- |
| `demo/bootstrap/code_key.cpp` | Actual parent-stage/lease admission, owned observation and typed key/readiness results |
| `demo/bootstrap/{flow.hpp,release.cpp,session.cpp}` | Private session lifetime, pre-AEAD consumption and retirement |
| `demo/cmake/MeasuredRelease.cmake`, `OuterPipeline.cmake`, `Configure.cmake` | Explicit mode, early selection/store, protected source/backend composition and late finalization DAG |
| `backends/windows_user/measured_release_record.cpp` | Native opaque v2 placeholder; existing v1 object remains separate |
| `tools/bootstrap_reference_plan.py` | Frozen per-target self-text identity derived before final executable code |
| `tools/finalize_measured_release.py` | Existing reference/release finalizers composed with exact data-only writes and verification |
| `tools/{finalize_references,pe_release_record}.py` | Authenticated presealed verification and explicitly selected record version; default behavior retained |
| `tools/prepare_references.py` | Content-preserving early header/storage generation; late plan refresh cannot rewrite identical code inputs |
| `demo/check_measured_release.py`, `measured_release_probe.cpp` | Actual phase/lease/key/retirement harness and code/reference/mask/missing/v1 DLL negatives |
| `demo/{measured_release_cases,measured_dependency_cases}.py` | CLI/alias/stale-output refusals and actual late-refresh/no-code-feedback/no-change build contract |
| `demo/measured_artifacts.py` | Explicit private inputs reused by existing failure and full-release cost drivers |
| `demo/{check_release_plan,check_cff_outer}.py`, `cmake/ReleaseChecks.cmake` | Current final-byte/report agreement and independent added authored-function inventory |

The actual consumer tests all seven lifecycle phases plus unknown values with an otherwise
correct fold. It also rejects a foreign lease returning the expected generation, closed or
repeated release, dirty SHA failures at reference/code/key stages, and modified executable,
reference, mask, missing-reference or v1 bytes. Retirement invalidates a retained snapshot.
Final-image checks cover113 SDK,24 ordinary bootstrap and2 EH definitions; decoy variants
cover113 SDK,31 bootstrap and3 EH definitions. Plain builds still execute but fail CFF proof.
Source-none, source-O2 with parent IPO/archive, outer-CFF-OFF and strict-unavailable profiles
exercise the relevant admission/failure branches. Source-only MSVC compiles the same new
bootstrap and backend code and runs actual phase, CNG/AES and lifetime checks; this does not
claim an MSVC LLVM-pass pipeline. Windows loader numeric limits avoid the SDK's `max` macro.

The existing `pyobf_native_demo_measure_bootstrap` target accepts this mode's actual material,
frozen per-role plans and native storage objects. It compares same-source plain/protected
images for source-none/O2 and real, failed-real-to-decoy and denied-to-decoy release. Timings
include real CNG, file-backed inner loading, entry and teardown, rather than only key expansion.
Code/layout and exact-image checks precede sampling. These local costs do not establish a
portable performance bound or complete D7's multi-owner/per-site/reporting acceptance.

## Private post-release material-to-word adapter

The private `pyobf_native_measured_contribution` source target reuses the complete-observation
record to decode32 bytes of early-fixed contribution material. `contribution::measured::derive`
then reads8 little-endian words and invokes the existing contribution word framing. It accepts
only an authenticated post-release identity (stage2), checks the retained snapshot again after
the contribution hash, and erases decoded bytes and words on all exits. Material, derivation
and final-observation errors remain distinct; failures publish no contribution word.
`Result.material` describes reconstruction; `Result.observation` describes the final check
only after successful derivation. The integrating loader establishes actual phase authority
and retains that exact snapshot until the consuming transition completes.

Build order is early material/independent expected words -> CFF/constants -> final code ->
hash -> reserved non-executable material mask. The compiler's expected words therefore never
depend on their own final code digest. Wrong actual fold/identity/digest instead decodes
different material and changes the word consumed by existing transition arithmetic. A valid
unchanged-code refresh still yields the same word; cache sequence/epoch are liveness metadata.
The stage2 identity domain separates this use from the startup stage1 record. Each future
consumer must freeze distinct owner/reference bindings and cannot borrow another owner's
result, storage or success state.
The resulting site word is32 bits, matching the existing transition contract; it is not an
independent cryptographic authenticator or a claim that every possible wrong input is collision-free.

This adapter is an implementation seam, not a registered production measured provider.
Production phase/query dispatch, generated independent readers/caches/storage, anti-merge
proof, configured function inventory, reserved material placement/composed finalization,
actual original-path CFF binding and reporting remain required. Runtime writers, substituted
backend primitives and the known loader/dump boundary retain their documented limits.

| File under `native/` | Responsibility |
| --- | --- |
| `src/contribution/measured.hpp`, `measured.cpp` | Private typed material-to-word result, post-purpose admission, final snapshot check and erasure |
| `measurement/{CMakeLists.txt,Checks.cmake}` | Private source composition and explicit actual/CFF checks |
| `tests/measurement/{check_measured_key.py,measured_key_probe.cpp}` | Existing real code/AEAD/input-bit driver with contribution mode and independent four-site SHA word vectors |
| `tests/measurement/measured_contribution_cases.{hpp,cpp}` | Real contribution/vector and changed-material refusal cases, separate from the runtime |
| `tests/measurement/measured_contribution_faults.cpp` | Controlled material/derivation/clock/origin failures, erasure and legitimate refresh |
| `tests/measurement/check_observer_cff.py` | Existing114-body final-image, plain-refusal, forced-success validator and scoped paired-cost driver |

## Invocation scope integration

The private measured-scope source target adds an invocation-owned C++ Scope. It retains an
exact per-use snapshot and the expected parent lease while the protected function executes,
including exception propagation to its caller. The measured source marker/query ABI takes
Scope directly; the legacy marker/query retains its lease ABI. Parent admission is a distinct
bounded request returning the admitted generation, rather than an alternate service returning
the expected contribution word. Admission and final observation checks bracket actual word
calculation. Each Scope rejects owner/source/instance mismatch, missing/reused/non-per-use
observations and recursive simultaneous use; independent invocations have separate objects.
This path uses a168-byte, one-record existing AEAD archive for the32-byte early material,
not the unauthenticated v2 material mask alone. Its key is SHA256 of the NUL-terminated
`pyobf.native.contribution.scope.material.v1` domain and the complete observed-code expansion.
Malformed records, wrong digests and ciphertext/tag changes cannot produce material. The
generated scalar helper terminates on failed admission/derivation instead of returning zero
into an arbitrary comparison-tree leaf. Direct private queries preserve typed errors and
clear both the outer word and diagnostic nested word on failure.

The first compiler provider is `measured-scope-v1`, with one material source per function.
Its reports distinguish256-bit measured evidence and32-bit transition words, and explicitly
leave generated owner independence unverified. The current unit does not complete production
demo L4, late multi-record placement/finalization, generated owner anti-merge, all policies/
mixed-source compositions or D7 acceptance. Those remain required.

The private contract is exercised by an actual protected function on Windows x64 with
source-none/O2 and parent IPO, plus source-only MSVC builds. Checks cover normal/EH lifetime,
independent word vectors, parent admission/closure, refresh/reentry/concurrency and controlled
hash/AEAD/clock/allocation errors. Valid-IR helper substitutions and detached query words
cannot retain the compiler proof; plain bodies cannot borrow final-image evidence. Forcing
snapshot validation to succeed still cannot authenticate material for a changed observed
digest. The current default regression covers all329 test names across unchanged-candidate
split runs. These checks do not establish continuous integrity between observation and use.

| File under `native/` | Responsibility |
| --- | --- |
| `src/contribution/scope.hpp`, `scope.cpp` | Private invocation/identity/admission contract, retained snapshot/parent and RAII cleanup |
| `src/contribution/scope_query.cpp`, `scope_marker.cpp` | Strict parent admission, live measured query and separate plain-source marker |
| `src/contribution/scope_material.cpp`, `tools/measured_scope.py` | Existing complete-observation expansion and AEAD archive used to authenticate early-fixed material; erasure and independent host framing |
| `llvm/cff/contribution_query.{hpp,cpp}` | Exact legacy/measured marker/helper selection; shared proof and reserved-name classification |
| `tests/measurement/scope_cases.{hpp,cpp}`, `scope_body.cpp` | Actual scoped function, lifecycle/reference-count normal/EH tests and pre-effect negative |
| `tests/measurement/scope_cff.py` | Existing compiler/final gates applied to the actual scoped body, including valid-IR ABI substitution and detached-word refusal |
| `tests/measurement/scope_faults.cpp` | Controlled hash/AEAD/clock/epoch/parent-close/refresh/allocation failures and material erasure |
