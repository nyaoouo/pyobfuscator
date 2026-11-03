# Native bootstrap composition and cost boundaries

The Windows CLANG64 demo protects selected outer glue, reconstructs a local path-bound key
and owns context/image teardown. The optional decoy is a separate source/image/key domain.
This document separates these executable claims from the unfinished post-release handoff and
runtime transition oracle. Completing a cost measurement does not complete those mechanisms.

## Actual startup and protection order

| Phase | Current operation and first allowed use | Protection and evidence | Remaining boundary |
| --- | --- | --- | --- |
| L0: OS loads the outer | Selected outer glue and unselected macro backend become executable | Independent request/CFF/native-object/data-finalization/final-image gate; same-source plain images reject | Clear stage-zero implementation is unavoidable; CFF is local obfuscation |
| L1: initialize support | `initialize_session` allocates owned state, claims a generation and initializes its fold; environment acceptance precedes support preparation | Four required actual CFF event owners; per-invocation owned state and single-update phases | Placeholder environment reports unavailable; explicitly allowing it supplies no physical evidence |
| L2: back-validation | `prepare_support` and `support_is_ready` verify lifecycle; opt-in pre-code-hash mode observes actual outer `.text` before release | Wrong phases/generation/lease, code/reference/mask mutations, hash failures and retirement have actual-byte tests; measured digest/fold reconstruct the AEAD key | Default v1 remains local-only; later-support/peripheral transition binding and complete L2 acceptance remain required |
| L3: release application | Actual fold serialization, backend SHA-256, fixed masked record and CNG AES-GCM precede application loading | No raw-key fallback; real CNG and byte-classified loader faults; separate fixed-data completion avoids executable relinking feedback | No issuer/device secret; disk-backed loader still has a close-to-load replacement window |
| L4: prepare user entry | Inner checks the borrowed handoff/generation, publishes with strict expected-context identity and invokes the owned lifecycle operation before compute | Actual loaded-DLL and source/CFF context tests; no legacy fallback on the strict path | Post-release range measurement and an integrity-bound application wrapper remain unimplemented |
| L5: protected use and teardown | Context calls retain admitted frames; outer closes/drains, withdraws publication, unloads and erases adopted state | Host exceptions, recursion/nesting, concurrent calls, retained leases and invalid generations have explicit tests | Arbitrary child-owned exceptions/objects/background code surviving unload require another ownership contract; extraction of live code/state remains outside this static boundary |
| Failure decoy | Retire real admission, construct independent fold/key, authenticate and call the distinct POD entry | Four additional required event owners, separate AEAD domain, actual DLL tests and33 LLVM-valid observed faults | Failure work is not real-application gate density, authorization or an indistinguishability guarantee |

Later support constrains earlier services through owned lifecycle state and a noncommutative
local fold. `PYOBF_NATIVE_DEMO_PRE_CODE_HASH=ON` additionally binds actual outer code into the
key before child decryption; see [measured bootstrap](NATIVE_MEASURED_KEYS.md) for its explicit
v2/data-only finalization and failure boundaries. It supplies no device-derived authority.
Remaining L2 work must run before application-sensitive key use; an inner check after release
cannot retroactively protect that first decryption. See [owned handoff](NATIVE_DEMO_HANDOFF.md),
[path fold](NATIVE_PATH_FOLD.md), [release records](NATIVE_RELEASE_RECORDS.md) and
[decoy acceptance](NATIVE_DECOY.md) for the executable scope and named negative inventories.

## Isolated measurement target

With outer CFF and the demo's allowed-unavailable policy enabled:

```powershell
cmake --build build/native --target pyobf_native_demo_measure_bootstrap
```

The target is deliberately separate from normal CTest and all-target builds. Run it with
other builds/tests stopped. It writes `demo/bootstrap.measurements.json` in the build tree.
The benchmark is specific to the declared sample entry and its positive/zero/negative
results. Optional decoy scenarios are added only for the sample decoy source list; a custom
decoy requires its own semantic reference. A strict unavailable-denying configuration and
outer-CFF-OFF configuration do not expose this target, because they do not exercise the
ordinary accepted application-release comparison.

For both source `none` and ordinary `O2` before CFF, the driver starts from actual production
outer combined IR. It does not use the observed81-definition fixture that embeds sample
user/SDK source for fault testing. Pairs share exact child bytes, private event inputs,
masked record and macro backend sources. Baseline retains the source selection boundaries
and links the reference fold markers; protected code uses requests, actual CFF and a native
non-LTO object. Both use backend O2/non-LTO compilation. The final gate accepts each protected
image and rejects its same-source plain counterpart after data-only record completion.

| Recorded cost | Included scope |
| --- | --- |
| Request and ordinary optimization | Original authored request capture and optional `default<O2>` over the same actual combined IR |
| CFF and code generation | Transform/verify, O0/non-LTO machine object generation, then native link; each phase reported separately |
| Shared support | Backend/reference-marker object and harness compilation reported once, outside per-image times |
| Completion and final check | Fixed-record data completion and linked-image verification/rejection; ordinary I/O participates |
| `.text` and file bytes | Each final same-source plain/protected outer, including native support; child DLL identity reported separately |
| Warm startup | Alternating16-sample median of outer load, symbol lookup, one complete release and outer unload |
| Repeated full release | Outer remains mapped; seven alternating24-call batches still allocate context, reconstruct key, authenticate, create/load the inner file, execute and tear down each call |

The repeated number includes result validation and is not a body-only hot-call measurement.
Startup is not cold process startup. Neither number isolates CFF instruction latency from
CNG, temporary-file I/O, loader behavior or scheduling. Build costs exclude source frontend,
payload/plugin/toolchain builds. The benchmark records compiler version, seed, plugin,
harness/driver/builder/header/backend hashes, combined IR/recipe and exact child/plan/record
identities. The sample keeps existing loader and runtime limitations; no performance or
protection-strength bound follows from these medians.

With pre-code-hash mode enabled, the same driver carries exact per-role frozen reference
plans, actual native storage objects and early material into both paired images. Completion
uses the composed v2/reference finalizer; provenance records the selected binding and its
inputs. This includes actual reference authentication, code reading and observer lifetime
in full release. A denied-to-decoy path rejects real admission before those operations;
that row is not evidence of successful real-code measurement. Historical v1 costs below
retain their original commit and input scope.

One isolated Windows x64 CLANG64/LLVM22.1.8 observation for commit68900f1 on2026-10-28, with the default child
and optional sample decoy, produced the following pairs. The protected build column sums
only CFF, object generation and link; the JSON retains all other phases separately.

| Source profile / path | Plain / protected `.text` bytes | Protected build seconds | Plain / protected startup ms | Plain / protected repeated release ms |
| --- | --- | --- | --- | --- |
| none / real | 22614 / 58150 | 0.4924 | 30.817 / 30.696 | 27.624 / 28.336 |
| none / failed-real decoy | 24246 / 67782 | 0.5937 | 25.675 / 25.257 | 24.116 / 23.755 |
| none / denied decoy | 24278 / 67814 | 0.4177 | 23.637 / 26.642 | 24.526 / 24.191 |
| O2 / real | 20790 / 46246 | 0.3213 | 31.386 / 30.923 | 29.050 / 28.953 |
| O2 / failed-real decoy | 22406 / 54758 | 0.5205 | 24.946 / 25.173 | 24.521 / 24.280 |
| O2 / denied decoy | 22438 / 54790 | 0.4721 | 25.717 / 24.773 | 24.108 / 24.405 |

The file/loader work dominates this fixture, and small reversals in paired latency do not
establish a CFF speedup or an upper bound on its instruction cost. Real and decoy child
sizes/paths differ, so these rows are not an equivalence claim across scenarios. Each plain/
protected pair shares its own child and required work.

## File responsibilities

| Files | Responsibility |
| --- | --- |
| `native/demo/cmake/BootstrapMeasurements.cmake` | Explicit optional target, actual production dependencies and backend inputs |
| `native/demo/measure_bootstrap.py` | Source-profile/scenario pairs and provenance-bound JSON result |
| `native/demo/bootstrap_measure_build.py` | Timed request/optimization/CFF/native link/data completion/final gates |
| `native/demo/measure_bootstrap.cpp` | Real loaded entry, result checking, alternating startup and full-release batches |
