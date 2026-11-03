# Independent native decoy domain

The optional Windows GNU Clang demo builds a separately identified decoy image and explicit
outer-decoy variants. Their runtime core retires real admission before preparing independent
fold/key/image state. Ordinary outer variants keep their original failure behavior. Actual
DLL/CNG/exception/nesting/thread tests cover the core. Separate observed actual-CNG tests
cover post-emission faults, erased ownership, allocation failure and exact-child loader roles.
The combined D5 cost/readiness audit remains separate.

The Python `pack_decoy` reference obfuscates decoy source with its own namespace while
disabling recursive pack/oracle/integrity prerequisites. Native uses a separate PE domain,
source list, recipe and finalized image identity. The package is independently encrypted;
there is no claim that real and decoy images are indistinguishable or share one ciphertext.
Its handoff cannot supply the missing key/context to the real application.

## Configuration and order

| CMake option | Default | Contract |
| --- | --- | --- |
| `PYOBF_NATIVE_DEMO_DECOY` | `OFF` | Build the decoy package plus separately named outer-decoy/default-triggered variants |
| `PYOBF_NATIVE_DEMO_DECOY_SOURCES` | Two sample `.cpp` files | Configurable nonempty, unique CMake source list; compile all into one child domain |
| `PYOBF_NATIVE_DECOY_CFF_CONFIG` | `demo/recipes/decoy.json` | Independent recipe with domain `decoy-payload` |
| `PYOBF_NATIVE_DECOY_CFF_SOURCE_OPT` | `none` | Supported source optimization before CFF: `none` or `O2` |
| `PYOBF_NATIVE_DECOY_CFF_SEED` | Domain-separated derivation from the main public seed | Independently configurable public layout diversity, without a secrecy claim |
| `PYOBF_NATIVE_OUTER_DECOY_CFF_CONFIG` | `demo/recipes/bootstrap-decoy.json` | Separate outer recipe requiring all four real and four decoy event owners |

```powershell
cmake -S native -B build/native -DPYOBF_NATIVE_DEMO_DECOY=ON
cmake --build build/native --target pyobf_native_demo_decoy_package
ctest --test-dir build/native -R pyobf_native_demo_decoy_ --output-on-failure
```

Use the existing LLVM/compiler/backend configuration when creating that build directory.
The decoy pipeline is source IR -> entry/init contract check -> requests -> optional O2 ->
CFF -> native non-LTO object -> DLL -> exact linked report -> private events -> AEAD package.
Parent IPO cannot reoptimize the sealed object. It links no real SDK/context/backend source
automatically and has no build dependency on the real child's release key or oracle.
`pyobf_native_demo_outer_decoy` and `_decoy_triggered` are additional buildable aggregates.
They expose `PYOBF_NATIVE_FINAL_IMAGE` like the ordinary targets; distribution uses that
finalized DLL, not its `_unfinalized` native target. Existing ordinary targets never select
the decoy merely because its package was enabled.

The sample's entry is exported as `pyobf_native_inner_entry`, matching the current loader's
fixed export name. Its distinct `DecoyEntry` signature takes `const DecoyHandoff *` and an
`int`; the16-byte POD contains ABI version, size, public role and failure reason. It contains
no real lease/token, callbacks, machine evidence or content key. Supported source IR must
define exactly one strong exported default-C `i32 (ptr, i32)` entry without ABI adapters.
TLS, authored `DllMain`, dynamic constructors/destructors and direct outer-release/fold
dependencies reject before CFF request collection. The byte-level ABI check cannot prove
arbitrary user source obeys the documented handoff semantics. User code must include the
header and preserve its lifetime/initialization contract; general third-party DLLs remain
outside this prototype.

## Runtime core and observed acceptance

The selector admits reasons-2 (environment),-4 (real authentication),-7 (support) and-8
(real material/expansion). It closes/drains/retires the real session before entering the
decoy subflow. Direct allocation(-3), loader/entry failures and observer exceptions retain
their existing error/unwind behavior. Decoy preparation/authentication/load/resolve failure
returns-9 without recursive release. A material failure may originate in the hash backend;
the current Boolean provider does not expose a finer allocation-versus-provider status.

DecoySession owns a separate allocated/erased32-byte fold and loaded-image guard. Required
init/selection/preparation/release sites bind its private events to actual CFF state.
The real context is used only for borrowed observer notifications after retirement. A shared
selected `key_expansion.cpp` validates each record and serializes that caller's actual fold;
decoy reconstruction does not read or repair the real fold. Its independent key and sealed buffers are
erased before stage7; plaintext is erased after loading and before stage8. Fold storage and
any retained image are cleaned on owned exits. The observed fixture checks exact owned spans
and zeroed bytes at release, including production CNG object allocations, under its bounded
failure inventory. It does not turn the runtime into a trusted execution environment.

Stages7/8/9/10 mean decoy authenticated/loaded/entry returned/unloaded. Real stages1-6 retain
their original meaning. The demo's existing nonzero `corrupt` argument still changes the
real ciphertext; additionally setting the second bit (`corrupt & 2`) changes decoy ciphertext for
testing. Default zero is normal execution. Actual DLL tests include both denied environments
and failed real AEAD, decoy AEAD refusal, host-owned observer exceptions, nested calls and
four threads. The currently executing outer must stay mapped through return. Child-owned
exceptions/objects or background code surviving unload need a separate loader lifetime
contract; these tests do not validate arbitrary child exception ownership.

Ordinary outer images report66 selected definitions (21 normal,2 hybrid,42 context,1 source
derivation). The outer-decoy variants report74 (28 normal,3 hybrid,42 context,1 derivation), with eight required event
owners. Hybrid coverage remains partial, and failure-domain work does not inflate D6
real-application gate density. The same-source ordinary/reference-marker DLL executes its
declared tests but is rejected by the final CFF gate; forcing whole coverage over the actual
hybrid bodies also rejects. Kernel/in-memory loading and device authorization remain separate.

The observed fixture protects81 actual authored session definitions (the outer74 plus two
sample-user and five SDK definitions), checks the exact linked image and rejects the same
sources compiled without CFF. Its loader compares plaintext byte-for-byte to the two exact
final child DLLs supplied by the build. Its entry adapters count roles and validate handoffs;
the separate loaded-DLL tests execute the real child code. The CNG implementations are
compiled unchanged apart from test-only symbol names. Both the fixed real decrypt adapter
and generic AEAD implementation are renamed together, so the adapter's internal call does
not count as a second decoy request. The actual decoy key-boundary fold is checked against
the independent private-plan reference, and key-derived transcripts are filtered from errors.

| Observed inventory | Boundary checked |
| --- | --- |
| 15 existing real IR faults plus a forced denied-environment/support flow | Skips, wrong states, duplicates and forged support/key/hash results cannot load or enter the exact real child; the original no-decoy19-fault suite also remains registered |
| 11 decoy event faults, three forced preparation/key successes and one forced failed-hash success | Missing/wrong/duplicated own events cannot authenticate the decoy or fall back to real execution |
| Two forced AEAD-success statuses after actual authentication failure | An invalid plaintext load may be attempted; exact real/decoy bytes and their entries remain unavailable, and the loader returns refusal |
| Eight denied-path and13 failed-real-auth-path allocation points | One failure at each context, fold, buffer, key or CNG allocation preserves bounded cleanup; real hash/AEAD object allocation failure may select decoy through-8/-4 |
| Reordered/altered fold, wrong generation, foreign expected lease and closed real owner | Real admission is closed before independent decoy work, including retained leases; the failed real fold is not repaired |
| Four malformed record fields, provider/load/resolve failures and unselected reasons | Invalid records refuse before hashing, decoy failure does not recurse, direct-3/-5/-6 retain their ordinary result |
| Host exceptions at stages1/7/8/9/10 | All observed owned allocations and successful image handles retire while the exception propagates |

These are explicit test mutations and allocation sites, not an exhaustive adversary model.
The normal failure cases make zero exact-real-image loader/entry calls. Forcing the final
AEAD status can reach a loader with invalid bytes; the distinction is visible in separate
invalid-image attempt counters rather than being hidden by a Boolean success assertion.
The observer backend is sequential; actual DLL tests supply nesting and concurrent execution.

## Private data and protection boundary

The producer binds child bytes, source coverage and the exact linked report. Duplicate JSON
fields reject even when the report hash matches those bytes. The declared entry must have
final CFF coverage. A fresh `decoy.private.json` and matching `decoy_events_generated.hpp`
use the separate `decoy_events`
namespace. Event roles inherited from the version1 plan are local arithmetic descriptors;
they do not imply a successful physical/environment observation. Runtime integration must
own its separate fold and cannot borrow or repair the failed real transcript.

`decoy_blob.hpp` contains exactly nonce, tag, ciphertext, authenticated data and a masked
release record. It contains no raw content key or expected-fold digest. AEAD authenticates
the distinct `pyobf.native.decoy.v1` NUL-terminated domain plus exact child and final-report
SHA-256 digests. `decoy.package.json` binds those private generated artifacts. Wrong AAD,
role or real-fold reconstruction cannot decrypt the package in the regression fixtures.
The record uses the [standard release format](NATIVE_RELEASE_RECORDS.md).

This inline decoy record is an ordinary parent compilation input, separate from the real
parent's post-link `.pyobf` completion. It cannot accept a future reference derived from its
own measured executable bytes. Such a feature would need a separate fixed data-finalization
contract; it must not create a relinking cycle. Recursive authorization/oracle/integrity
requirements remain disabled for a decoy intended to run after a failed real path.
Local event obfuscation is reconstructable in a white-box attack. Keep private headers,
plans, IR and plaintext images in the build tree. Distribute only the intended outer artifact
after runtime integration; a child package alone does not close runtime/loader boundaries.

## Files and evidence

| Files | Responsibility |
| --- | --- |
| `native/demo/cmake/DecoyConfigure.cmake` | Source/recipe/optimization/seed options and early validation |
| `native/demo/cmake/DecoyPipeline.cmake` | Independent IR/CFF/native/final/plan/package build DAG |
| `native/demo/cmake/DecoyChecks.cmake` | Optional package, source-build and sample-entry test registration |
| `native/demo/cmake/DecoyRuntime.cmake`, `DecoyRuntimeChecks.cmake` | Separate outer-decoy targets, actual DLL/CNG/cleanup tests and same-source/whole-EH negatives |
| `native/demo/decoy/{handoff.hpp,payload.cpp,compute.cpp}` | Distinct POD ABI and two-source sentinel sample |
| `native/demo/decoy/smoke.cpp` | Actual loaded sample entry, boundary integers and malformed handoffs |
| `native/demo/decoy/runtime_smoke.cpp` | Accepted/denied/real-corrupt/decoy-corrupt execution, host exceptions, nested and four-thread mapped-image cleanup |
| `native/demo/check_decoy_runtime.py`, `decoy/runtime_build.py` | Actual source/request/none-O2/CFF/native/final checks, separate host observations and independent private-fold reference |
| `native/demo/decoy/runtime_mutations.py` | 33 LLVM-valid real/decoy event/status faults compiled without rerunning the build proof |
| `native/demo/decoy/runtime_fixture.hpp`, `runtime_backend.cpp`, `runtime_crypto.cpp` | Invocation counters, exact-image loader roles, allocation/erasure/lifetime observations and wrappers around production CNG |
| `native/demo/decoy/runtime_cases.cpp`, `runtime_fault_smoke.cpp` | Allocation/context/record/provider/observer scenarios and one-mutant process boundary |
| `native/demo/bootstrap/failed_release.cpp` | Bounded failure selection following real close/drain/retirement |
| `native/demo/bootstrap/{decoy.hpp,decoy_session.cpp,decoy_preparation.cpp}` | Separate fold/image ownership and ordinary selected event preparation |
| `native/demo/bootstrap/{decoy_key.cpp,key_expansion.hpp,key_expansion.cpp}` | Decoy record adapter and shared selected standard expansion/serialization erasure |
| `native/demo/bootstrap/decoy_release.cpp`, `native/demo/recipes/bootstrap-decoy.json` | Explicit hybrid decrypt/load/entry/unload subflow and eight required owners |
| `native/tools/decoy_contract.py`, `check_decoy_input.py` | Source ABI/init refusal and exact decoy coverage/final identity policy |
| `native/tools/release_plan.py`, `prepare_release.py` | Strict shared private-plan format with explicit event namespace |
| `native/demo/pack_decoy.py` | Separate domain-bound authenticated encryption and masked-record header/manifest |
| `native/demo/decoy_test_support.py`, `check_decoy_package.py` | Independent package bytes/AEAD checks, valid-IR source refusals and stale/wrong-role/namespace/alias negatives |
| `native/demo/check_decoy_build.py` | Production module in isolated none/O2/IPO CMake builds, source/header/recipe/output invalidation and no-change/OFF checks |

Final inspection proves the same scoped linked function/component presence as the other
demo domains; it does not promote this to individual machine-site coverage. Package tests
prove producer AEAD behavior, with separate actual DLL and observed-CNG runtime tests.
The disk-backed loader replacement window,
device authorization and runtime extraction keep their existing independent boundaries.

Isolated build tests retain their private fixture and complete command output on failure.
Observed runtime tests retain their failed private directory and redacted failure traceback.
Successful cleanup is restricted to the fixture created under the declared test parent;
cleanup errors remain visible. Atomic replacement and single owned-file removal use the
shared [bounded Windows I/O policy](NATIVE_RELEASE_RECORDS.md); persistent and unexpected
errors remain failures, without accepting stale output. Recursive fixture cleanup has no
additional retry policy.
