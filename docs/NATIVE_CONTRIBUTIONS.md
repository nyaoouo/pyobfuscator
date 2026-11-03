# Native runtime contribution foundation

The first D6 units implement a finite-width word reference, LLVM relative-transition
correction expression, strict compiler descriptor resolution and synchronous owned-context
acquisition. Opt-in [contribution gates](NATIVE_CONTRIBUTION_GATES.md) now acquire actual
words and seal explicit-point or selected retained-input normal-edge transitions, with
count/density and budget requirements, including Windows x64 GNU hybrid normal edges and
branch-only regions. Per-site owned-material groups now use the same ordered framing.
Other provider classes/compositions and ordinary demo payload integration remain unimplemented.
The demo now freezes private source material after authenticated decryption and serves
derived words after payload entry. Its ordinary payload does not consume those words yet;
this unit alone does not make a dumped body depend on a bootstrap context.

The gate adapter is separate from the original primitive and generic descriptor
tests below; its partial runtime coverage does not complete D6.

## Word framing and reference

The internal v1 mixer keeps two uint32 lanes and a uint32 word counter. Domain, function and
site identify initialization. A source contributes its label, encoding identifier and word
count before its ordered words. Source boundaries and empty groups therefore remain part
of the representation. Arithmetic wraps modulo2^32, without signed-overflow assumptions.
The independent Python implementation rejects malformed/out-of-range build words instead
of truncating them silently.

This mixer is public obfuscation arithmetic with32-bit output, not a cryptographic hash or
source validator. Its output can collide. It does not replace the eight-lane bootstrap fold
used by [key reconstruction](NATIVE_PATH_FOLD.md). Source encoding IDs merely frame words at
this layer; they do not implement evidence classes, backend capability or reference policy.
Those remain the compiler/runtime source-resolution contract.

## Compiler source and site policy

The internal `resolve_contribution_contract` API accepts registered provider capabilities,
source descriptors and ordered site assignments. It resolves all input without modifying IR;
failure returns an error and an empty result, including when an earlier site was valid.
The gate adapter uses this resolver for its owned-context material policy, including a
[schema2 JSON catalog and per-site groups](NATIVE_CONTRIBUTION_GATES.md#per-site-source-subsets),
and a bounded [schema3 explicit-site owned/measured mix](NATIVE_CONTRIBUTION_GATES.md#mixed-providers-across-explicit-sites).
The [schema4 source-mixed profile](NATIVE_CONTRIBUTION_GATES.md#mixed-providers-within-one-explicit-site)
uses one explicit site with separate owned and measured references. Its joint
owner/epoch binding and automatic original-edge allocation remain open.
The homogeneous [schema2 multiple-Scope original-edge profile](NATIVE_CONTRIBUTION_GATES.md#multiple-scope-references-on-original-edges)
instead binds generated edges to retained explicit measured anchors. It does
not extend schema4 automatic edge allocation or prove generated owner independence.
Arbitrary provider classes and dynamic evidence adapters remain unfinished.

| Policy | Current resolution rule |
| --- | --- |
| Identity and framing | Bounded nonempty IDs, exact provider version, unique source ID/nonzero word label, canonical nonaliased encoding names/tags and unique owner/site pairs |
| Types and budgets | uint32-word widths within the declared source budget; currently32-bit correction result; bounded source/site inventories |
| Reference semantics | Evidence uses independent build reference; material uses its authenticated context; dynamic values require a named registered symbolic adapter |
| Runtime stage | A source cannot claim readiness before its provider or be assigned before its own required stage |
| Freshness contract | Per-use/once cannot silently ignore an age setting; periodic requires nonzero age, exact clock unit and a declared monotonic-clock capability |
| Observation sharing | Independent owner observation must be supported; shared context material cannot stand in for independent evidence |
| Required groups | Count only required binding sources; exclude dynamic diversity and observation-only sources; independent-evidence groups also exclude material |
| Unavailable provider | Required use fails resolution; explicitly observation-only use remains unavailable with no encoding/value authority or required coverage |
| Reporting | A source cannot upgrade a known provider's reportability; unavailable observation-only sources have effective reporting disabled |

Required binding, dynamic diversity and observation-only use are separate enum values and
counters. A source may appear at several owners; resolution preserves each owner and source
order. `independent_declared` records the capability contract and is not proof of emitted
independent readers/caches. Those still require D7 implementation and final-code checks.

Provider capability sets declare their complete supported combinations. Register separate
typed adapter IDs when a backend does not support that full combination of classes, widths,
encodings, reference and observation policies. The catalog is supplied by backend/compiler
registration, not by an observation claiming that it is valid. Capability declarations do
not prove an implementation, its clock, runtime freshness or cryptographic authority.
The current contract executable uses a deliberately synthetic `fixture-only` catalog.

The resolver contains no expected/private source words and performs no observation or cache
read. `OwnerObservation` is still a future runtime snapshot contract; this unit does not
implement its epoch, refresh or invalidation behavior. Source acquisition must not expose
the bootstrap fold used for real key reconstruction as a public SDK value.

Different sites can frame different source groups. Future acquisition must independently
establish their values, validity, origin/generation, freshness and admitted reference. A
required unavailable source cannot be substituted with a normal numeric zero. Ordinary
program values may legitimately vary; they need proven symbolic/normalizing adapters or an
unsupported result, rather than a baked correction that assumes one unknown value. No dynamic
provider or symbolic adapter is implemented by the primitive or initial context adapter.

## Correction algebra

Let `M` be the existing bijective uint32 mask, `s/t` the normal source/target states, `r` the
transition salt and `q` a site contribution salt. The independent build reference supplies
`expected`; the emitted consumer receives `actual` and `current`:

```text
encoded = (t - s) XOR M(s XOR r)
sealed  = encoded XOR M(expected XOR q)
delta   = sealed XOR M(actual XOR q) XOR M(current XOR r)
next    = current + delta                         [modulo 2^32]
```

Normal values produce `next=t`. For fixed normal state, a different32-bit actual contribution
produces a different delta. The emitted expression contains no expected-value lookup or
fixed-state comparison. This is not an unforgeability guarantee against coordinated input/
code replacement. Owned context acquisition/lifetime now exists for the initial material
adapter; other source/reference semantics and genuine code observation still need later
D6/D7 work.

The emitter validates i32 state/observation inputs before emitting the expression and reuses
the existing word-mask and relative-delta implementations. It adds no CFG branch or OS call;
acquisition/availability structure must be prepared before final state assignment when the
component is integrated.

## Owned context source

`pyobf_native_contribution_runtime` is a source-only CMake consumer target, separate from the
provider implementation. It links the owned context runtime and compiles `client.cpp` into
the consumer. When a backend declares `PYOBF_NATIVE_BACKEND_CAN_SHA256` and its
`PYOBF_NATIVE_BACKEND_SHA256_SOURCES`, `pyobf_native_contribution_provider` additionally
provides derivation and that backend's hash implementation. Only Windows user mode has
verified SHA-256 acquisition here; other backends can supply the same semantic macro.
No compiled SDK library or Python/C ABI is introduced.

```cpp
const contribution::Site point{domain_id, function_id, site_id, source_id, current_state};
const auto result = contribution::request(expected_lease, routing_tag, point);
```

The four identity fields and routing tag must be nonzero uint32 values; current state may
be any uint32. `expected_lease` must match the actual scoped publication. Requests never
fall back to the legacy v1 API. The caller retains its executing consumer module through
return; a context lease alone does not keep arbitrary caller code mapped. The synchronous
owned call retains admitted provider userdata and callback code. Requests admitted before
close may finish afterward; later acquisition refuses. Request fields are copied before
dispatch, so reentrant withdrawal/reset does not require accessing the caller's lease again.

The private v1 message is48 bytes with explicit version, exact size, routing tag, generation,
site and zero reserved fields. The provider copies bounded input before reading it, allowing
unaligned storage. This is an in-process C++ protocol using the target ABI, not a portable
network format. The result's high uint32 is a reply framing tag and its low uint32 is the
derived nonzero word. Failed statuses discard any supplied value. A wrong tag or zero word
is invalid. The tag detects malformed responses; it is not a MAC or provider authenticity
proof.

The demo takes a single immutable eight-word snapshot only after real AES-GCM authentication
returns success. An atomic initializing/published state makes later readers observe complete
storage; a second freeze refuses. Serving also requires `payload_entered`, the current owned
generation and matching routing identity. The snapshot is separate from mutable startup fold
storage and is erased with the whole context after all retained uses. It is key-related
material, not an integrity cache: changing the original fold afterward is not a new observation.
Patching the published flag over a zero snapshot produces the wrong derived material.

The provider serializes the following bytes and returns the first four SHA-256 bytes as a
little-endian uint32, replacing zero with one:

```text
"pyobf.native.contribution.context.v1\0"
+ LE32(routing_tag, domain, function, site, source, current)
+ LE32(private_snapshot[0..7])
```

Generation is validated for lifetime/origin, but excluded from the derivation so a legitimate
new context with the same build material has a stable independent build reference. Private
words never appear in the reply. Serialization and the allocated32-byte digest are erased;
allocation or backend hash failure produces a failed status and word zero. All runtime
allocation, release, erasure, hashing and synchronization use backend operation macros.

This is local binding with a32-bit truncated result and possible collisions. It is not
machine authorization, a secure MAC, replay prevention, or protection from a live attacker
querying/altering the same process. The gate adapter now emits query calls and
sealed corrections at explicit points or automatically selected retained-input normal edges,
with count/density and budget checks, including admitted hybrid normal CFG and branch-only
regions. Schema2 source subsets combine actual derived material queries with the word mixer.
Other provider classes/broader compositions and the ordinary demo payload gate remain
unfinished. The earlier compiler capability policies
do not establish independent hash readers, caches or freshness; those remain D7 work.

## Verification and limits

The standalone generator executes the production LLVM correction emitter. Its harness
checks the C++ model against an independent Python reference at every initialization,
source header and word update. Fixtures include different identities/source subsets,
boundary words, empty groups, count/length framing and deterministic randomized transcripts.
Named skip/duplicate/reorder/label/encoding/bit mutations must perturb their declared normal
fixture. Those sampled changes do not prove collision resistance.

Three site consumers execute1,755 correction vectors, including normal observations,
changed states and observation bits. Ordinary none/O2 and parent-IPO test profiles check
bit-exact behavior. Invalid/null/wrong-width emitter inputs reject before creating output.
An LLVM-valid consumer whose return is replaced with zero must fail the executable test.
This is expression/reference coverage, not final-application gate coverage or real-edge
density. Only the Windows CLANG64 environment is verified at this stage; other platforms
remain unverified.

```powershell
ctest --test-dir build/native --output-on-failure -R pyobf_native_demo_cff_contribution
ctest --test-dir build/native --output-on-failure -R "pyobf_native_(contribution_|demo_contribution_session_)"
```

The actual CNG context tests compare six site/identity variants with an independent Python
SHA-256 reference. They exercise strict foreign/missing/closed contexts, malformed replies,
reentrancy, four concurrent readers and close/drain with an admitted call. Separate resource
tests observe exact serialization/digest erasure, allocation failure, hash failure with dirty
output, and zero normalization. The44 authored client/provider/context definitions execute
under none/O2 source optimization and linked-image checking; the failure provider also runs
after CFF. Actual bootstrap tests protect74 authored definitions, compare the authenticated
snapshot with the private build reference, and reject premature use, corrupt ciphertext,
malformed messages and stale generation. Runnable same-source plain builds must fail final
CFF certification. These test counts are source coverage, not required-edge gate density.
The source context factory initializes the const code-lease array's members explicitly;
MSVC19.44 rejects the earlier aggregate-copy form. This preserves the provider handles and
ownership protocol rather than introducing a compiler-specific runtime branch.
The source-only MSVC Release profile passes11 tests, including actual CNG contribution,
erasure/failure paths and owned context lifetime. The backend probe explicitly builds Release
and resolves multi-configuration executable directories. This is source SDK support; LLVM
CFF and the encrypted bootstrap remain verified only with CLANG64.

## File responsibilities

| Files | Responsibility |
| --- | --- |
| `native/src/contribution/value.hpp` | Portable ordered word framing, finish and correction seal/unseal |
| `native/tools/contribution_reference.py` | Independent strict uint32 host model |
| `native/llvm/cff/contribution_expression.{hpp,cpp}` | Typed runtime-observation/current-state correction emission |
| `native/llvm/cff/contribution_contract.hpp` | Source/provider/site/use/resolution descriptors; future runtime owner snapshot |
| `native/llvm/cff/contribution_validate.{hpp,cpp}` | Width/reference/freshness/sharing and capability prerequisites |
| `native/llvm/cff/contribution_resolve.cpp` | Registry identity/encoding/label checks, ordered owner subsets, group counts and failure that clears every site |
| `native/llvm/tests/contribution_contract.cpp` | Synthetic catalog positives and57 descriptor/policy refusals; no runtime-provider claim |
| `native/llvm/tests/contribution_fixture.cpp`, `llvm/cmake/ContributionFixture.cmake` | Production-emitter generator with three sites and malformed-input modes |
| `native/tests/contribution_cases.py`, `contribution_harness.cpp` | Independent framed transcripts, source mutations and executable C++/LLVM comparisons |
| `native/demo/check_cff_contribution.py`, `demo/cmake/ContributionChecks.cmake` | none/O2/IPO execution, malformed-emitter and altered-consumer refusals |
| `native/include/pyobfuscator_native/contribution.hpp` | Source-only C++ site/result and synchronous request/provider helper APIs |
| `native/src/contribution/protocol.hpp`, `client.cpp` | Private bounded frame, strict owned dispatch and response validation |
| `native/src/contribution/context_derive.cpp` | Canonical SHA-256 serialization, nonzero normalization and private temporary erasure |
| `native/contribution/{CMakeLists.txt,Checks.cmake}` | Separate source consumer/provider targets and supported CFF test registration |
| `native/demo/bootstrap/contribution{,_snapshot}.cpp` | Lifecycle-bound source dispatch and post-authentication immutable snapshot |
| `native/tests/contribution/{context.cpp,check_context.py}` | Actual CNG, independent canonical reference, identity/reentry/concurrency/lifetime tests |
| `native/tests/contribution/{derive_failure.cpp,check_cff.py}` | Observed OOM/hash/erasure paths and transformed/plain exact-image tests |
| `native/demo/{contribution_session.cpp,check_contribution_session.py}`, `demo/cmake/ContributionSessionChecks.cmake` | Actual protected bootstrap snapshot, malformed/early/failed source use and private-plan reference |
