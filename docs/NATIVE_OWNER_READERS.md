# Generated owner readers and private cache representations

Status: implementation in progress. Optional reader admission, actual generated same-subject
CNG/cache execution and controlled lifetime/freshness/error checks pass. Generated callbacks
also pass source-none/O2 CFF, actual execution and exact callback/binding final-image checks.
Pre-key and both post-release production roles now select their early generated readers;
native placement, composed consumer and paired complete-release cost checks pass. The
existing measured CFF report still says generated owner independence is false.
The POST-only compiler and final-artifact join now prove the two fixed role/site
paths within the admitted Windows demo shape; independent generated-owner
contribution and individual-site machine survival remain unverified.

The existing observer allocates a separate owned State, cache and immutable consumer snapshot
for every creation. Generated readers add distinct actual mapped-byte paths rather than
wrappers around one shared captured digest. Standard SHA-256, canonical framing, OS range
admission and lifetime operations remain common primitives. They provide no shared cache or
public success result.

An optional private `ReaderBinding` carries the early owner/domain, capture callback and
self-inverse cache codec. Creation copies the binding; it retains neither the caller's
binding pointer nor mutable configuration. Reader and codec code are pinned until owned
State destruction. Legacy callers omit the optional field and retain their existing path.
The private C++ callbacks require the same build ABI; no public cross-DLL C++ ABI is added.
The cache codec must be bounded, operate only on the supplied record and avoid reentry into
observer/context APIs: publication and cache decoding invoke it under the existing owner lock.

The generated capture owns its volatile mapped reads, canonical DIR64 normalization,
material allocation/erasure, standard SHA-256 invocation and acquisition interval. Owner
and binding mismatches refuse before reading. Per-owner chunking changes the read loop
without changing canonical byte order or digest semantics.

The cache codec transforms that owner's digest and freshness/generation tuple only in its
private persistent cache. Consumption decodes into a temporary immutable tuple before the
existing identity, epoch, digest and read-start freshness checks. Publication sequence and
revocation remain owned by the same context. Codec failure revokes the owner rather than
replacing its value with zero or another owner's success. The representation is reversible
diversification, not encryption or a separate root of trust.

`prepare_owner_readers.py PLAN HEADER SOURCE` accepts the existing early reference plan,
requires `owner_readers.hpp` and writes only changed outputs. Owner keys and symbol domains
derive from its canonical pre-codegen identity and record index. No observed code bytes,
expected digest, final helper inventory or late reference value enters source generation.
Header/source/input aliases refuse. Generated callbacks use normal SDK CFF markers plus
private owner annotations; source annotations alone are not final independence evidence.

The same early generator now emits one `create_N` function per owner. Each checks the
supplied owner and supplies a fixed binding row to `observer::create`; callers do not
choose the row pointer. Pre-key and post-release bootstrap paths call these functions.
The compiler checks each typed creator definition, its local `Spec.reader` store and
direct `observer::create` call before and after CFF. It also requires a call from selected
noncreator producer code and rejects direct raw creation in a generated-owner module. The final PE
check covers the complete creator code beside the callback and binding contributions,
and rejects creator overlap with callback code. These checks establish the creator
function's row and code identity. The separate POST flow checks and final join below
connect the two parent role slots to child Scope sites; they do not prove that each
site has independent generated-owner contribution in final machine code, so
`generated_owner_independence_verified` remains false.

The compiler gate inventories actual distinct function definitions and readonly binding
initializers before transformation, and seals their exact identities through CFF. A bounded
origin analysis checks that volatile mapped-byte loads reach the callback's own material
allocation and standard SHA input, with output in its own capture. Ambiguous copies and
clobbered pointer slots refuse. It also checks a literal comparison with the early binding
key; the report names this a comparison check, not a complete proof of guard dominance or
all possible callback semantics. Runtime wrong-key and canonical-digest cases complement
that structural check. This is the admitted Windows x64 GNU/Clang source profile, not an
arbitrary IR or backend verifier.

The final checker requires the exact early plan, emitted COFF object and existing emission
inventory/report pair. It compares complete function contributions and relocated readonly
binding bytes with the final PE. Distinct callback ranges, exact owner keys, actual function
addresses and nonwritable/nonexecuting binding storage are required. Thin shared readers,
missing roles, disconnected reads, wrong SHA routes, stale emission inputs, modified code
or binding data, and folded final symbols have explicit refusal tests. Additional generated
helper compositions are rejected until they have a complete corresponding flow contract.

| File under `native/` | Responsibility |
| --- | --- |
| `tools/owner_reader_plan.py` | Early domains, binding declarations and generated source |
| `tools/prepare_owner_readers.py` | Existing plan parser and changed-only source output CLI |
| `cmake/OwnerReaders.cmake` | Early changed-only owner source/header generation in existing reference directories |
| `tools/owner_reader_image.py` | Exact actual callback and readonly binding contributions in final PE |
| `tools/owner_creator_image.py` | Exact final creator code and disjointness from reader code |
| `llvm/cff/owner_reader_bindings.*` | Typed source roles and actual constant binding initializers |
| `llvm/cff/owner_reader_flow.*` | Bounded mapped-byte/material/SHA and cache-write origin checks |
| `llvm/cff/owner_reader_contract.*` | Before/after CFF identity seal and private compiler evidence |
| `llvm/cff/owner_creator_flow.*` | Before/after CFF fixed creator row, direct call and selected producer use |
| `llvm/cff/owner_post_flow.*`, `owner_post_child_flow.*` | POST parent ready/creator/role and child Snapshot/Scope/site flow checks |
| `tools/post_role_join.py`, `demo/check_post_role_join.py` | Exact final cross-artifact role/site connection and mutation refusals |
| `src/measurement/owner_inline.hpp` | Compiler spelling for private algorithm instantiation |
| `src/measurement/owned_material.hpp` | Actual per-owner volatile byte loops and canonical fixups |
| `src/measurement/owned_capture.hpp` | Owner-specific capture, material/clock/hash and cleanup |
| `src/measurement/owner_cache.hpp` | Owner-bound reversible cache tuple representation |
| `src/measurement/observer.hpp`, `observer_internal.hpp` | Optional private binding and owned state |
| `src/measurement/observer_factory.cpp` | Binding snapshot, callback code pins and cleanup |
| `src/measurement/observer_sampling.cpp` | Independent callback invocation and cache publication/reuse |
| `tests/measurement/owner_reader_probe.cpp` | Real same-subject CNG/cache/domain/source-error and code-damage cases |
| `tests/measurement/owner_reader_module.cpp` | Private test factory and loader detach counter; no public SDK ABI |
| `tests/measurement/owner_reader_lifetime.cpp` | Same/split DLL callback origins, caller unload, forced reads/cache and last-snapshot detach |
| `tests/measurement/check_owner_readers.py` | Early source/CLI controls, real reference inputs and native test build |
| `tests/measurement/check_owner_reader_refusals.py` | Valid-IR and actual-image mutations against production gates |
| `tests/measurement/owner_creator_client.cpp`, `check_owner_creator_refusals.py` | Selected three-owner producer and creator source/final mutations |
| `tests/measurement/owner_reader_faults.cpp` | Existing controlled backend: callback pins, failed cleanup, encoded cache timing and revocation |

Production bootstrap builds generate the family from each existing early reference plan.
`demo/bootstrap/code_key.cpp` uses slot0; `post_preparation.cpp` uses the two declared post
slots, with the pre-release offset when enabled. The family enters the same authored IR
before optimization/CFF. Each observer copies and pins its exact callback pair. The ordinary
outer-CFF-OFF path compiles the same family without claiming transformed final code.

`demo/cmake/OuterPipeline.cmake` requests actual function sections and a private emission
receipt for measured CFF builds, then passes that object, receipt and early plan to the
existing final checker. `check_cff_outer.py` derives expected owner count from the independently
supplied plan. New SDK function requests are included in ordinary source accounting; no owner
is credited merely because the report contains a matching name.

Existing phase/post probes verify actual copied keys, callback addresses, pins and encoded
cache representations. Post probes additionally corrupt one reader key/codec and require
typed denial before effects, with the peer still usable. `measured_artifacts.py` forwards
explicit per-target reader inputs to existing failure/cost consumers. Each cost pair emits
fresh ordinary and protected objects and receipts; the ordinary image is tested against its
own pair's actual protected contribution, not a report from another optimization variant.

The three-owner fixture proves actual independent canonical CNG reads, declared once/bounded/
per-use cache hits and refresh, source-specific failure, immutable pending snapshots and
owner-specific cache poisoning. Controlled faults exercise callback pins, partial cleanup,
erasure, deadlines and terminal release failures. Actual same/split DLL callback unload passes
for ordinary and protected none/O2 code, including parent IPO. Per-site compiler source authority and influence/reporting,
remaining policy compositions and the original D5-D8 acceptance conditions stay open.
These checks add no root of trust against a local attacker who can patch runtime code,
replace OS/crypto primitives or dump already released data. Cache diversification is reversible;
once/periodic policies retain their declared stale observation windows.

The fixture is registered as `pyobf_native_code_owner_readers` and
`pyobf_native_code_owner_readers_cff_{none,O2}`. The protected none case also runs the
valid-IR and final-image refusals; parent IPO configurations add `--ipo` to the consumer link.
`pyobf_native_owner_reader_faults` uses the existing controlled backend and fault driver;
it verifies lifecycle/error handling, not crypto authenticity. Existing observer/context,
measurement and release consumers remain part of the affected regression selection.

Private-mechanism validation at f56a3f2 on Windows x64: the affected CLANG64 observer/context/measurement/
session/CFF-contract selection passes 60/60; parent-IPO none/O2 reader execution and final
gates pass 2/2; MSVC Release source-only observer fault/time/reader-fault checks pass 3/3.
This is selected affected regression, not the complete supported-profile matrix or a D7/D8
completion claim. Fresh production placement validation additionally passes POST-only 8/8,
PRE+POST/O2/archive/IPO/decoy plus private-reader refusals 17/17, and ordinary outer-CFF-OFF
7/7. Distinct public build chains settle without work. Six actual-bootstrap cost pairs bind
twelve fresh parent reader receipts to their exact early plans, objects and compiler reports;
the child uses its exact independent fixed contribution. Costs include disk/CNG/loading and
teardown, establish no performance bound or strength, and do not complete D5-D8.

The owner fixture also builds a private callback DLL and copies it to a separate module file.
Both instances must load at distinct handles with independent detach counters. A single-module
case and a split capture/codec case verify actual code origins, copied configuration, canonical
CNG digests, encoded cache reuse and forced refresh after caller handles are dropped. Closing
the owner and releasing its ordinary lease must keep both modules alive until the last retained
Snapshot releases. Each module must then detach exactly once. This is a same-build private C++
ABI test, not a new exported product API or an arbitrary cross-compiler DLL guarantee.
Borrowed-handle mutants return the correct module address without increasing its loader
reference count, separately for capture and codec. Each must fail at its precise early-detach
check before any unmapped callback is invoked. The actual module driver passes all three
ordinary/none/O2 cases with these mutants; production SDK/backend code is unchanged.
