# Independent owned code observations

The private `pyobf_native_code_observer` source target combines authenticated
[reference records](NATIVE_CODE_REFERENCES.md), actual [mapped-code capture](NATIVE_CODE_CAPTURE.md)
and existing owned-context lifetime. Each observer has its own decoded reference, pinned
target-module view, cache, epoch and read sequence. Snapshot values are copied, with an
external context lease retaining the actual target and metadata. Caches contain no self lease.

The private runtime has actual native, controlled-clock, CFF, IPO and source-only MSVC
validation. Scoped costs and integration evidence are recorded in the D7 implementation plan.
This is not yet the
production stage/provider/CFF adapter or a new public SDK. No installed/exported observer ABI
or challenge serializer is provided.

## Ownership and operation boundary

`observer::create(package, size, expected_identity, private_words, spec)` authenticates with
independent caller identity/material, validates the descriptor against the actual module
containing `spec.member`, and pins that module before returning an owned context. Caller input
is immutable through creation; ciphertext/private words are not retained. Creation errors
preserve reference/capture/context failure sources. Actual bootstrap phase/key authority is
the integrating loader's responsibility; record stage IDs and lifecycle generations do not
establish it.

`observe(lease)` returns a move-only Snapshot containing full identity/policy, context instance,
captured epoch/read sequence, actual digest/status/start/completion/frequency, and acquisition
error. `reused()` describes this acquisition. `reference_digest()` is a local expected-value
view, not key material or automatically reportable metadata. Moves/reset retire visible state
before the previous lease can dispose resources; callers serialize mutation of one handle.
Concurrent calls through stable leases are supported.

`Snapshot::check()` validates the same acquired operation against current lifecycle and
read-start age. It does not perform a new code read or replace a pending request's snapshot.
A per-use CFF/reporting boundary must acquire a new snapshot through `observe`; validating an
old operation is not another per-use observation. A collector can copy `data()` while retaining
the Snapshot through consumption. No remote authenticity follows from these client records.

The tuple separates the observer's context `instance` from the trusted loader-supplied
`subject_instance` in Spec (required nonzero). Neither is a module base or remote attestation.
The integrating loader must issue a new subject instance and retire affected observers when
that target/stage changes. Several owners can name the same subject instance while retaining
different observer contexts and caches. The target cannot
unload while observer/snapshot leases retain the pin. Retire the context and create a new one
for a new loader instance/stage; same-address loading cannot reuse the old context authority.
Closing prevents consumption while retained memory can remain alive until the last lease.

## Policies and invalidation

| Policy | Normal `observe` behavior | Bound |
| --- | --- | --- |
| `once_per_instance` | Read initially, then privately reuse | `max_age_ns` must be zero; later mutations are outside normal observation coverage |
| `periodic_bounded_age` | Reuse within max age; synchronously refresh an expired cache | Nonzero age and scan budget, measured from read start |
| `per_use` | Independently read on every call, including concurrent/reentrant calls | Nonzero age and scan budget; no in-flight read coalescing |

`observe(lease, true)` explicitly strengthens the request with a fresh read, including for
challenge/operation refresh. No background scheduler or silent policy downgrade is introduced.
Normal refresh advances sequence and may replace cache values; it does not alter an old
snapshot, invalidate its still-valid operation or change normal correction semantics. Earlier
scans may return their own valid result but cannot overwrite a newer published sequence.

`invalidate(lease)` revokes that owner. Failed required scans, digest/cache corruption, invalid
clocks or exhausted counters also revoke it and clear cache authority. Later success cannot
reopen that context; recovery requires explicit new-owner initialization against the original
authenticated reference. An old snapshot's ordinary age expiry rejects that operation while
allowing a new acquisition to refresh. Expected hashes never rebase to observed bytes.

These checks detect the tested malformed tuples, cross-owner copies and digest changes.
The mutable cache is not separately authenticated against an arbitrary in-process writer;
plausible forged timestamps are outside this static-protection boundary. Once mode and the
bounded cache window also intentionally leave later unobserved code changes undetected until
an explicit refresh or the next required read. No continuous monitoring is claimed.

Age and scan comparisons use portable exact64-by64 wide multiplication against nanosecond
bounds, with no `__int128`, floating point or overflow-prone conversion. Reversed time,
frequency changes, late completion and late publication cannot reset age to zero. Once mode
still records timing and rejects invalid clock tuples without claiming bounded freshness.

## Synchronization and backend contract

Publication and close use the existing context gate. A private friend/access declaration adds
no state/layout/ABI fields and no installed callable API. Context close cannot interleave
inside publication. Allocation, AEAD, mapped reads, SHA and resource destruction execute
outside this gate, allowing reentrant reads. Only pure tuple work and the existing monotonic
clock may run under it. This clock must be bounded, non-reentrant and callback-free; the
current Windows backend uses QPC/QPF. This is a checkpoint linearization, not continuous
observation or an atomic snapshot of mutable executable memory.

The source target is private same-build C++ and inherits the context ABI/backend/caller-code
lifetime contract. Its internal request structures accept trusted in-process C++ callers;
they are not parsers for untrusted network/license input. Context generations and operation
IDs are lifecycle/routing information. The later compiler adapter must bind genuine digest
influence and actual phase prerequisites, not use a standalone returned success Boolean.

## Source and test map

| File under `native/` | Responsibility |
| --- | --- |
| `src/measurement/observer.hpp`, `observer_internal.hpp` | Private typed API, immutable tuple, protocol and owner state |
| `src/measurement/observer_factory.cpp` | Authenticated creation, actual module pin, existing context ownership and destruction |
| `src/measurement/observer_time.cpp` | Portable wide deadline comparison and clock interval/policy rules |
| `src/measurement/observer_state.cpp` | Gate access, identity/cache checks, terminal invalidation and copied results |
| `src/measurement/observer_sampling.cpp` | Cache policy, actual reads outside locks, sequence/epoch publication and consumption |
| `src/measurement/observer_dispatch.cpp` | Private request shape/origin and action routing |
| `src/measurement/observer_client.cpp` | Snapshot ownership/moves/reset and typed client operations |
| `src/context/runtime.hpp`, `include/pyobfuscator_native/bootstrap_context.hpp` | Private friend seam; existing runtime algorithms/layout remain unchanged |
| `tests/measurement/observer_probe.cpp`, `check_observer.py` | Real AEAD/module/code policies, moves, refresh, independent owner/cache poisoning and error provenance |
| `tests/measurement/observer_time_probe.cpp`, `check_observer_time.py` | Independent big-integer deadline oracle and interval/policy cases |
| `tests/measurement/observer_fixture.*`, `observer_faults.cpp`, `check_observer_faults.py` | Reused controlled backend, typed fixture/key erasure, cleanup and terminal release failures |
| `tests/measurement/observer_policy.cpp`, `observer_races.cpp`, `observer_failures.cpp` | Freshness/cache corruption, reentry/late/close ordering, OOM and failure provenance |
| `tests/measurement/check_observer_cff.py` |109 authored observer/reference/archive/capture/context bodies, actual real/fault final images and plain-image refusal |
| `tests/measurement/observer_cost.cpp`, `measure_observer.py` | Optional paired section/function, one/four owner, three-policy hot/cold costs using the existing final-image/size/hash helpers |
| `tests/measurement/failure_{fixture.hpp,backend.cpp}` | Existing erasure/end guards with optional fixed clock; legacy defaults remain unchanged |

The real driver covers `.text`, an exact unwind interval and a closed function including its
declared alias/cold fragment. It keeps normal reads and mutation windows ASLR-enabled. A
separate test-only copy disables DYNAMIC_BASE for actual same-address unload/reload, after
proving its canonical code digest is unchanged; normal ASLR reload may choose another base.
Source none/O2 and parent-IPO cases check all109 authored bodies against each actual final
image and refuse a plain image borrowing its protected report. The controlled backend tests
ordering and failure cleanup; independent real AEAD/mapped reads supply crypto/code evidence.
The deadline driver compares28197 cases with Python arbitrary-precision arithmetic; the
source-only MSVC consumers exercise the same private runtime without an LLVM/MSVC pass claim.

`check_observer_cff.py --measure-output <json>` also measures paired plain/protected costs on
the same section or closed function, with one/four distinct owners and all three policies.
Hot groups include acquisition, consumption and snapshot retirement; cold groups also include
reference authentication, owner creation, first read and final cleanup. Seven batches of32
groups and compiler/IR/object/sample/package/image digests are recorded. These are local
microbenchmarks, not full bootstrap or reporting costs, and are not timing guarantees.

Runtime read/cache independence does not prove distinct final owner-function wrappers or
anti-merging. Those, stage/provider integration, uncancelled full-digest CFF influence,
bootstrap L2/L4, reporting consumers and complete D5-D8 acceptance remain required.
