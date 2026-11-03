# Authenticated code reference codec

The private `pyobf_native_code_reference` source target now seals and decodes bounded
canonical code references using the existing typed archive AES-256-GCM envelope. It reuses
the [native capture](NATIVE_CODE_CAPTURE.md) and [function subject](NATIVE_FUNCTION_SUBJECTS.md)
foundations. Production late reference slots/finalization, source-provider registration,
cache/freshness and measurement-bound CFF consumption remain pending.

## Independent identity and key material

The caller supplies an identity fixed before code generation:16-byte build ID,16-byte
subject-image role, nonzero owner and subject tags, canonical kind1/2/3, stage1/2 and reserved
slot capacity. The decoder never learns this identity or key material from ciphertext.
Capacity is248 bytes through512KiB, covering the canonical1024-range/65536-DIR64 budgets.
The current512KiB limit is a descriptor/envelope budget, not a code-subject byte limit.

The reference key is SHA-256 of `pyobf.native.code.reference.key.v1` plus NUL, the independent
identity encoded as `<16s16sIIIII>`, then eight private LE32 path-fold words. Every identity
byte and all eight material words influence authentication. Identity is snapshotted before
backend calls; encrypted package bytes and material are borrowed through the synchronous
call and must remain valid and immutable during it.

The existing bootstrap performs its release fold event before content-key reconstruction
and decryption; its immutable contribution snapshot is published after authentication.
This offers material for a pre-decrypt and post-load owner without using a final code hash
as a code-generation input. Stage IDs provide key-domain separation. They do not establish
runtime readiness: actual context phase, subject availability and stage-authorized use must
still be enforced by the production provider integration.

`pack_archive.seal(records, keys=...)` adds an optional private host key input. The existing
default and CLI continue generating independent random keys. Code-reference construction
returns only the encrypted package, and does not emit a raw key or key-binding source.
The existing archive package ID, two distinct nonces, access tag and body tag remain in use.

## Payload and owned native result

One archive bytes record occupies the fixed slot. Its plaintext starts with a104-byte header:
16-byte magic `PYOBF-CODEREF1` padded with two NULs; ten LE32 values(version1,header104,
canonical scheme1,kind,subject,owner,stage,range count,fixup count,image size); LE64 original
preferred base;32-byte expected digest;8 zero reserved bytes. Ascending range RVA/size pairs
and DIR64 RVAs follow, then zero padding. The archive overhead is136 bytes.

The decoder validates its exact single-record profile, derives a transient key, authenticates
and decrypts through existing archive operations, then validates the typed payload. It owns
new range/fixup arrays and the expected digest. C++ array lifetimes use non-allocating placement
array construction, following [CWG2382](https://cplusplus.github.io/CWG/issues/2382.html);
fault allocation guards also check that construction/erasure stay within the allocated size.
All common-code system operations use the existing backend macros.

The move-only `Reference` retires moved-from metadata and releases a previously owned result
on replacement. Reset clears public views/digest/status before erasing and releasing owned
storage. Temporary plaintext and derived keys are erased on success and failure, including
dirty crypto output and allocation failure. Each open uses its own local archive cache;
separate calls do not share decoded metadata or cache authority.

`Reference::status()==ok` means authenticated, structurally admitted reference metadata.
It does not mean the running code matches. The consumer must separately acquire actual code
and use that evidence through the required protected computation. An authenticated reference
with a deliberately different digest remains different from the observed code; the decoder
never adopts the observed value as a new reference.

Reference views last through the owning object. Callers serialize moves/reset and borrowed
view use; this is not a cross-DLL C++ object ABI. The encrypted package may be retired after
open returns. The reference itself does not pin a subject module: actual `Capture` owns that
lease, and the production context/provider must maintain its own module/epoch relationship.

## Source and test map

| File/group under `native/` | Responsibility |
| --- | --- |
| `tools/reference_identity.py` | Independent identity admission, LE framing and path-word key domain |
| `tools/code_reference.py` | Actual final canonical digest/descriptor payload and existing archive sealing |
| `tools/pack_archive.py` | Existing envelope, nonce/tag generation and optional supplied private keys |
| `src/measurement/reference.hpp`, `reference_internal.hpp` | Private move-owned API, status/identity and format bounds |
| `src/measurement/reference_owner.cpp` | Ownership transfer, views, reset and erasure |
| `src/measurement/reference_key.cpp` | Independent identity validation and transient key derivation |
| `src/measurement/reference_payload.cpp` | Header/identity/range/fixup/padding admission and typed array ownership |
| `src/measurement/reference_decode.cpp` | Archive profile, authentication, cleanup and final result publication |
| `src/archive/{format,acquire}.cpp` | Reused typed archive parser, access/body authentication and local cache |
| `measurement/{CMakeLists.txt,Checks.cmake}` | Private source target and separate reference/CFF test registration |
| `tests/measurement/reference_probe.cpp`, `check_reference.py` | Real CNG reference/code roundtrips, independent inputs, moves/concurrency and retired ciphertext |
| `tests/measurement/reference_cases.py` | Identity/material/tag/body/descriptor mutations and observed-code mismatch |
| `tests/measurement/reference_faults.cpp`, `failure_{fixture.hpp,backend.cpp}` | Reused allocation/erasure fixture with key-watch hooks, guards, OOM and reentry |
| `tests/measurement/check_reference_cff.py` |36 authored reference/archive/capture functions, real/fault final images and plain-image refusal |
| `tests/measurement/measure_reference.py` | Optional paired decode/destruction costs on the same sealed descriptor, reusing existing build/size helpers |

Tests use test-only metadata/package files to deliver independent identities/material.
Production code does not read those files. Actual EXE/DLL section, interval and closed-function
references run under Clang and source-only MSVC; none/O2 CFF compositions exercise36 authored
bodies(Reference15,Archive9,Capture12) with real and fault backends. Independent opens retain
distinct typed storage, including four concurrent calls. Faults cover hash output, plaintext
and typed allocation, access/body authentication, dirty outputs and reentry during outer decode.

The CFF driver accepts optional `--measure-output <json>`. Its existing actual/plain binaries
decode the same4096-byte descriptor in seven batches of32 groups, with one or four sequential
independent opens and destruction per group. Native code observation remains outside timing.
Both binaries run the real record/code contract first; the protected image passes the same
final CFF checker. Results include compiler, input IR/object, sample, package and image digests.
These are raw codec costs; integrated owner-cache, startup and full release costs remain open.

## Remaining protection boundary

The build owner and caller-provided identity/path material remain trusted inputs. Local
envelopes and keys raise static recovery cost; they are not hardware/issuer attestation or
a promise that in-process runtime hooks cannot observe plaintext or keys. The raw reader
still requires stable mapped code during its call.

Final code must be frozen after instrumentation/linking before hashing. The
[reserved reference finalizer](NATIVE_REFERENCE_SLOTS.md) now fills only pre-reserved
non-executable data, proves code/layout unchanged and binds early selection/record identities.
Production function-selection handoff and provider/bootstrap release integration remain open.
The private [owned observation runtime](NATIVE_OBSERVATIONS.md) now supplies independent
value caches, epochs/freshness, late-publication rejection and retained module lifetime.
Production stage/provider integration, final owner anti-merge evidence, actual uncancelled
CFF influence, D5 release consumers and D8 acceptance remain open.
