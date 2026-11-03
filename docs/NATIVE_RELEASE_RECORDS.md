# Native fixed release records

The Windows demo now packages its finalized inner DLL with a random AES-GCM key and emits
only ciphertext, nonce and tag in its payload header. Runtime reconstruction consumes the
actual context fold and a masked record. The key is no longer a `packed::key` array. This is
local white-box obfuscation: recovering the event/data path still recovers the key. It does
not authenticate a device, protect against runtime extraction or close the loader's
temporary-file replacement window.

## Private build input and runtime consumption

The demo first uses `prepare_release_material.py` to generate independent private events and
their matching numeric C++ header. The [strict payload consumer](NATIVE_PAYLOAD_BINDING.md)
can use their fold before compiling its executable corrections. After final child verification,
`prepare_release.py --material <early.json>` validates that existing header and writes only
the late versioned plan, binding exact child image/report SHA-256 digests. It does not rewrite
the upstream header. The original child-first CLI still generates a new plan and header.
The inputs supply an unsigned32 seed plus three distinct event tags and words.
The strict parser rejects unknown/missing/duplicate fields, invalid
types or widths and oversized input. Seed/tag/word values are private build inputs, not a
new cryptographic trust root. Legacy child-first generation rotates the transcript;
the two-phase build retains its early root until generation inputs or outputs change.
Child-source changes alone do not rotate that root. Each package still uses a fresh key/nonce.

`pack_payload.py` checks the exact plan/child/report/header relationship before emitting
ciphertext and a64-byte masked record. Its old raw-key CLI has no fallback. The independent
Python reference computes the producer fold; runtime never loads that expected value.
`bootstrap/key_material.cpp` supplies the external record and actual fold to the selected
`key_expansion.cpp` helper. It validates the record, serializes the actual eight
runtime words in little-endian order, expands them through the backend SHA-256 macro and
XORs the mask. Four required marker sites bind initialization and the environment, support
and release events to actual CFF state. Their local values do not prove a genuine hardware
observation or measured L2 readiness.

The release function owns the32-byte key buffer. Serialized fold material is erased after
hashing, including failure, and the reconstructed key is erased/freed immediately after
AEAD, before observer stage2. SHA-256 failure returns-8 before decryption; wrong reconstructed
keys return-4 before loader/entry. Existing cleanup also erases plaintext on all owned exits.
The OFF profile links ordinary marker arithmetic and still reconstructs the key, but does
not receive CFF state binding or outer-coverage credit. There is no expected-fold/digest
runtime global or raw-key fallback in either profile.

Plans, generated headers, child plaintext, transformed IR and diagnostic fold checkpoints
belong only to the private build tree. Tests capture checkpoints privately and redact their
lines from user-visible diagnostics. The public source/format alone no longer supplies a
fixed startup transcript; reverse engineering a specific build remains possible.

## Record and expansion

| Byte offset | Size | Field |
| --- | --- | --- |
| 0 | 16 | ASCII `PYOBF-RELKEY-v1` followed by NUL |
| 16 | 4 | Little-endian version1 |
| 20 | 4 | Little-endian record size64 |
| 24 | 32 | Content key XOR expansion |
| 56 | 8 | Reserved zero bytes |

Expansion is SHA-256 of `pyobf.native.release.fold.v1` followed by NUL and the canonical
32-byte [fold serialization](NATIVE_PATH_FOLD.md). The producer accepts exactly32 key bytes
and eight unsigned32 fold words. The record has no raw-key field. The algorithm and format
are public. Production event descriptors must vary per build and remain private build inputs
consumed by state-dependent emission; reusing the fixed source fixture transcript would let
an attacker compute the expansion directly from this open repository. Recovered descriptors
and masks remain reconstructable by an attacker who recovers the data path; this is local
obfuscation material, with no issuer or unforgeability claim. The separately verified
Windows SHA-256 backend performs runtime reconstruction through its semantic macro.

## Ordered compilation and filling

Protected code includes only `src/release/record.hpp` and its external declaration. Compile
the Windows `release_record.cpp` separately to a native non-LTO object. It contains one
zero-mask record in a readable, non-writable, non-executable `.pyobf` section. The initializer
must stay outside the protected input and any later optimizer's definition visibility.
The fixture checks the actual COFF object, LLVM section inspection and loaded record bytes.

After linking freezes code and layout, fill only the32 mask bytes at the reserved offset.
The finalizer compares every byte outside that range, the header/section geometry and all
executable raw ranges. Its report binds before/after image and record SHA-256 digests without
printing content-key or mask values. Identical material is idempotent; a record containing
different previously finalized material rejects. Final CFF/image inspection must run after
filling, and parent packaging must consume that exact verified image. Reference-dependent
recompilation or relinking remains prohibited.

The demo's build DAG is child final image/report -> private plan/header -> ciphertext/record
-> outer CFF/native raw link -> data-only finalized copy -> exact final CFF report. Native
record storage stays outside protected IR and parent IPO. The raw target does not depend on
the record blob, so a future measured-code-dependent mask cannot cause a relinking cycle.
Public `pyobf_native_demo_outer` and `_triggered` targets are buildable aggregates, with
`PYOBF_NATIVE_FINAL_IMAGE` naming the distributed DLL and `PYOBF_NATIVE_UNFINALIZED_TARGET`
naming the private SHARED target. `$<TARGET_FILE:...>` applies only to the latter. Final
filenames and `cmake --build ... --target pyobf_native_demo_outer` remain stable. Raw images
live under `demo/unfinalized`; they have zero mask placeholders and are not release artifacts.

The current PE adapter accepts unsigned, zero-checksum AMD64 PE32+ GUI/console images with
at most96 sections, power-of-two file alignment512 through65536, and section alignment of
at least4096. The dedicated section has virtual size64 and zero raw alignment padding.
Duplicate sections, malformed headers, writable/executable/discardable/uninitialized records,
raw or virtual overlap, out-of-range data and stale material reject. Checksumming and signing
follow finalization. Other formats, driver profiles and general PE loading/signing validation
remain separate backends. The finalizer does not supply executed-image authenticity or D7
relocation-aware code measurement.

```powershell
.venv/Scripts/python.exe native/tools/finalize_release.py `
  linked.exe release-record.bin finalized.exe --report finalization.json
```

Output may equal the input image for in-place completion. Replacing the input record or
aliasing the report with an input/output path rejects. Validated outputs use a same-directory
temporary file and replacement. An I/O failure between image and report writes can leave a
valid filled image without its new report; report identity remains a required downstream gate.
The host artifact helper bounds Windows access/sharing/lock errors5/32/33 to eight attempts
per replace/unlink operation, with at most315ms of scheduled waits. The validated temporary
bytes stay unchanged across replacement attempts. Persistent failures and all other errors
remain visible; POSIX errors do not receive this Windows policy. Stale artifacts never become
accepted output. This affects build I/O only; authenticated runtime release remains one attempt.

## Files and evidence

| Files | Responsibility |
| --- | --- |
| `native/src/release/record.hpp` | Private fixed-layout declaration and size/offset assertions |
| `native/backends/windows_user/release_record.cpp` | Separate native read-only zero-placeholder definition |
| `native/tools/release_format.py` | Strict host format, canonical SHA-256 expansion and key masking |
| `native/tools/pe_release_record.py` | Bounded PE geometry/record validation, data-only filling and identity report |
| `native/tools/finalize_release.py`, `atomic_artifact.py` | CLI path checks, expected-error boundary and shared atomic artifact replacement |
| `native/tools/release_plan.py`, `prepare_release.py` | Strict private plan, exact child/report identity, generated input and independent reference |
| `native/demo/pack_payload.py`, `cmake/Packaging.cmake` | No-raw-key packer and ordered per-domain build integration |
| `native/demo/bootstrap/key_material.cpp`, `key_expansion.{hpp,cpp}` | Real-context adapter, shared record validation/actual-fold expansion and unmasking through backend macros |
| `native/demo/check_release_plan.py` | Fresh inputs, strict/stale/header/legacy guards, producer AEAD and exact current raw/final/report checks |
| `native/demo/release_flow_mutations.py`, `release_fault_smoke.cpp`, `session_build.py` | Isolated post-emission faults, zero-loader/entry assertions and real native crypto/record support |
| `native/tests/release_record.cpp` | Actual loaded native record bytes |
| `native/tests/release_record_cases.py` | Malformed images derived independently from linked headers |
| `native/tests/check_atomic_artifact.py` | Actual Windows transient/persistent shared handles, unknown-error output preservation and fixed retry-budget checks |
| `native/demo/check_release_record.py`, `cmake/ReleaseChecks.cmake` | Native none/O2/parent-IPO, LLVM inspection, loaded before/after bytes, host/CLI/stale and layout checks |

The `pyobf_native_demo_release_record` test compiles a native record object and two real PE
executables, fills and runs them, checks independent LLVM section metadata, and exercises
malformed input and output-preservation cases. The separate `pyobf_native_demo_release_plan`
test checks fresh same-child descriptors, actual generated C++ values, strict/stale inputs,
no raw-key fallback, producer AEAD round trips and exact current raw/final image/report bytes.

The session CFF tests execute19 named runtime faults after emission, bypassing the plugin's
build-time proof: four omitted event updates, four changed current-state reads, three duplicate
events, a forced support result, two forced support checks, a forced key-helper result,
a forced failed-hash result, reordered events, a changed fold lane, a wrong generation and
a foreign expected context. The15 actual LLVM edits pass the LLVM verifier before direct
native compilation. Sixteen cases reach real CNG AES-GCM and refuse authentication; three
fail earlier lifecycle/identity gates. All assert zero loader calls and zero real-entry calls.
The tests observe key/serialization erasure and preserve OOM, observer-exception and protocol
checks. They are bounded regression evidence, not proof against every arbitrary binary patch,
cryptographic collision or runtime observation. Measured L2, optional full decoy, D6 oracle
and D7 integrity remain separate unfinished work.
The [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
defines the section offsets, raw/virtual extents and flags used by this adapter.
