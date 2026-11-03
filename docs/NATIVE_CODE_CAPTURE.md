# Private native code capture

The D7 reader prerequisite now executes canonical SHA-256 acquisition in native Windows
x64 code. It is a private C++17 source target, `pyobf_native_code_capture`, available with
the existing context runtime or demo when the backend admits code capture. It is not an
installed SDK or a cross-DLL C++ object ABI. The [host subject model](NATIVE_CODE_SUBJECTS.md)
defines the exact digest framing and current section/unwind-interval scopes.

## Ownership and acquisition

`capture(descriptor, member)` resolves an actual code address to its current-process module,
retains that module and checks its OS-derived extent, bounded mapped AMD64 PE headers and
section layout. Every requested byte must belong to exactly one readable executable,
non-writable, non-discardable logical section. Live pages must be committed `MEM_IMAGE`
pages of the retained module with `PAGE_EXECUTE_READ` protection and no guard flag.
The backend uses [module information](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation)
and [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery).
It does not discover modules by filename or search the filesystem for code bytes.

Descriptor arrays are immutable, borrowed inputs valid through the synchronous call.
Ranges, relocation fields, bounds and allocation budgets are checked before reading.
Each call allocates its own material, copies volatile mapped bytes, normalizes covered DIR64
fields and uses the existing backend CNG SHA-256 operation. No observed digest is reused by
another owner. All system operations in common code pass through semantic backend macros.

The original preferred base is a producer input. Windows may rewrite the mapped PE header's
ImageBase to the actual load base; that live header cannot recover the original link origin.
Normalization therefore subtracts actual-base minus original-preferred-base. Live-header
validation admits the original or actual base. The descriptor and original base still need
the protected reference producer/consumer contract; this reader does not authenticate them.

The move-only `Capture` retains the target module until reset/destruction. Moving clears
the source, and reset erases result data before releasing the module. Failed acquisition
returns a specific status with no digest or timing interval; material is erased before
release, including dirty-output hash and late-clock failures. Unexpected module-release
failure invokes the existing terminal protection-failure operation.
The consuming module containing these C++ methods must remain loaded through calls and
destruction. Self-unload and objects crossing a DLL boundary are not supported contracts.

Successful data includes kind, subject, owner, full digest, read start/completion and clock
frequency. The start sample precedes the first requested code read; completion follows
hashing. The Windows backend uses [QPC](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)
and [its frequency](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency).
Allocation and frame construction precede that interval. These samples do not implement a
consumption deadline, cache epoch or trusted wall clock.

## Source map and extension point

| File/group under `native/` | Responsibility |
| --- | --- |
| `src/measurement/types.hpp`, `capture.hpp` | Private bounded descriptors, status/data and move-owned result |
| `src/measurement/backend.hpp`, `internal.hpp` | Semantic platform boundary and internal algorithm declarations |
| `src/measurement/ownership.cpp` | Move/reset/destruction and result retirement |
| `src/measurement/validation.cpp` | Independent descriptor, range, fixup and mapped-view admission |
| `src/measurement/material.cpp` | Canonical framing, fresh byte copies and DIR64 normalization |
| `src/measurement/capture.cpp` | Acquisition order, clock/hash publication and failure cleanup |
| `backends/windows_user/measurement/module_view.cpp` | Current-process module pin, live PE/RX span checks and release |
| `backends/windows_user/measurement/clock.cpp` | QPC samples |
| `measurement/CMakeLists.txt`, `Checks.cmake` | Source target and separate CFF contracts |
| `tests/measurement/{descriptor.hpp,descriptor.cpp}` | Bounded test-only file exchange; no production reference-record format |
| `tests/measurement/{sample.cpp,probe.cpp,check_capture.py}` | Actual image/CNG/relocation, concurrency, move and unload verification |
| `tests/measurement/{failure_fixture.hpp,failure_backend.cpp,failures.cpp,check_failures.py}` | Fault injection, failure origins, erasure, reentry and terminal close refusal |
| `tests/measurement/{check_cff.py,CMakeLists.txt}` | Twelve authored core bodies through the existing CFF/final-image checker and source test wiring |
| `tests/measurement/{cost.cpp,measure_capture.py}` | Optional paired full-acquisition costs using the existing CFF build and size helpers |

A backend declares `CAN_CODE_CAPTURE` and its `CAPTURE_SOURCES` in its existing manifest,
implements the private semantic operations and supplies the existing memory/code-lifetime/
SHA-256 primitives. Unsupported backends leave the capability disabled. This stage adds no
detector/provider registration, public SDK command or extra platform implementation.

## Verification and remaining boundaries

`pyobf_native_code_capture` compares real native CNG output with final-build host references:
self EXE and two DLL variants, `.text` and explicit unwind interval, six owners per subject.
The DLLs contain a retained executable-section DIR64 pointer; GNU Clang additionally links
one at preferred base zero. Concurrent captures, move retirement, target pinning and last
lease unload execute against actual Windows modules. Missing modules, changed image extent,
non-code data and writable executable pages refuse without publishing partial results.

`pyobf_native_code_capture_failures` covers malformed ranges/fixups before acquisition,
unavailable/partial views, allocation/read/hash/start/end-clock failures, backward time,
frequency mismatch, dirty hash output, material/data erasure, reentry and terminal close
failure. `pyobf_native_code_capture_cff_none` and `_O2` protect all twelve source-authored
core bodies, execute the real contracts and verify their final linked images. An ordinary
unprotected core cannot borrow the protected report. Parent IPO covers ordinary surrounding
code; transformed objects remain outside later LTO under the existing CFF contract. Backend
OS primitives are separately compiled and are not claimed as twelve protected core bodies.
MSVC tests cover source-only acquisition/failures, not the LLVM pass.
Its test-only initialized pointer is explicitly merged into `.text`; LINK's LNK4254 warns
about differing code/data content flags. The resulting section must still pass RX admission.

The existing CFF test driver accepts optional `--measure-output <json>` to compare its plain
O2 core with its protected none/O2 core. Both measure the same loaded DLL's section and
interval, with one or four independently acquired owners, seven batches of32 groups.
Timing covers full acquisition and destruction, including module/heap/CNG/erasure costs;
the harness's steady-state reference check is included in both sides. It is a local cost
fixture, not a startup/cache benchmark or a security reference established from runtime bytes.
Results include sample/IR/object and actual benchmark-image digests plus compiler identity.
The protected benchmark image also passes the existing final CFF checker.

This unit does not compare an observation with an authenticated expected reference and
does not bind it to a release key or transition. Complete function/fragment closure,
protected late records, independent per-owner wrappers/cache storage and anti-merge proof,
instance/context epochs, freshness/late-publication policy, challenge metadata and mixed
CFF source consumption remain required D7 work. The ordinary
[payload contribution consumer](NATIVE_PAYLOAD_BINDING.md) retains its current private fold.
The [function contribution producer](NATIVE_FUNCTION_SUBJECTS.md) now supplies admitted kind3
ownership scopes and real native checks. General production function selection/reference
integration, independent owner/cache-policy and full release costs remain pending.
The [authenticated reference codec](NATIVE_CODE_REFERENCES.md) now supplies independently
keyed, move-owned metadata; production finalization and protected consumption remain separate.

Module retention prevents ordinary unload, not simultaneous writes, remapping or page
protection changes by another actor. RX checks and volatile reads are not an atomic snapshot
or a fault-isolation boundary; the current capture requires stable mapped code during its
call. No runtime baseline calibration, shared cache, machine authorization, tamper-proof
clock or remote attestation is claimed. Final code measurement must follow instrumentation
and linking, then change only reserved non-executable reference data to avoid hash cycles.
