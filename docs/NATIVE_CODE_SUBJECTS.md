# Canonical native code subject tooling

The current D7 foundation supplies host reference/observation models for bounded unsigned
AMD64 PE images. The separate [private native capture](NATIVE_CODE_CAPTURE.md) now implements
the raw Windows reader prerequisite. Owned cache, freshness policy, authenticated reference
records and measurement-bound CFF corrections remain open. The existing
[ordinary contribution consumer](NATIVE_PAYLOAD_BINDING.md) remains based on its private fold.

## Modules and subject scopes

`tools/pe_layout.py` owns the shared bounded image layout, RVA reads and data-directory
access. The release finalizer reuses its unchanged legacy layout validation; the existing
64-byte release record,32-byte permitted write and unchanged-executable/layout proof retain
their semantics. The finalizer's CMake command declares the new transitive input.

`tools/code_subject.py` selects and validates explicit ascending non-overlapping ranges.
The host model limits one subject to1024 ranges and64 MiB. `.text` means its logical
`VirtualSize`, falling back to raw size when that field is zero. File alignment padding
beyond that logical extent is excluded explicitly. RVA reads supply zero-fill for declared
virtual bytes beyond initialized raw data. Subjects require readable executable sections
without writable/discardable flags. These are image-format restrictions, not a live memory
permission or environment detector. The PE field semantics follow Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

The second scope is one exact AMD64 `RUNTIME_FUNCTION` interval selected by its entry RVA.
It uses final exception-directory bounds and checks admitted unwind metadata, rather than
subtracting neighboring symbols. This is labelled `unwind-interval`, not a complete function
subject. Chained unwind/version variants and complete split/cold/thunk/alias ownership still
need their explicit closure implementation. Missing, interior or ambiguous entries fail.
See Microsoft's [x64 unwind format](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170).

The separate [closed function contribution producer](NATIVE_FUNCTION_SUBJECTS.md) supplies
kind3 subjects from explicit COFF ownership and exact final linked bytes, including admitted
leaf/private/EH and associated fragment/alias cases. It does not promote an arbitrary unwind
interval or generic range validation into complete-function ownership evidence.

## Canonical digest model

`tools/pe_relocations.py` parses bounded base-relocation blocks. Version1 admits ABSOLUTE
padding and DIR64 fields. Unknown kinds, malformed or overlapping fields and fields crossing
a subject boundary fail. `tools/code_observation.py` subtracts the supplied actual load delta
from each covered DIR64 field modulo2^64 before hashing. Other covered bytes remain exact.
This makes ordinary rebasing preserve the declared digest; it does not make changed code
acceptable or authenticate a caller-supplied descriptor/base/reader.

Scheme `pe-amd64-dir64-owner-sha256-v1` uses standard SHA-256 over:

1. `pyobf.native.code.observation.v1` followed by NUL.
2. Five LE32 values: scheme version1, kind(1 section/2 unwind interval/3 function contribution), nonzero subject tag,
   nonzero owner tag and range count.
3. Each range's LE32 RVA and size, in declared ascending order.
4. Each range's actual bytes, in that same order, after DIR64 normalization.

Each owner call starts its own digest and invokes its own reader. It never hashes a shared
base digest with a new salt. This host model demonstrates the required byte/framing semantics;
it does not prove native owner wrappers, storage or reads survive compiler/linker merging.
The reference helper reads the final build image. The observation helper takes mapped-byte
reads and a load base, with no expected-file-byte fallback or runtime baseline calibration.

## Verification and remaining integration

`pyobf_native_demo_code_subjects` links three real DLLs, keeps them loaded at distinct actual
bases and verifies a retained executable-section pointer relocation. One DLL has preferred
ImageBase zero: its logical build reference works while an actual null module base refuses.
For both `.text` and
an interval, two owner calls independently read actual mapped bytes and match build references.
LLVM independently supplies interval endpoints; a separately assembled standard digest frame
checks the model. The first two compiled code variants change digests with matching range geometry.
Typed/range/metadata/reader/relocation/unwind/padding controls cover failure and coverage limits.
The existing release-record tests still exercise native none/O2 and parent-IPO images,
43 malformed images, stale/idempotent/CLI paths and unchanged executable bytes/layout.

Remaining D7 requirements include complete function-fragment subjects, protected late
reference/correction records without build cycles, verified module-instance epochs beyond
the capture's target-module lifetime, independent owner wrappers/caches, scan-start freshness and late-publication rules,
mixed source CFF consumption, final anti-merge evidence and startup/reporting integration.
The local digest is not a secret or hardware/remote attestation. Reference-record identity
and integrity must prevent accepting a new observation as its own reference; that producer/
consumer contract is still required before the native binding emitter.
