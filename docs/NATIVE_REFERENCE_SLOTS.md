# Reserved code-reference finalization

The private Windows x64 build seam reserves read-only `.pyobm` data before compiling an
observing module. It hashes final code and fills only ciphertext slots after linking.
The [reference codec](NATIVE_CODE_REFERENCES.md) format and
[canonical subjects](NATIVE_CODE_SUBJECTS.md) are unchanged. This is build tooling with actual
native reference and [invocation Scope](NATIVE_MEASURED_KEYS.md) consumers. The opt-in
[two-role L4 handoff](NATIVE_PAYLOAD_BINDING.md#opt-in-post-release-code-observations) uses
these slots; configured/generated independent owner integration remains required.

## Early selection and identity

`prepare_references.py plan.json reference_slots.hpp reference_slots.cpp` accepts strict
JSON with exactly `schema_version: 1`, a nonzero16-byte lowercase-hex `build_seed`, a
nonzero16-byte lowercase-hex `container` role, and1..64 `records`. Each record has exactly
`image` (target role hex), `owner`, `subject`, `kind`, `stage`, `capacity`, `selector`.
Owner/subject are nonzero unsigned32; stage is1 or2, capacity248..524288 bytes.

| Kind | Symbolic selector | Final producer requirement |
| --- | --- | --- |
|1 | `{"section": ".text"}` | One stable readable/executable `.text` |
|2 | `{"symbol": "exact_name"}` | Retained final COFF symbol and exact AMD64 unwind interval |
|3 | `{"symbol": "root", "aliases": [], "fragments": []}` | Actual final classic non-LTO compiler object plus retained PE symbols and explicit closed ownership |

The effective16-byte build identity is the prefix of SHA256 over
`pyobf.native.code.reference.build.v1\0` plus canonical sorted compact ASCII JSON of the
entire plan. The full plan SHA256 is also stored. Record order is significant. Changing a
selector, role, capacity or any other plan input changes independently compiled identities;
the code does not learn its expected identity from the storage directory. No final code
digest, address, length or private path words feed the generated source.

The opt-in schema2 adds exactly `scope_materials`, a nonempty ascending list of distinct
record indices. Every selected index must name a stage2 record; an unselected record remains
a reference only. The entire selection participates in the early build identity. Schema1
does not accept this field and keeps its original directory/header/source bytes.

The generated header exposes private `measurement::reserved::{data,size,count,offsets,identities}`.
Only the prefix is emitted as source initializer; C++ zero-initializes the full reserved array.
Compile that source separately without LTO. Compile the observing consumer against the header.
MSVC allocation pragmas and GNU section attributes are supplied; this unit's execution/CFF
pipeline is validated on Windows CLANG64. Other target backends remain unimplemented.
The source-only MSVC placement probe also compiles the generated store, admits its actual PE,
fills data without changing code and executes raw/final images. It does not repeat native
codec/runtime validation. The local MSVC probe uses the existing project's
`CMAKE_SUPPRESS_REGENERATION=ON` policy and explicit reconfiguration after CMake changes.
That placement evidence is for schema1; the scoped schema2 consumer is tested with CLANG64
and its ThinLTO/IPO configuration.

## Fixed storage and late fill

The64-byte header contains16-byte magic `PYOBF-REFSLOT1\0\0`, version/count/total/reserved
unsigned32 values and full plan SHA256. Each64-byte directory entry contains the codec's
52-byte independent identity, slot offset and8 reserved zero bytes. Slots start on16-byte
boundaries and retain their declared capacities. Alignment gaps and raw file padding are zero.

Store-v2 uses magic `PYOBF-REFSLOT2\0\0` and version2 with the same64-byte header and entries.
Its entry contains52-byte identity, reference offset, material offset and4 reserved zero bytes.
A nonzero material offset reserves168 bytes for an existing one-record32-byte AEAD archive;
zero denotes an unselected index. Material and reference slots are separately aligned and
checked. Only schema2 headers expose `reserved::{material_size,material_offsets}`; the
consumer's independently compiled offsets never come from the runtime directory.

`finalize_references.py image plan material output --report report.json` reads the existing
private [release material](NATIVE_RELEASE_RECORDS.md). `material_fold` supplies the eight
private words. External artifacts use repeated `--target role_hex=path`; each function record
needs `--object record_index=path`. Missing, duplicate and foreign bindings are errors.
The observing image is selected by its container role; it is never supplied as an external
target. All target artifacts/objects are immutable snapshots during the synchronous operation.

For schema2, provide exactly the selected early32-byte materials with repeated
`--scope-material record_index=path`. Missing, extra, duplicate, noncanonical or wrong-size
bindings fail. These private build inputs do not enter generated instructions or distributed
reports. Each material is sealed using the complete observed-code/identity/fold key and Scope
domain described in the measured-key guide. Different owners cannot exchange these envelopes.
The caller still fixes its expected contribution material before compiling its CFF constants.

The finalizer rejects duplicate/mismatched storage, writable/shared/executable/discardable/
uninitialized sections, loader-directory overlap, DIR64 writes into the store, nonzero gaps
and padding, and an incorrect early plan. It resolves symbolic selections only after final
code generation, validates closed function bytes against the actual object, computes canonical
references and seals zero slots with the existing archive AEAD. A nonzero slot must authenticate
and equal the complete current canonical payload. Stale or altered slots are rejected; repeat
finalization preserves ciphertext exactly rather than generating new random envelopes.

The shared `pe_data_patch.py` proves unchanged length, parsed PE layout, all executable raw
bytes and every byte outside the explicit slot writes. The legacy release-mask finalizer
uses the same proof and preserves its prior format/report/stale behavior. Self references
are recomputed after filling to prove no code/hash feedback. Reports record plan, exact input,
target, function object, ciphertext and output SHA256, range identities and write regions;
they contain no private path words or keys. Input hashes in an idempotent report describe that
invocation's input, so reports need not be byte-identical even when the image is unchanged.

Outputs/report must not resolve to each other or any input. Writes use existing atomic artifact
replacement; a failed build is not a valid finalized output. Signing/checksumming must occur
after finalization and requires the separate downstream canonicalization contract.

## CMake seam and build order

Include `native/cmake/ReferenceSlots.cmake`, call
`pyobf_native_reference_storage(raw_target plan)`, then
`pyobf_native_finalize_references(final_target raw_target material output report
TARGETS role=path OBJECTS index=path DEPENDS producer_targets)`.
The first helper creates a separate non-LTO object and ensures its generated header exists
before compiling the consumer. The second declares plan/material/artifact/object and transitive
tool dependencies. Generator-expression paths may be used for artifacts; declare their producer
targets through `DEPENDS` where required. It does not change a consumer's CFF recipe or flags.

Order: immutable early plan -> compile instrumentation/CFF -> final linked code/object inventory
-> reference data fill -> exact-image verification -> packaging -> parent use. Repeating an
unchanged dependency chain performs no work; changing early identity recompiles consumers,
while late private material changes refill raw zero slots without changing code generation.
The tested pipeline also refuses a missing object rather than reusing old finalized output.
For schema2, add `SCOPE_MATERIALS index=path ...` to the same finalization helper. Material
files are real dependencies: changing one refills data without recompiling the observing
module; deleting one prevents stale output from being accepted. No new runtime SDK or
separate finalization service is introduced.

This single-observer seam accepts self code and fixed external targets without reference stores.
An external `.pyobm` is rejected: admitting interdependent observers requires an explicit
topological/batch contract. Iterative regeneration, cyclic full-file/report hashes and code
generation from a final measured digest are not supported. Do not bypass this check by removing
the store. Production function-selection/codegen handoff and multi-observer finalization remain
required D7 work; this document does not close that stage.

## Files and evidence

| File under `native/` | Responsibility |
| --- | --- |
| `tools/reference_plan.py` | Strict immutable symbolic selection and pre-codegen build identity |
| `tools/reference_slots.py` | Storage layout, independent header/source emission and PE admission |
| `tools/prepare_references.py` | Bounded-plan preparation CLI and atomic artifacts |
| `tools/finalize_references.py` | Exact artifact selection, stale/authentication checks, data fill and report CLI |
| `tools/code_reference.py` | Existing codec plus authenticated comparison of filled slots |
| `tools/pack_archive.py`, `measured_scope.py` | Shared exact typed-bytes authentication and full-observation scoped-material sealing/verification |
| `tools/pe_data_patch.py` | Shared exact data-only write proof |
| `cmake/ReferenceSlots.cmake` | Private preparation/object/finalization dependency seam |
| `tests/measurement/slot_probe.cpp` | Compiled identities, actual stored-reference decode and live code captures |
| `tests/measurement/check_slots.py` | Actual self/external/function storage, CLI, idempotence and native substitution negatives |
| `tests/measurement/slot_cases.py` | Independent plan/layout/authentication/stale/code/cycle/patch refusals |
| `tests/measurement/slot_pipeline.py` | CMake early/late dependency, missing object and no-change checks |
| `tests/measurement/check_scope_slots.py`, `scope_slot_probe.cpp` | Actual schema2 self/external observation and Scope word consumer; ciphertext/cross-owner no-word negatives |
| `tests/measurement/scope_slot_cases.py` | Frozen schema1 bytes and schema2 selection/authentication/replay/stale/CLI/alias controls |
| `tests/measurement/scope_slot_inputs.py` | Existing independent host word reference applied to each fixture owner |

The standalone CTest is `pyobf_native_code_reference_slots`. Existing reference CFF tests
also execute the stored-reference consumer and verify its actual final image against all36
authored Reference/Archive/Capture bodies, under source-none/O2 and the parent-IPO profile.
The unfilled image fails; changed final code reaches a specific observation mismatch. Replacing
the plan header and resealing using another identity still fails the original compiled
expectation. These controls do not establish provider readiness or force a CFF edge to consume
the digest. Independent owner reads/caches, epochs/freshness/late publication, anti-merge and
uncancelled CFF contribution influence remain open, as do D5/D6 release closure and D8 acceptance.

`pyobf_native_code_material_slots` exercises schema2 against actual self `.text`, external
unwind and closed-function references. Selected owners use real per-use Scope/CNG queries
with independent host word expectations; unselected records have no material. It also tests
exact permitted writes, authenticated idempotence, ciphertext/cross-owner refusal and the
existing CMake early/late/missing/no-change chains. This data-placement unit does not complete
the production two-role L4 handoff, generated owner anti-merge or all policy/source combinations.
