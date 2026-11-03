# Closed native function contributions

The D7 producer foundation can now construct canonical kind3 `function-contribution`
subjects from a classic AMD64 COFF object and its actual final unsigned PE image. It reads
whole compiler-owned input contributions and verifies their exact linked bytes. This
extends the [section/interval model](NATIVE_CODE_SUBJECTS.md); it does not infer a function
length from adjacent symbols or require every leaf to have `.pdata`.

## Extents and explicit ownership

An admitted root is one offset-zero typed function definition in its own code contribution.
The COFF section header and unique auxiliary section definition must agree on size and
relocation count. Microsoft defines the auxiliary section length as the section data size
in its [PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-5-section-definitions).
Declared literals/padding inside that input code contribution are covered; independent
linker padding between contributions is excluded explicitly.

`function_subject(object_bytes, final_bytes, image, tag, root, aliases=(), fragments=())`
requires exact alias and executable-fragment inventories. Root aliases must share their
declared object body and final address. Fragment sections must have an explicit associative
COMDAT ownership path to the root; section names are not ownership evidence. Associations
must terminate without cycles. Each included code contribution has offset-zero typed
anchors, stable RX flags and exact final symbol mapping. Sorted disjoint final ranges can
be adjacent or separated. Missing/unaccounted fragments, a detached alias, another function
inside an extent and undeclared final folding refuse.

The producer must freeze its required alias/fragment inventory from its compiler/source
contract. The tool cannot discover an arbitrary outlined function's semantic parent from
its name. Unassociated outlining is unsupported; removing a declared fragment's association
fails its required inventory. A helper call or ordinary OS import thunk is a separate callee,
not implicitly part of a function's byte range. A declared compiler-associated executable
thunk uses the same closure as other fragments.

## Exact link fixups and input boundary

Every admitted AMD64 ADDR64, ADDR32, ADDR32NB or REL32/REL32_1..5 field is evaluated against
actual final target symbols and its original addend. The resulting whole span must equal
the final image. Fields must be bounded and non-overlapping; unknown types, unexplained
byte changes and missing/ambiguous targets fail. No relocation bytes are merely masked.
Runtime DIR64 rebasing remains the separate canonicalization step in the native reader.
Address32 fields retain their low32 bits, including negative addends; REL32 fields must
fit the signed displacement. The actual-link fixture exercises every admitted kind.
ADDR32 code also introduces HIGHLOW base relocations: canonical v1 refuses that image
explicitly rather than treating it as DIR64-compatible native measurement.

Section-relative references to initialized or uninitialized data use retained data labels
from the same actual input contribution. Each available unambiguous label must imply the
same final base after subtracting its input offset, and the entire input contribution must
fit one final virtual section. This also admits BSS and a sole nonzero-offset label without
inventing file bytes. Conflicting bases, missing usable labels and overflowing extents refuse.
This maps relocation addresses only: mutable data is not included in the code subject.
Exact linked-code comparison remains required after every fixup is evaluated.

This provider currently needs retained final COFF symbols and a non-LTO classic object with
the requested closed contributions. Missing/private-stripped symbols, bigobj and unsupported
ownership/link rewrites fail explicitly. Object and final symbol/string spans are bounded;
raw code spans cannot overlap file metadata. The initial resource limits are128MiB/object,
8192 sections,2^20 symbol slots and the existing1024-range/64MiB subject budgets.

The object, compiler policy and expected inventory are trusted build inputs. Generic range
validation and a caller-created `Subject` are not ownership authentication. Runtime
descriptors remain raw inputs to the [private native capture](NATIVE_CODE_CAPTURE.md).
[Reserved authenticated records](NATIVE_REFERENCE_SLOTS.md) now carry final subjects; runtime
provider and measurement-bound correction remain required. General function selection and
its pre-link frozen metadata handoff remain pending integration.
Code generation/instrumentation must finish before reference calculation; late reference
data must not regenerate measured instructions.

## Production object emission

`pyobf_native_emit_object(output input FUNCTION_SECTIONS)` opts into separate compiler
function contributions through `cmake/LLVMCompile.cmake`. The existing two-argument form
keeps its prior command. Both forms end IR transformation before native `-O0 -fno-lto`
codegen, including under a parent IPO build. Unknown emission arguments fail configuration.
This private build seam does not create a new SDK or automatically measure all functions.

The current Windows GNU-Clang producer uses `-ffunction-sections`; actual classic COFF
ownership and complete final bytes remain the acceptance boundary. A separate-section flag
cannot substitute for alias/fragment inventory, protect against arbitrary link rewrites or
admit a pre-CFF object. Existing unconfigured emitters are unaffected. Other compiler/backend
function ownership and selection handoffs remain unsupported until their producer is defined.

## Modules and verification

| File/group under `native/` | Responsibility |
| --- | --- |
| `tools/coff_symbols.py` | Bounded classic symbol/string decoding for object and final image |
| `tools/coff_layout.py` | Object sections/auxiliary agreement, raw spans, relocation indices and acyclic ownership |
| `tools/coff_relocations.py` | Exact final target resolution and admitted link-fixup evaluation |
| `tools/function_subject.py` | Required aliases/fragments, final code identity and complete owned ranges |
| `cmake/LLVMCompile.cmake` | Existing default/native IPO boundary plus explicit function-section emission |
| `tests/measurement/function_fixture.cpp`, `function_fragments.s` | Real private/leaf/GNU-EH functions and associative cold/alias/literal fixture |
| `tests/measurement/check_functions.py`, `function_cases.py` | Independent LLVM extent checks, live CNG reads and actual object/image mutations |
| `tests/measurement/function_icf.s`, `function_icf.py` | Same-object LLD ICF-off/on counterpart, live address identity and folded-subject refusal |
| `tests/measurement/function_relocations.s`, `function_relocations.py` | Actual-link ADDR64/ADDR32/ADDR32NB and REL32_0..5 fields, signed addends and explicit HIGHLOW canonicalization refusal |
| `tests/measurement/function_data_fixture.cpp`, `function_data_targets.py` | Real O0/O2 BSS/writable/readonly section targets, live execution/CNG capture and missing/conflicting/overflowing data-label refusals |
| `tests/measurement/function_cff.py` | Actual complete CFF getter/validator byte subjects and pre-instrumentation reference refusal |
| `tests/measurement/function_emission.py` | Production CMake emitter, exact old/default and function/direct object equivalence, no-change and unknown-option refusal |

`pyobf_native_code_function_subjects` uses the existing native capture harness: five subjects,
six owners each, including a leaf without `.pdata`, private code, GNU EH and a root with
associated cold bytes plus DIR64 and RVA literals. LLVM independently decodes contribution
lengths; a separately framed kind3 digest checks the scheme. Invalid header/symbol/section/
fixup metadata, changed instructions/fixup targets, missing/shifted aliases, lost fragment
ownership, writable code and stripped symbols are exercised against the production tools.

The ICF fixture must first prove different addresses with folding off and the same actual
loaded addresses with folding on. Both folded function subjects refuse. Its assembly uses
matching COMDAT section names; unique named C++ sections did not actually fold in the tested
LLD22 profile. LLD compares section names as part of
[ICF equivalence](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.0/lld/COFF/ICF.cpp#L137).
The normal capture CFF tests also read full protected getter/validator subjects under source
none/O2 and parent IPO, and refuse the pre-CFF object as a reference for changed final code.
Their function objects now come from the production CMake helper. The default helper object
must exactly equal its pre-existing direct counterpart; the function object must exactly equal
the established direct function-section command. Unchanged builds preserve object bytes and
timestamps. Shared-section objects and a misspelled required option are rejected. These checks
exercise the emitted object in the live CNG reader, not just a generated-command report.
This does not establish independent owner cache/anti-merge authority or close D7's reference,
freshness, production selection, CFF consumption and startup/reporting work.
The separate [generated-subject producer](NATIVE_GENERATED_SUBJECTS.md) now composes explicit
compiler-owned helpers with this physical primitive; it does not infer ordinary callees.

## Early post-role host selection

`tools/post_reference_plan.py --subjects FILE` accepts schema1 JSON with exact `parent`
and `child` entries. Each has `kind` and `selector`: kind1 uses `{"section":".text"}`;
kind3 uses `{"symbol":"exact_name","aliases":[],"fragments":[]}`. Unwind intervals are
not admitted as complete functions. The existing plan parser validates these selectors,
and their canonical bytes contribute to the build identity before storage/code generation.
Omitting the file preserves the existing two-section plan byte for byte.

`tools/finalize_post_release.py --subjects FILE --object INDEX=PATH` requires that same
early selection and an exact actual-object binding for every kind3 record, with no surplus
objects. Indices include the optional leading pre-release record. It reuses the existing
reference producer and data-write proof; late selector changes, foreign/changed code and
missing objects refuse. The optional production CMake setting
`PYOBF_NATIVE_DEMO_POST_SUBJECTS=/absolute/path/to/subjects.json` forwards the same early
selection. It requires `PYOBF_NATIVE_DEMO_POST_CODE_HASH=ON`. The default empty setting keeps
the existing two-section plan and object emission. The checked-in
`native/demo/recipes/post_functions.json` selects the authored parent initialization
function and the child's bound computation; it uses GNU-Clang symbol names.

Only a function-selected role enables function-section emission. With outer CFF disabled,
the selected parent's authored units are combined into one explicit non-LTO native object
without running CFF. Backend and marker callees stay separately linked. Runtime fault
probes and same-source cost pairs use their actual newly linked parent objects when code
changes. The post probe modifies every measured range in turn, requires that owner's exact
digest-mismatch while the other stays valid, and restores code before unrelated cleanup.
Its observed ranges must match the actual object/final-image completion evidence.

Ordinary callees and generated CFF helpers are
separate contributions unless their own explicit producer ownership is supplied; a root
hash alone does not establish coverage of those bodies.

`demo/check_post_subjects.py` re-emits the real protected child with function sections and
checks its actual linked CFF report. Six parent/child section/function and pre-release
combinations exercise early storage generation, both private record versions, actual
object/range evidence, idempotent authenticated completion and CLI output preservation.
The parent is a host-composer fixture; this test does not execute a production bootstrap
with configured function subjects or prove complete generated-helper coverage. Production
function execution and range corruption use the separate existing post-release probe.
