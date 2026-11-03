# Native prototype

The native tree contains a source-only C++ SDK, a registered LLVM CFF strategy, named target
backends, and an opt-in Windows bootstrap demonstration. The bootstrap runs its backend's
configured pre-release environment detectors,
decrypts an already linked DLL, loads it through the Windows loader, hands off an owned lease/token,
and invokes its entry. The default detector reports `unavailable`; this is not a clean result.
There is no TPM provider, Python dispatcher, kernel backend, or general in-memory DLL loader.
Marked outer-bootstrap glue has its own CFF/request/object/final-report pipeline. Its local
path-fold key binding now reconstructs a transient AES key from context-owned events and a
masked record. The ordinary payload now has a default strict contribution consumer with an
explicit weaker decoupled profile. An opt-in post-release profile binds two later CFF
roles to actual parent/child code observations; full configured measured readiness remains required.
See [ordinary payload binding](../docs/NATIVE_PAYLOAD_BINDING.md) for the acyclic early/late
build contract, actual-entry checks, measurements and limits.
The [canonical code subject tooling](../docs/NATIVE_CODE_SUBJECTS.md) adds bounded host .text/
unwind-interval references and actual mapped-DLL equivalence tests. The
[private native capture](../docs/NATIVE_CODE_CAPTURE.md) now provides raw Windows x64 code
reads, CNG digests and target-module ownership, with none/O2 CFF and source-only MSVC tests.
Owned observation/cache/freshness support is implemented; configured multi-owner/mixed-source CFF remains required.
The [native scaffold release handoff](../docs/NATIVE_SCAFFOLD_HANDOFF.md) records a bounded
branch snapshot. Use the current project plans and progress records for subsequent work.
The [function contribution producer](../docs/NATIVE_FUNCTION_SUBJECTS.md) proves explicit
COFF root/fragment/alias extents against final code, including leaf and GNU-EH cases;
optional production post-role selection now uses the same frozen selectors and exact objects.
The [generated-subject producer](../docs/NATIVE_GENERATED_SUBJECTS.md) adds typed frame/
external/archive helper closure, private emission provenance and reserved reference support;
its production post-role wiring and generated reader independence remain pending.
The [reference codec](../docs/NATIVE_CODE_REFERENCES.md) reuses archive authentication for
late-data-ready code descriptors and owned native results. The [reserved reference slots](../docs/NATIVE_REFERENCE_SLOTS.md)
add frozen pre-codegen identities, read-only storage and authenticated idempotent data fill.
Their opt-in schema2 adds explicit scoped-material slots and private CMake input dependencies;
the opt-in two-role L4 handoff uses them, while generated owner integration remains pending.
The [owned observation runtime](../docs/NATIVE_OBSERVATIONS.md) adds private context-owned
read/cache lifetimes and three freshness policies, with final integration still pending.
The private [measured key primitive](../docs/NATIVE_MEASURED_KEYS.md) adds full observation/fold
key expansion and v2-only record admission. Its opt-in Windows measured bootstrap protects
pre-release admission; see that guide for stage, retirement, data-only finalization and tests.
Its private post-release material-to-word adapter keeps expected CFF words independent of
final code; production multi-owner/provider release binding remains required.
The generated owned contribution query stops on an invalid acquisition before its zero
word can enter CFF state; the ordinary `contribution::request` API still returns status.
The private `measured-scope-v1` query keeps an invocation-owned snapshot through normal/EH
return; see that guide for actual CFF and failure tests. The optional
`PYOBF_NATIVE_DEMO_POST_CODE_HASH` profile integrates actual parent/child roles through the
[private handoff and composer](../docs/NATIVE_PAYLOAD_BINDING.md#opt-in-post-release-code-observations).
The mixed POST profile has a strict late private-input generator: it consumes
the frozen two-owner original-edge plan, derives separate owned release and measured Scope
roots, and assigns each edge a distinct owned-source subset plus one measured source.
The `PYOBF_NATIVE_DEMO_POST_MIXED` option now reserves the exact plan-to-private
build dependency, the parent site allowlist, and separate lease/Scope arguments
in both child owners. The source role seal accepts the none/O2 shape and rejects
detached lease/Scope forwarding. The two-owner planner and final linked-PE
verifier are integrated. Actual mixed-none and PRE+POST/O2+archive child/parent
builds prove 7/4 and 6/3 original edges, respectively, with exact plan,
private-root, helper-route, PE prologue/unwind and cross-artifact refusal tests.
The legacy measured-only POST path remains available. An optional
[builder-fixed receipt](../docs/NATIVE_CONTRIBUTION_GATES.md#builder-fixed-mixed-post-receipt)
checks exact PE/report/private/plan/IR/object bytes after an explicit freeze
target. A five-input standalone schema4 source-mixed profile omits the plan
and rejects the earlier exact branch-NOP, entry-state and paired PE samples
under its own fixed receipt. The opt-in `PYOBF_NATIVE_DEMO_G3_SUBJECTS`
profile adds exact COFF-to-PE relocation and extent proofs for the two mixed
owners and two contribution helpers; actual none/O2+archive builds and a
receipt-matched changed-object finalizer negative pass. The mixed profile
also offers an opt-in owner entry-state check from the frozen CFG seeds;
two paired COFF/PE mutations with newly frozen receipts are refused by the
production finalizer. The mixed and standalone receipt profiles retain
their legacy no-receipt paths;
the further opt-in `PYOBF_NATIVE_DEMO_G3_REPLAY` explicitly reruns opt and
Clang before freezing a distinct 13-role receipt. It byte-compares the
transformed IR, report and COFF object, while ordinary no-change outer builds
do not rerun the compiler. Actual mixed none/O2+archive child/parent and
paired conditional-move negatives pass under this trusted-builder boundary.
The further opt-in `PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN` freezes a separate
20-role record after child replay for PRE+POST/O2/archive. It replays the
deterministic archive stages from snapshots, authenticates all 36 existing
records and rebuilds their generated C++ before fixed-record finalization.
The actual plan-tamper and package/key/source negatives refuse. Runtime
C++-to-IR and O2 predicate equivalence remain open.

`PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR` separately freezes the requested IR,
optimized IR and optimizer executable before the inner build. Its exact
`default<O2>` replay joins optimized IR and tool paths and bytes to the
archive-origin record. The main seed-692 joint final report and dedicated
O2 predecessor CTest pass. Changed IR/tool, forged command, same-byte
wrong-path and hardlink negatives refuse. C++ source provenance, optimizer
DLL dependencies and publisher signing remain outside this record.
`PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION` further proves the selected
PRE+POST/O2/archive PE wrapper arguments, six writable output/cache extents,
two same-slot reads and comparison/state routes. It checks all six wrapper
machine frames and the 21 direct owner call targets. Actual paired COFF/PE
slot, call, alias, frame and CFG bypasses refuse. The selected full finalizer
first verifies the mixed POST helper routes; the standalone publication
verifier assumes their normal returns. Both observed seed-248 and seed-692
comparison orders pass; other generated layouts fail closed.
Decoder/cache effects and complete O2 original-predicate equivalence remain
unverified.

The further opt-in `PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE` binds the
selected `require_record -> acquire_record` call and acquire's parse,
access-check and decode child calls to exact COFF/PE targets and local
argument windows. The seed-692 O2/archive worktree final report and
origin/publication/decoder CTests pass 3/3. Paired call retarget, wrong
argument, frame restoration, jumps into protected instructions and captured
stack slot mutations refuse. The report explicitly leaves decoder/cache effects,
platform crypto and acquire inter-state reachability unverified.

The separate `PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES` option checks exact local
binding-callee extents and the bounded status-to-return/failure route. It
tracks Scope/lease argument identities and keeps modeled stack slots inside
the aligned Win64 frame and state outside call shadow space. Actual none and
O2+archive builds reject paired COFF/PE control, argument and stack-slot
mutations with fresh older receipts. Helper-to-local argument provenance,
transitive effects and unwind/EH remain open.
`PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS` further proves the selected
`Scope::binding_status` pointer and generation guards, status selection and
three local accessor return routes against exact COFF/PE function bodies and
call-site relocations. Actual source-none and O2/archive final reports and
paired guard, field, symbol-alias, overlapping-stack and Win64 shadow-space
negatives pass. The further default-off
`PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT` checks the called
`context_availability` closing bit/status and exact lock/unlock call route
in source-none and O2/archive COFF/PE. Paired closing-mask and lock-target
edits pass the predecessor and fail this gate. Platform atomic effects,
request/query through dispatch and arbitrary runtime memory integrity
remain unverified.

`PYOBF_NATIVE_DEMO_G3_BOUND_CALL` further checks the selected
`call_bound_bootstrap` publication pointer guard, successful retain-status
route, captured lease construction and unchanged invoke request in exact
source-none and O2/archive COFF/PE bodies. Both option-on products and
paired pointer self-compare, wrong-request and frame/CFG refusals pass in
the isolated worktree after its latest-main merge. Publication-source,
retain/invoke body and platform lock effects remain unverified; the
result does not close the transitive binding chain.

`PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL` checks the selected local retain
increment and guards. `PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL` then checks the
request/admit-status/callback/complete/result route in source-none and
O2/archive COFF/PE. `PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM` and
`PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE` separately check the selected
conditional first-use arm and its entry success path in O2/archive. The
seed-692 main product enables these checks together; its five focused
bound/retain/invoke/first-use/entry tests pass. Called-body effects,
arbitrary runtime memory and full G3 closure remain unverified.

G3 machine-profile closure, request freshness, distribution authority and
loaded-byte authenticity remain open.
The opt-in parent reference-plan producer also checks the exact mixed private
input against both early roots and the frozen child edge plan before fixing
its two role slots. Mixed final composition and package admission have bounded
none and PRE+POST/O2+archive production evidence; full D7 acceptance remains open.
Generic schema3 CFF can now bind separate explicit sites in one function to owned context
and measured Scope providers; see [the mixed-site contract](../docs/NATIVE_CONTRIBUTION_GATES.md#mixed-providers-across-explicit-sites).
Schema4 CFF binds owned context and measured Scope sources within explicit sites
through a dual-reference marker. The bounded Windows x64 whole-function profile
admits one or two such sites, with distinct function-argument or immutable entry-spill
references. Its linked-image checks retain each helper return route and show local
numeric sensitivity and nonempty unsigned dispatcher intervals in the two-site profile.
A separate opt-in exact-PE caller-flow diagnostic checks first/eighth pointer
arguments; with `--contribution-input`, the
final checker also compares each two-site helper's routing, domain and owner register
arguments with the validated private build policy. Schema4 helpers compare actual
context state and generation before producing words; equal-generation foreign
contexts fail. The finalizer obtains both helper symbol disassemblies from the
same PE and refuses a missing symbol. It checks direct stack writes against
each helper's exact PE unwind interval, including aliases and CFG merges.
The linked route gate checks both helpers' direct rel32 binding, query and
failure call targets and requires binding before every query path.
These bounded checks do not prove transitive helper write effects, global
state reachability, the binding callee body or arguments, symbol authority,
every wrong-value refusal or authenticity of a replaceable private policy.
The report keeps
`joint_caller_pointer_provenance_verified=false` and
`cross_provider_owner_binding_verified=false`; see [the source-mixed contract](../docs/NATIVE_CONTRIBUTION_GATES.md#mixed-providers-within-one-explicit-site).
Homogeneous schema2 measured CFF can also map multiple live Scope references
to selected original edges using explicit `reference_site` anchors; see
[the bounded original-edge profile](../docs/NATIVE_CONTRIBUTION_GATES.md#multiple-scope-references-on-original-edges).
For whole non-hybrid `relative-tree` schema2 owned CFF, the linked Windows x64
gate now checks a bounded grouped helper-return, state-write and dispatcher
route. It rejects detached returns and unmodeled stack/argument writes;
hybrid and region keep their prior presence evidence. Numerical influence,
global state preservation and individual-site machine equivalence remain open;
see [the grouped source contract](../docs/NATIVE_CONTRIBUTION_GATES.md#per-site-source-subsets).
Generated helper inventory, generated owner independence and complete D7 acceptance remain open.
The [path-fold component](../docs/NATIVE_PATH_FOLD.md) has an independent build reference,
LLVM emitter and explicit whole/hybrid sites, including four actual bootstrap startup events.
Private per-build event descriptors feed state-bound emission. The Windows backend supplies
macro-mediated SHA-256 expansion, followed by masked-key reconstruction and real CNG AES-GCM.
The [release tools](../docs/NATIVE_RELEASE_RECORDS.md) bind the finalized child and its report,
emit ciphertext without a raw key, and fill only reserved data in a separate final parent
image. This raises static recovery cost; it does not establish machine authorization.
The optional [decoy domain](../docs/NATIVE_DECOY.md) supports an independent source list,
recipe, finalized image and authenticated package. Named outer-decoy variants use independent
runtime state/key/image ownership. Separate observed actual-CNG tests classify exact child
bytes and check post-emission faults, erased ownership and allocation failures.
The [bootstrap composition and costs](../docs/NATIVE_BOOTSTRAP_ACCEPTANCE.md) guide separates
the current lifecycle/fold guarantees from genuine measured handoff and provides an isolated
actual-CNG/loader release measurement target.
The [contribution foundation](../docs/NATIVE_CONTRIBUTIONS.md) adds independently checked
word framing, an LLVM correction expression and source-only owned-context client/provider
targets. The demo serves derived words from an immutable post-authentication snapshot.
Opt-in [contribution gates](../docs/NATIVE_CONTRIBUTION_GATES.md) acquire actual context words
and seal explicit-point or automatically selected retained-input normal-edge transitions.
Whole and supported hybrid normal bodies compose opaque, junk and decoy layers through
isolated identity models and independent frozen source/flow proof. Region gates retain
their existing function-only component restrictions; broader compositions remain pending.
Existing reference/import/local initializers compose with whole and admitted hybrid
contribution gates. Closed source markers stay outside
user call routing, and shared data-state/root proof supplements each operation verifier.
Automatic selection checks count/density requirements, query budgets and actual routes,
including Windows x64 GNU hybrid EH normal edges with explicit unwind exclusions and
explicit branch-only regions with scoped inventory and outside-boundary proof.
Per-site ordered owned-material groups are available; other provider classes, remaining
compositions and genuine independent measurement remain open.
Its internal descriptor resolver validates versioned capabilities and per-owner site subsets;
runtime observation/freshness proof remains separate from these declared policies.

For composable configuration, strict site requirements and extension steps, see
[Native recipes](../docs/NATIVE_RECIPES.md). The old strategy names remain compatible recipes.
The opt-in [typed archive runtime](../docs/NATIVE_ARCHIVE.md) is a separate source target;
LLVM planning, wrapper verification/materialization and state-key binding now execute through
explicit compiler stages or the opt-in demo CMake pipeline. Deterministic binary assets use
the same protected storage; ordinary O2 precedes archive planning and final CFF.
The opt-in `reference-routes` component adds per-build target-table layouts and state-dependent
function-address/call lookup while preserving actual callback addresses and call ABI. This
is the first D4 unit. Separate opt-in `call-frames` adds typed invocation-owned storage and
automatically protected internal invokers. Opt-in `call-preparation` splits field I/O, invocation
and result handling across distinct CFF states and binds field addresses to their producer's
actual state. Opt-in `indexed-locals` routes original typed stack-object addresses through
an invocation-owned slot table, preserving object identity, aliases, alignment and lifetime.
The Windows GNU hybrid profile supports these routes in normal and exception continuations;
required original objects removed by source O2 still fail instead of borrowing generated storage.
Opt-in `external-calls` uses the same typed-frame infrastructure for admitted strong external
declarations, with separate original requests and automatically protected private adapters.
Opt-in `import-routes` separately protects scalar strong-declaration address uses through
state-indexed tables, including original uses moved into typed frames or a common exit.
Its resolver verifies the exact imported index graph and actual dispatcher route. Final
import names/ABI and OS loader ownership remain visible.
Internal/external frames and call steps also compose with whole and admitted hybrid
[contribution gates](../docs/NATIVE_CONTRIBUTION_GATES.md#framed-call-and-preparation-composition).
Explicit original-invoke replacement and completion tracking preserve source identity across
result RAUW; generated preparation states do not inflate original-edge coverage.
Normalized graph snapshots also preserve owned routing roles; clone/synthesis placement
excludes those atomic boundaries. Frozen guard/predicate/result/write plans now compose
clones/synthesis with whole and admitted hybrid source gates. Isolated predicate templates
reuse scalar literal emission, preserving raw and hidden-constant expressions.
Whole and admitted hybrid source gates also compose with integer/equality rewrites under the
[scalar data contract](../docs/NATIVE_CONTRIBUTION_GATES.md#scalar-data-composition).
Hybrid literal returns use a separate typed proof adapter; comparisons retain their original
condition identity, while invoke/resume and other terminal operands keep their frozen boundaries.
Actual source none/O2 cases keep nonzero feature coverage separate from optional lost requests.
The [archive composition](../docs/NATIVE_CONTRIBUTION_GATES.md#archive-data-composition) follows
the existing plan/package/materialization pipeline for whole and admitted GNU hybrid owners,
preserving closed source IDs and EH control identity. Actual
cached data reuse still requires current contribution queries; record caches grant no context authority.
The [structural composition contract](../docs/NATIVE_CONTRIBUTION_GATES.md#structural-normalization-composition)
covers whole common exits, splitting and explicit-gate deduplication. Closed source descriptors
do not consume the work budget; ordinary calls do. Automatic deduplication preserves frozen
logical edges through compiler-owned aliases and separately counts compatible physical queries.
The existing GNU hybrid EH scope also admits the three normalizers. Original cut requests
survive earlier source/frame preparation; registered invoke completion chains remain before
their delayed acquisition gateway. Other EH models and region normalizers retain their limits.

## File map

| File or group | Responsibility |
| --- | --- |
| `CMakeLists.txt`, `cmake/Options.cmake` | Source-only SDK target and optional smoke/pass/demo switches |
| `cmake/Backends.cmake` | Resolve and validate one named target backend |
| `cmake/LLVMCompile.cmake` | Matching toolchain flags, IR depfiles, final native objects outside later IPO and opt-in function sections |
| `cmake/ArchivePipeline.cmake` | Plan/pack/helper-request/link/materialize DAG and merged source/helper requests |
| `cmake/Assets.cmake`, `tools/embed_asset.py` | Deterministic private source/header generation and binary input dependencies |
| `tools/merge_requests.py` | Strict deterministic merge with duplicate-definition and marker-conflict rejection |
| `demo/cmake/IrPipeline.cmake`, `demo/recipes/archive.json` | Demo IR orchestration and explicit optional archive recipe |
| `demo/cmake/OuterPipeline.cmake`, `demo/recipes/bootstrap.json` | Separate default/triggered outer CFF pipelines, explicit whole/hybrid markers, native object before parent IPO and independent final reports |
| `demo/check_cff_outer.py`, `demo/check_cff_outer_failures.py` | Authored outer requests, exact image/report digests, partial EH accounting, executable same-source unprotected-image and wrong-whole-scope rejection |
| `backends/template/Backend.cmake.in` | Manifest template for another target backend |
| `backends/windows_user/Backend.cmake` | Windows user-mode sources, capabilities, detector names, and link libraries |
| `backends/portable_stub/Backend.cmake` | SDK-only placeholder backend for non-Windows builds |
| `include/pyobfuscator_native/sdk.hpp` | Public C++ inspection and callback types |
| `include/pyobfuscator_native/asset.hpp`, `src/archive/asset_identity.cpp` | Module-owned byte view and opaque identity helper linked after ordinary optimization |
| `include/pyobfuscator_native/cff_marker.hpp` | Source markers for user and SDK CFF selection |
| `include/pyobfuscator_native/bootstrap_api.hpp` | Versioned SDK-to-bootstrap call table |
| `include/pyobfuscator_native/bootstrap_context.hpp`, `context/` | Optional owned-context source target, capability and CFF test wiring |
| `include/pyobfuscator_native/bootstrap_binding.hpp`, `src/context/{publication.hpp,publication.cpp,binding.cpp,bound_call.cpp}` | Scoped owned publication, private serials and expected-context call capture |
| `src/context/runtime.hpp`, `src/context/{synchronization,factory,owner,lease,call,lifetime}.cpp` | Private lifecycle state, locks/generations, adoption, ownership, admission and cleanup |
| `backends/windows_user/operations/code_lifetime.cpp`, `tests/context/` | Actual callback code references, lifecycle/failure/DLL/CFF tests |
| `include/pyobfuscator_native/environment.hpp` | Bounded named detector report and tri-state result |
| `include/pyobfuscator_native/system_ops.hpp` | Semantic OS-operation macros and backend function contract |
| `src/release/record.hpp`, `backends/windows_user/release_record.cpp` | Private fixed-layout declaration and separately compiled native placeholder storage |
| `tools/release_format.py`, `pe_release_record.py`, `finalize_release.py` | Host expansion/mask format, bounded data-only PE filling and CLI artifact writes |
| `demo/cmake/ReleaseChecks.cmake`, `demo/check_release_record.py`, `tests/release_record{.cpp,_cases.py}` | Actual native/LLVM/loaded-record, malformed-input and invariant checks |
| `backends/windows_user/operations/hash.cpp` | Per-call CNG SHA-256, macro-mediated storage and explicit erased-output failure |
| `tests/hash_sha256{,_failure}.cpp`, `check_hash_sha256.py` | Actual CNG reference vectors, concurrent independent calls and forced allocation failure |
| `src/sdk.cpp`, `src/sdk_internal.hpp` | SDK binding, callback delivery, and private platform interface |
| `src/environment.cpp`, `src/environment_internal.hpp` | Shared detector selection, aggregation, and backend catalog contract |
| `src/platform/unsupported.cpp` | SDK-only non-Windows unavailable placeholder |
| `src/platform/atomic.cpp` | SDK-only stub CAS/store/load with no OS scheduler dependency |
| `backends/windows_user/sdk_environment.cpp` | Windows SDK placeholder, currently unavailable |
| `backends/windows_user/environment/registry.cpp` | Explicit Windows detector catalog |
| `backends/windows_user/environment/placeholder.cpp` | Default unavailable detector |
| `backends/windows_user/environment/{clear,triggered}.cpp` | Test-only detector fixtures, excluded from the normal outer DLL |
| `backends/windows_user/operations/{memory,crypto,loader}.cpp` | Windows heap, AES-GCM CNG, and disk-backed LoadLibrary operations |
| `backends/windows_user/operations/{atomic,archive_support}.cpp` | Archive publication/pause, target byte order and terminal failure operations |
| `archive/CMakeLists.txt` | Optional source-only typed archive runtime target and backend capability gate |
| `src/archive/runtime.hpp`, `src/archive/format.{hpp,cpp}` | Private cache/status types, bounded typed-pool parsing and storage validation |
| `src/archive/acquire.cpp`, `src/archive/require.cpp` | Per-access key verification, stable-storage publication and fail-before-use boundary |
| `tools/archive_format.py`, `tools/pack_archive.py` | Strict private-plan schema, AES-GCM pool and generated wrapper/private-key bindings |
| `tests/archive_fixture.py`, `tests/archive_smoke.cpp`, `tests/check_archive_{tool,failure,cff}.py` | Typed/ownership/concurrency/negative protocol checks and actual runtime/wrapper CFF execution |
| `llvm/CMakeLists.txt`, `llvm/cff/cff.hpp` | LLVM plugin target and internal strategy interface |
| `llvm/archive/plan.hpp`, `llvm/archive/pipeline.cpp` | Private archive-plan contracts, source selection, exact manifest hash and incomplete-output gates |
| `llvm/archive/constant_bits.cpp` | Target storage/stride/endian serialization and explicit typed eligibility |
| `llvm/archive/collect.cpp`, `llvm/archive/use_closure.cpp` | Bounded source inventory, local-global use closure and known early-call rejection |
| `llvm/archive/control_operands.cpp`, `llvm/archive/control_operands.hpp` | Shared request/plan/closure classification preserving exception clauses, resume and GNU type-info ABI identity |
| `llvm/archive/instrument.cpp`, `llvm/archive/manifest.cpp` | Original zero storage, predecessor/key-frame skeletons, invalidated purity and private schema output |
| `tests/archive_plan_cases.py`, `tests/check_archive_plan.py` | Planning/type/layout/closure fixtures, real packer handoff and unfinished-output rejection |
| `tests/archive_eh_cases.py` | Typed hybrid archive planning, immutable EH control operands and shared-use/model/personality refusals |
| `llvm/archive/bindings.hpp`, `llvm/archive/bindings_reader.cpp`, `llvm/archive/metadata.hpp` | Strict private key/binding schema and compiler metadata access |
| `llvm/archive/wrapper_verify.cpp`, `llvm/archive/materialize.cpp` | Actual wrapper/require/pool/cache/storage verification, target descriptor checks and private key preparation |
| `llvm/archive/empty_plan.{hpp,cpp}` | Canonical no-pool bindings, empty-phase content checks and retained compiler-stage guards |
| `llvm/archive/key_address.{hpp,cpp}`, `llvm/archive/source_report.{hpp,cpp}` | Frame/address provenance through SSA spills and indirect routes, original-source acquisition coverage and final private-material removal |
| `llvm/cff/archive_keys.cpp` | Independent registered archive key-lane CFF strategy |
| `demo/cff_archive_evidence.py` | Scoped linked archive-key mix multiplicity and source/physical count checks |
| `tests/check_archive_protected.py`, `tests/archive_protected_negative.py`, `tests/archive_protected_smoke.cpp` | Full protected user-DLL pipeline, cold concurrency/recursion/lifetimes, combined strategies and binding/key/state/ownership negatives |
| `tests/check_archive_build_tools.py` | Asset determinism/empty/budget/path errors and request merge provenance/conflicts |
| `tests/check_archive_pipeline.py`, `tests/archive_pipeline/{CMakeLists.txt,reader.cpp}` | Real shared CMake helpers with O2/parent IPO, runtime assets, incremental/removal/error checks and lost-source coverage |
| `tests/check_archive_empty.py`, `tests/archive_empty_pipeline.py` | Empty/disabled/originally-eliminated inventories, executable/CMake behavior, strict failures and malformed-phase/binding rejection |
| `demo/archive_measure_input.py`, `demo/archive_measure_build.py` | Public typed-data cost workload and separately timed request/optimization/archive/CFF/link phases |
| `demo/measure_archive.py`, `demo/measure_archive.cpp` | Paired plain/CFF/archive size/build/startup/first-use/warm-call evidence with independent typed-result checks |
| `llvm/cff/pass.cpp`, `llvm/cff/pipeline.{hpp,cpp}` | Thin CLI/pass entry and function/region orchestration |
| `llvm/cff/selection.cpp`, `llvm/cff/marker_selection.cpp` | Exact/marked/config/request selection and annotation parsing |
| `llvm/cff/recipe.hpp`, `llvm/cff/recipe_config.cpp`, `llvm/cff/component_registry.cpp`, `component_seed.cpp` | Versioned recipe resolution, typed component hook registration and separate public seed derivation |
| `llvm/cff/dependency_contract.cpp` | Declared domain/readiness graph and mutation-stage validation |
| `llvm/cff/mutation_guard.{hpp,cpp}`, `llvm/tests/contract_smoke.cpp` | Detect undeclared block/terminator/edge changes around nonstructural hooks; negative gate fixture |
| `llvm/cff/block_split.cpp`, `llvm/cff/block_split.hpp` | Legal budget splitting with retained original manifest anchors, including before-coverage archive insertion |
| `llvm/cff/block_deduplicate.cpp`, `llvm/cff/common_exit.cpp` | Separate structural deduplication and typed result/exit normalization |
| `llvm/cff/dedup_alias.hpp`, `contribution_edge_alias.cpp` | Private semantic-normalizer witness, ordered owned-source compatibility and original-to-physical route proof |
| `llvm/tests/contribution_parallel_mutations.hpp` | Parallel-successor flow positives and valid-IR condition/arm/constant mutations |
| `tests/contribution/normalizer_{fixture.ll,gate_cases.py}`, `contribution/NormalizerChecks.cmake` | Independent normalized source/results/effects/cut expectations, strict optimized-loss controls and modular CNG matrix registration |
| `tests/contribution/alias_gate_cases.py`, `normalizer_{terminal,switch}_fixture.ll` | Physical budgets, required/optional policy and selection conflicts, duplicate returns/switch ordinals and independent source-map refusal |
| `tests/contribution/alias_gate_cost.py` | Paired actual-CNG dedup off/on costs using the existing checked semantic/effect host, with separate process and warmed-loop samples |
| `tests/contribution/hybrid_normalizer_cases.py`, `contribution/HybridNormalizerChecks.cmake` | Named duplicate-work and authored-return expectations, source-none/O2 strict losses and hybrid/frame/grouped composition matrix |
| `tests/contribution/hybrid_completion_cases.py` | Distinct void completion owners, optional skip/required refusal and deferred-reference native code/relocation/unwind equivalence |
| `tests/contribution/hybrid_local_cases.py` | Independent retained-object/lifetime inventory, runnable hybrid-only local erasure and actual wrong-state execution controls |
| `demo/split_request_cases.py` | Independent original-cut and replaced-call-cut regression through actual typed frame expansion, execution and final-image checks |
| `llvm/cff/preparation.{hpp,cpp}`, `llvm/cff/transition_sites.{hpp,cpp}` | Frozen pre-state anchors, typed structural preparation and bounded component selection |
| `llvm/cff/module_prepare.{hpp,cpp}` | Registered early helper generation, definition/owner validation and implicit baseline-CFF helper recipes |
| `llvm/cff/call_frames.hpp`, `llvm/cff/call_frame_sites.cpp` | Typed call-frame contracts, public-seeded layouts, ABI/storage eligibility and stack/site budgets |
| `llvm/cff/call_abi_retention.cpp` | Pre-request compiler-used roots for eligible required local frame targets, including optional frames with required preparation |
| `llvm/cff/external_calls.{hpp,cpp}` | Independently registered external-declaration strategy over shared typed frame discovery/planning/rewrite, without a new OS resolver |
| `llvm/cff/call_frame_plan.cpp`, `llvm/cff/call_frame_metadata.cpp` | Pre-seal internal invokers, source/helper inventory and strict private layout/ABI metadata |
| `llvm/cff/call_frame_rewrite.cpp` | Per-original-site stack ownership, argument/result marshaling, source-use aliases and entry hoisting |
| `llvm/cff/frame_eh.cpp`, `llvm/cff/frame_eh_guard.cpp` | Framed invoke emission, normal-result blocks/PHI handoff and pre-state normal-edge dominance checks |
| `llvm/cff/frame_profile.{hpp,cpp}` | Call-count/edge/target profile partition and immutable source metadata snapshots before helper generation |
| `llvm/cff/frame_profile_guard.cpp` | Original source-to-helper binding and complete final outer/inner event/profile inventory before artifact stripping |
| `llvm/cff/exceptional_origins.{hpp,cpp}` | Original personality/pad/unwind inventory, explicit invoke replacement and cross-stage preservation checks |
| `llvm/cff/frame_address.cpp`, `llvm/cff/call_frame_verify.cpp` | Bounded address/spill closure, actual typed storage/ABI/owner checks and final private-inventory removal |
| `llvm/cff/call_preparation.{hpp,cpp}` | Opt-in discovery, step budgets and private field/anchor planning |
| `llvm/cff/call_steps.cpp` | Pre-state preparation blocks for actual typed I/O, invocation and result handling |
| `llvm/cff/call_address_emit.cpp`, `llvm/cff/call_address_bind.cpp` | Production bounded/aligned state-dependent byte addresses and site/provenance binding |
| `llvm/cff/call_address_proof.cpp`, `llvm/cff/call_step_proof.cpp` | Exact mask/bounds/field/slot graph and actual final dispatcher-route checks |
| `llvm/cff/call_preparation_verify.cpp` | Planned caller/helper field/step inventory, private-artifact rejection and stripping after combined verification |
| `llvm/cff/ssa_origin.{hpp,cpp}` | Bounded unambiguous closed stack-copy origins for values crossing preparation steps |
| `llvm/cff/indexed_locals.hpp`, `llvm/cff/local_sites.cpp` | Original object/use eligibility, retained controls and inherited local table/use/byte budgets |
| `llvm/cff/local_metadata.cpp`, `llvm/cff/local_table.cpp` | Typed source-object inventory, seeded private slots and initialization generated after structural splitting |
| `llvm/cff/local_bind.cpp`, `llvm/cff/local_proof.cpp` | Actual-state object address lookup and exact mask/index/target/dispatcher-route checks |
| `llvm/cff/local_table_proof.cpp`, `llvm/cff/local_verify.cpp` | Immutable complete table, original object/control/use ownership, source artifact rejection and final stripping |
| `llvm/cff/scalar_proof.{hpp,cpp}` | Shared exact i32 public-mask graph/constant/state-slot matching, without sample-only acceptance |
| `llvm/tests/local_contract.cpp` | Whole/hybrid table fixtures, retained lifetime identity and thirty-three valid-IR graph/object/source/escape/control mutations per fixture |
| `demo/local_cases.py`, `demo/check_cff_locals.py` | Typed/atomic/volatile/alias/escape/lifetime/recursive/reentrant/thread execution, seeds/mixed strategies, source O2 and real C++ ABI |
| `demo/check_cff_local_edges.py`, `demo/check_cff_local_sdk.py` | Unsupported/strict/optional/budget/private/32-bit cases and actual SDK/user/backend source-unit linking |
| `demo/cff_local_evidence.py`, `demo/measure_cff_locals.py` | Scoped final address-route feature evidence and isolated same-source plain/CFG/locals/composed costs |
| `llvm/tests/frame_fixture.hpp`, `llvm/tests/frame_contract.cpp` | Shared internal/external typed-frame fixture, nineteen ownership/ABI/access/inventory mutants per profile and four external profile/control mutants |
| `llvm/tests/frame_eh_contract.cpp` | Valid-IR early/unwind/shared-result negatives plus source exception target/personality/clause/ownership-transfer checks |
| `llvm/tests/frame_profile_fixture.hpp`, `llvm/tests/frame_profile_contract.cpp` | Twenty-four profile matrices and eighteen valid-IR source/owner/event/count/VP/shared-metadata mutations |
| `llvm/tests/preparation_contract.cpp` | Seventeen state/graph/step/field/inventory/escape/SSA-copy mutations against actual production address expressions |
| `demo/frame_cases.py`, `demo/check_cff_frames.py` | Typed/recursive/reentrant/thread/loop/vector/aggregate execution, O2/unsupported/private-input and erased-invoker checks |
| `demo/frame_cpp_{fixture,harness}.cpp` | Actual frontend C++ ABI and exception propagation through callers without selected EH cleanup |
| `demo/cff_frame_evidence.py`, `demo/measure_cff_frames.py` | Scoped final invoker/route inventory and isolated costs using the shared reference-call workload |
| `demo/external_cases.py`, `demo/check_cff_external.py` | Separate-provider DLL ABI/effects/callback/recursive/reentrant/thread/seed/O2/target-32 checks and real frontend C++ ABI/unwind propagation |
| `demo/check_cff_external_backend.py` | Actual Windows macro-mediated memory backend: whole-scope EH rejection, hybrid cfg/frame/preparation/import profiles and separate no-exceptions adapter profiles |
| `demo/hybrid_frame_abi.cpp`, `demo/check_cff_hybrid_frames.py` | Framed C++ catch/cleanup/rethrow/recursion, sret/small aggregate ABI, shared-pad PHIs and optional reference/import/preparation combinations |
| `demo/frame_profile_cases.py`, `demo/check_cff_frame_profiles.py` | Ordinary/hybrid profile placement, internal/external frames, source O2, preparation/routes, differential exception execution and linked PE checks |
| `demo/frame_abi_retention_cases.py`, `demo/check_cff_frame_abi_retention.py` | O2 return-ABI rewriting, required/optional retention, repeated collection, real unwind cleanup and archive scope admission |
| `demo/hybrid_final_cases.py`, `demo/check_cff_hybrid_final.py` | Same-named unprotected/wrong-image reports, actual post-CFF erasure, private input rejection and exact final-image/report digests |
| `demo/measure_cff_hybrid_fixture.cpp` | Shared source-built typed exception workload with normal decisions, catch, guard effects and external rethrow |
| `demo/measure_cff_hybrid.cpp` | Windows host-only paired DLL-load and warm-call sampling with per-call result/cleanup/exception validation |
| `demo/measure_cff_hybrid.py` | Plain/CFG/frame/five-component none/additional-O2 builds, final gates, raw cost samples/digests and four harness behavior negatives |
| `demo/check_cff_hybrid_project.py`, `tests/hybrid_project/CMakeLists.txt` | Real CMake whole/hybrid multi-source SDK/asset/archive composition across ordinary O2 and parent IPO, plus required original-literal loss rejection |
| `tests/hybrid_project/api.hpp`, `tests/hybrid_project/owner.cpp`, `tests/hybrid_project/whole.cpp` | Declared DLL ABI, reentrant callback/catch/cleanup/rethrow owner and separate whole-scope SDK/asset consumer |
| `tests/hybrid_project/provider.cpp`, `tests/hybrid_project/harness.cpp` | Separate provider-DLL function-pointer identity and paired original/protected recursive/concurrent result/effect checks |
| `demo/cff_external_evidence.py`, `demo/measure_cff_external.py` | External helper final-presence gate and isolated paired costs with one unchanged provider DLL |
| `demo/check_cff_preparation.py`, `demo/check_cff_preparation_edges.py` | Full ABI/effect/seed/O2 differential suite, empty fields, padding/budgets, wrong-state and erased-feature negatives |
| `demo/cff_preparation_evidence.py`, `demo/measure_cff_preparation.py` | Final address-component presence and paired plain/CFG/frame/preparation/composition costs |
| `llvm/cff/cfg_origin.{hpp,cpp}`, `llvm/cff/site_prepare.cpp` | Explicit generated-block origins, transition roles, preparation metrics and private donor provenance |
| `llvm/cff/opaque_choices.cpp`, `opaque_transition.cpp`, `opaque_expression.{hpp,cpp}` | Separate bounded site selection, actual transition emitter and finite-width predicate families |
| `llvm/cff/reachable_junk.cpp`, `junk_transition.cpp`, `junk_expression.{hpp,cpp}` | Separate live-state site selection, actual transition emitter and host reference calculation |
| `llvm/cff/bogus_blocks.{hpp,cpp}` | Shared fake-body skeleton, quotas, late guard binding and decoy-result consumption |
| `llvm/cff/bogus_clones.cpp` | Safe wrapping-i32 donor discovery and fresh state-derived clones, preserving dependency order |
| `llvm/cff/bogus_synthesis.cpp` | Independent bounded fake arithmetic and explicit unavailable-clone fallback |
| `llvm/cff/site_provenance.{hpp,cpp}`, `llvm/cff/site_origin.cpp`, `llvm/cff/site_alias.cpp`, `llvm/cff/site_alias_graph.{hpp,cpp}` | Pure source-origin reading, component-aware identities, relocation/coalescing links and required-alias validation |
| `llvm/cff/site_report.{hpp,cpp}`, `llvm/cff/cfg_sites.cpp`, `llvm/cff/report_writer.cpp` | Site provenance/coverage, CFG discovery and JSON output |
| `llvm/cff/contribution_contract.hpp` | Compiler-facing source/owner/site contracts shared by the production owned-material catalog and future providers |
| `llvm/cff/contribution_source_config.cpp`, `contribution_sources.{hpp,cpp}` | Strict schema2 catalog/default rules, schema3 mixed-provider sites and schema4 source mixing; default two-site cap and frozen-plan-only eight-site admission, policy resolution, query budget and independent group reference |
| `llvm/cff/contribution_reference_origin.hpp` | Closed schema4 reference origin for distinct function arguments or immutable entry pointer spills |
| `llvm/cff/contribution_mix.hpp`, `contribution_mix_{plan,emit,proof}.cpp` | Ordered word framing, pure32-bit emission and iterative non-mutating expression proof |
| `llvm/cff/contribution_groups.hpp`, `contribution_group_{acquire,queries,bind,proof,report}.cpp` | Modular multi-query acquisition, standalone query inventory, correction binding, exact retained graph and separate source-subset/query reports |
| `llvm/tests/contribution_group_mutations.hpp`, `tests/contribution/group_gate_cases.py`, `demo/cff_contribution_groups.py` | Private source-plan/dataflow mutants, independent configured subsets/member failures and false report checks |
| `contribution/{CMakeLists.txt,Checks.cmake}`, `include/pyobfuscator_native/contribution.hpp` | Source-only owned client/provider targets and C++ API; separate CFF test registration |
| `src/contribution/{protocol.hpp,client.cpp,context_derive.cpp}` | Bounded strict request/reply, canonical SHA-256 derivation and private temporary erasure |
| `src/contribution/{gate,marker}.cpp`, `include/pyobfuscator_native/contribution_marker.hpp` | Separate generated scalar query ABI and plain-source point reference |
| `src/contribution/{scope_marker,mixed_marker,mixed_gate}.cpp`, `src/contribution/scope.hpp` | Plain measured and same-site dual-reference markers; schema4's two private joint helpers check exact context state and generation before each word |
| `llvm/cff/contribution_{private,artifacts,marker,acquire,normalize,bind,proof,seal}.{hpp,cpp}`, `contribution_gate.hpp` | Private adapter, stage guards, closed points, acquisition, routing, actual correction and graph/frozen-plan proof |
| `llvm/cff/contribution_options.{hpp,cpp}`, `contribution_edges.hpp`, `contribution_edge_{source,inventory,instrument,lower,flow}.{hpp,cpp}` | Automatic source admission, retained-input inventory, seeded count/density selection, PHI-safe gateways, switch trace and complete normal-route proof; per-file roles in the contribution guide |
| `llvm/cff/contribution_edge_plan.cpp`, `tests/contribution/original_edge_plan.py` | Private exact-retained-IR schema1 two-successor or schema2 3-8-successor planning and CFF preflight; deterministic labels and fail-closed changed-plan/IR/option/ABI/edge-shape checks |
| `llvm/cff/transition_binding.hpp`, `contribution_route_seal.cpp`, `contribution_edge_invoke.cpp` | Compiler-only verified normal-target binding and exact invoke/EH/contribution source trace; gate plans also freeze private source identities/salt |
| `llvm/cff/contribution_frame_trace.cpp` | Original-invoke replacement and registered completion splitting before RAUW/deletion, preserving exact source/gateway continuity |
| `llvm/cff/hybrid_eh_edges.cpp`, `hybrid_eh_prepare.cpp` | Pure EH boundary preparation and coverage integration adapter |
| `llvm/tests/contribution_edge_{source,flow}_{fixture.hpp,contract.cpp}`, `tests/contribution/{edge_fixture.cpp,edge_policies.py}` | Actual automatic switch execution, independent denominator/policy negatives, production source/flow mutation contracts |
| `tests/contribution/multi_scope_edge_*.{cpp,py}` | Two-Scope original-edge planning, runtime CNG/final image and negative anchor/pointer/source mapping checks |
| `llvm/tests/contribution_invoke_contract.cpp`, `contribution_binding_{fixture.hpp,contract.cpp}`, `tests/contribution/hybrid*` | Hybrid invoke/binding mutation contracts and actual caught/escaping/nested/concurrent source-gated execution |
| `llvm/tests/contribution_frame_mutations.hpp`, `tests/contribution/framed_gate_cases.py` | Framed source/registration/RAUW regression and actual typed-target/owned-route erasure plus helper inventory controls |
| `llvm/cff/region_scope.{hpp,cpp}`, `region_pipeline.cpp` | Shared region membership and scoped orchestration through registered normalization/preparation/binding hooks |
| `llvm/cff/region_boundary.{hpp,cpp}` | Detached outside-operation snapshot and exact admission/operand/metadata preservation proof |
| `llvm/cff/transition_rewrite.{hpp,cpp}` | Shared normal-branch transition encoding/callback/state update for whole, hybrid and region CFF |
| `llvm/cff/transition_registry.{hpp,cpp}`, `transition_model.{hpp,cpp}`, `transition_model_{identity,match}.cpp` | Registered actual-emitter capability, isolated pure identity reference, symbolic reduction and exact graph matching |
| `llvm/cff/transition_literal_model.cpp`, `hybrid_scalar_bindings.{hpp,cpp}` | Distinct typed constant model and delegated exact-return proof; no generic terminal/RAUW permission |
| `llvm/cff/transition_predicate_model.cpp`, `llvm/tests/transition_predicate_mutations.hpp` | Isolated entry-state true-predicate reference using the same evaluator and exact matcher; independent observation/root/poison/constant negatives |
| `llvm/cff/bogus_control_plan.hpp`, `bogus_controls.hpp`, `bogus_control_{plan,descriptor,proof}.cpp` | A4-owned guard/normal/decoy/result/store identities, private state/codec references, typed retained descriptors and exact read/write capabilities |
| `llvm/tests/bogus_control_{fixture,mutations}.hpp`, `tests/contribution/bogus_gate_cases.py` | Raw/decoded normal-flow and ownership mutants, actual CNG compositions, malformed/reserved descriptors, runnable guard/work erasures and absent-donor checks |
| `llvm/cff/transition_layers.{hpp,cpp}`, `transition_layer_{selection,descriptor}.cpp` | Frozen layer order/site plans, typed retained metadata and verified normal-core/exact-read capabilities |
| `llvm/cff/source_marker.hpp`, `state_binding_proof.{hpp,cpp}` | Closed compiler marker candidate exclusions and shared frozen whole/hybrid data-state/root boundary |
| `llvm/tests/state_binding_mutations.hpp`, `tests/contribution/{preparation_fixture.cpp,preparation_cases.py}` | State/root/type/movement mutants, actual initializer compositions, exact frame inventory and runnable final-presence negatives |
| `llvm/tests/transition_model_contract.cpp`, `transition_layer_mutations.hpp`, `llvm/cmake/TransitionModelFixture.cmake`, `tests/contribution/layer_cases.py` | Production model/combined-flow mutants, composed actual source/hybrid execution and individually erased runnable final-image negatives |
| `llvm/tests/hybrid_scalar_{fixture,mutations}.hpp`, `tests/contribution/hybrid_scalar_fixture.ll` | Typed literal/terminal mutation contracts and real equal-return EH source fixture |
| `llvm/tests/contribution_region_{fixture.hpp,contract.cpp}`, `tests/contribution/{region_fixture.ll,region_host_support.hpp,region_gate_cases.py}` | Boundary/flow mutants, actual retained-region execution, independent denominator, repeated entry and source/budget/report refusals |
| `demo/cff_contribution_evidence.py`, `demo/cff_grouped_owned_flow.py`, `tests/contribution/gate*` | Final query/mask evidence, bounded whole schema2 owned linked return route, actual gated execution and negatives |
| `tests/contribution/{source_mixed_body.cpp,source_mixed_cff.py}`, `contribution/Checks.cmake` | One-site schema4 owned/Scope runtime, compiler and linked-image positives plus reference, detached-result and state-overwrite refusals |
| `demo/cff_source_mixed_dispatcher.py`, `tests/contribution/dispatcher_interval_cases.py` | Two-site exact-PE unsigned dispatcher interval and deterministic leaf-route gate; linked root/inner/leaf/copy/skip mutants and focused alias/conditional refusals |
| `demo/cff_source_mixed_helper_writes.py`, `tests/contribution/helper_write_cases.py` | Two-site helper unwind/PE-byte and direct stack-write gate; linked caller/return/below-frame mutations and bounded alias/CFG/hidden-instruction refusals |
| `demo/cff_source_mixed_helper_routes.py`, `tests/contribution/helper_route_cases.py` | Two-site direct rel32 binding/query/failure route gate; owned and measured linked target/skip mutants and focused branch bypass/byte mismatch refusals |
| `demo/cff_source_mixed_original_edges.py`, `tests/contribution/source_mixed_original_{edges.py,negatives.py,body.ll,probe.cpp}` | Bounded schema4 automatic two-successor proof: frozen plan/compiler-report identity, per-edge state-to-linked-site mapping, actual source-none CNG execution and PE bypass refusals; O2 merged-return shape, final-PE condition reachability and external report/image authenticity remain open |
| `demo/cff_source_mixed_bounded_{edges,site_map,dispatcher,numeric}.py`, `tests/contribution/source_mixed_bounded_*` | Separate 3-8-edge schema4 original-edge plan and linked Windows x64 PE proof; wrapper/compute none/O2 execution, per-edge denials, helper-return sensitivity and artifact/PE mutants; original-predicate machine binding and POST remain open |
| `demo/cff_joint_machine_evidence.py`, `tests/contribution/linked_machine_mutations.py` | Opt-in exact-PE schema4 caller-flow diagnostic, CFG/argument/return-route controls, forged final-only field and helper-write limitation cases; no complete binding claim |
| `tests/contribution/scalar_gate_cost.py`, `contribution/DataChecks.cmake` | Same-retained-source owned-CNG scalar off/on linked proof, refusal-gated size and paired hot-path cost record |
| `tests/contribution/contribution_gate_cost.py` | Same-authored-fixture grouped owned-CNG contribution on/off, linked/refusal-gated size and paired process/loop cost record; requests differ by design |
| `demo/bootstrap/contribution{,_snapshot}.cpp` | Post-authentication immutable snapshot and payload-entry-bound source dispatch |
| `tests/contribution/`, `demo/{contribution_session.cpp,check_contribution_session.py}`, `demo/cmake/ContributionSessionChecks.cmake` | Actual source/context/CNG lifetime, resource failures, protected execution and independent reference |
| `llvm/cff/request_manifest.{hpp,cpp}` | Pre-optimization request JSON writer and strict reader for retained/removed comparisons |
| `llvm/cff/registry.cpp`, `llvm/cff/relative_tree.cpp` | Explicit strategy table and relative-tree strategy adapter |
| `llvm/cff/region.hpp`, `llvm/cff/region_relative_tree.cpp`, `llvm/cff/region_validation.cpp`, `llvm/cff/region_rewrite.cpp` | Separate region strategy, single-entry/single-exit preflight, and selected-block rewrite |
| `llvm/cff/control_validation.{hpp,cpp}` | Shared selected-function returns-twice, reserved SJLJ and coroutine admission gate for whole/region CFF |
| `llvm/cff/hybrid_eh.hpp`, `llvm/cff/hybrid_eh_validation.cpp` | Explicit hybrid landingpad scope, target/personality admission and preserved-boundary contract |
| `llvm/cff/hybrid_eh_registry.cpp` | Explicit per-component hybrid capability registration, reported with each effective recipe |
| `llvm/cff/hybrid_eh_prepare.cpp`, `llvm/cff/hybrid_eh_bind.cpp` | Pre-state normal/pad gateways and invocation-owned encoded normal/unwind corrections |
| `llvm/cff/hybrid_eh_report.cpp` | Separate original EH inventory and partial-coverage report |
| `llvm/cff/hybrid_flow.hpp`, `llvm/cff/hybrid_flow_plan.cpp`, `llvm/cff/hybrid_flow_verify.cpp` | Immutable pre-bind state/choice/terminal inventory and exact final normal/invoke/pad/storage/data-label checks |
| `llvm/cff/transition_proof.{hpp,cpp}`, `llvm/cff/dispatch_proof.{hpp,cpp}` | Exact live-state wrapping decode matcher and bounded complete gap-comparison-tree verification |
| `llvm/tests/hybrid_flow_fixture.hpp`, `llvm/tests/hybrid_flow_contract.cpp` | Production binder/codec fixture, 29 valid-IR flow mutants and seed/constant/gap-pivot/body-order positives |
| `demo/hybrid_eh_fixture.cpp`, `demo/hybrid_eh_cases.py`, `demo/check_cff_hybrid_eh.py` | Actual C++ cleanup/catch/rethrow/recursion, invoke/shared-pad PHIs, paired switches with duplicate/default destinations, scope/strict/model negatives and linked normal-dispatch presence |
| `demo/nonlocal_fixture.cpp`, `demo/check_cff_nonlocal.py` | Legal real setjmp baseline, alias/call-site/function control attributes, region-owner rejection and ordinary-control positives |
| `llvm/cff/validation.cpp`, `llvm/cff/block_pad.cpp`, `llvm/cff/ssa_lower.cpp`, `llvm/cff/switch_lower.cpp`, `switch_lower_edges.{hpp,cpp}`, `llvm/cff/state_rewrite.cpp`, `llvm/cff/dispatch_tree.cpp` | Reachability/shape preflight, padding, SSA/PHI, pure switch lowering/coverage adapter, transition rewrite and comparison tree |
| `llvm/cff/state_layout.{hpp,cpp}`, `llvm/cff/transition_encode.{hpp,cpp}` | Seeded state layout, gap pivots, and state-dependent encoded deltas |
| `llvm/cff/block_layout.cpp` | Seeded physical order of flattened body blocks |
| `llvm/cff/constant_hide.cpp`, `llvm/cff/scalar_mask.{hpp,cpp}` | Typed i1-i128 literal reconstruction and separately testable lane-based state masks |
| `llvm/cff/compare_hide.cpp`, `llvm/cff/compare_codec.{hpp,cpp}` | Independent i2-i128 constant-equality strategy and finite-width bijection expressions |
| `llvm/cff/call_indirect.cpp` | Selected deep-strategy direct internal call routing through volatile pointer slots |
| `llvm/cff/reference_routes.hpp`, `llvm/cff/reference_sites.cpp` | Independent reference-route contract, direct-reference discovery and explicit ABI/budget eligibility |
| `llvm/cff/reference_table.cpp` | Seeded per-invocation table and use normalization, entry-storage hoist and initializer preparation |
| `llvm/cff/reference_bind.cpp`, `llvm/cff/reference_proof.cpp` | Late state-index binding, actual bounded table/index/target validation and private metadata removal |
| `llvm/cff/import_routes.{hpp,cpp}` | Independent strong-declaration strategy over shared scalar-reference discovery/normalization/binding and separate budgets/mask domain |
| `llvm/cff/import_table.cpp` | Complete imported-slot initialization generated after structural normalization/first SSA, without a new resolver or OS operation |
| `llvm/cff/import_proof.cpp` | Exact imported mask/decoded-slot/table/target proof and actual final dispatcher-state reachability |
| `llvm/tests/import_contract.cpp` | Twenty-three import table/profile/layout/graph/canceled-dependency/fake-state/dispatcher/escape/orphan/unused-consumer mutations |
| `demo/check_cff_imports.py` | Separate-provider DLL address/callback/PHI/select/effect/seed/mixed/source-O2/target-32/C++ ABI tests, private-input/final-erasure negatives and optimizer-effect regression |
| `demo/cff_import_evidence.py`, `demo/measure_cff_imports.py` | Imported-domain final presence and isolated plain/CFG/import/frame/preparation costs with a fixed provider DLL |
| `llvm/tests/reference_contract.cpp` | Corrupted table/target/index/state, escape, incomplete initialization and live-dependency negatives |
| `demo/reference_cases.py`, `demo/check_cff_references.py` | ABI/effects/recursive/reentrant/thread/address/PHI fixtures, source/O2 requests, seed and final-code negatives |
| `demo/cff_reference_evidence.py`, `demo/measure_cff_references.py` | Scoped linked reference-key/indirect-transfer presence and opt-in plain/CFG/legacy/table costs |
| `llvm/cff/decoy_transition.cpp` | Selected deep-strategy alternate encoded deltas on a corrupted-state range |
| `src/path_fold/value.hpp`, `tools/path_fold_reference.py` | Internal version1 modular fold model and independent build reference/serialization |
| `llvm/cff/path_fold.hpp`, `llvm/cff/path_fold_emit.cpp` | Eight-lane volatile runtime arithmetic and current-state event decoding |
| `src/path_fold/marker.{hpp,cpp}`, `llvm/cff/path_fold_{marker.hpp,sites.hpp,sites.cpp,retain.cpp,bind.cpp}` | Private marker ABI/reference, closed site discovery, source retention and registered final-state binding |
| `llvm/cff/path_fold_{proof,seal}.cpp`, `llvm/tests/path_fold_seal.cpp` | Actual-IR arithmetic/span proof plus frozen original storage/event/body-state contract and coherent mutation tests |
| `tests/path_fold_sites{,_harness}.cpp`, `tests/path_fold_plain_harness.cpp`, `tests/path_fold_site_cases.py`, `demo/check_cff_path_fold_sites.py`, `demo/cff_path_fold_evidence.py` | Whole/hybrid/loop source execution, typed refusals, ordinary modes, changed-state checks and scoped final evidence |
| `llvm/tests/path_fold_fixture.cpp`, `tests/path_fold_harness.cpp`, `demo/check_cff_path_fold.py` | Actual emitted-IR/value/reference equivalence, transcript/state mutations and none/O2/IPO contract |
| `demo/CMakeLists.txt`, `demo/cmake/Configure.cmake`, `demo/demo_config.hpp.in` | Fixed demo build pipeline, option validation, generated runtime settings |
| `demo/bootstrap/{entry,config,environment,release,bridge}.cpp`, `flow.hpp` | Ordered bootstrap stages, settings, gate, payload release, SDK dispatch, and internal contracts |
| `demo/bootstrap/{handoff.hpp,session.cpp,lifecycle.cpp,support.cpp,buffer.hpp,buffer.cpp}` | Version2 owned handoff, lifecycle protocol and exception-safe state/image/plaintext cleanup |
| `demo/bootstrap/path_events.hpp` | Wrapper for private generated per-build startup descriptors |
| `demo/bootstrap/key_material.cpp`, `key_expansion.{hpp,cpp}` | Real-context adapter and selected shared record validation/actual-fold expansion with erased serialization |
| `demo/bootstrap/failed_release.cpp` | Optional failure selection after closing/draining the real session |
| `demo/bootstrap/{decoy.hpp,decoy_session.cpp,decoy_preparation.cpp,decoy_key.cpp,decoy_release.cpp}` | Independent fold/image ownership, selected preparation/key helpers and hybrid decrypt/load/entry/unload flow |
| `demo/cmake/Packaging.cmake`, `tools/{release_plan,prepare_release,atomic_artifact}.py` | Exact child/report binding, private input generation, atomic writes and raw-link/data-fill/final-report DAG |
| `demo/cmake/ReleaseMaterial.cmake`, `tools/{release_material,prepare_release_material}.py` | Independent early main/decoy roots, headers and shared fold model |
| `tools/pe_layout.py`, `pe_relocations.py`, `code_subject.py`, `code_observation.py` | Shared bounded PE layout, DIR64 metadata, explicit subject scopes and owner-domain canonical host digest model |
| `tools/{coff_symbols,coff_layout,coff_relocations,function_subject}.py` | Separate classic-COFF decoding, ownership and exact final-link relocation/extent proof; detailed source/test map in the function subject guide |
| `tests/measurement/function_data_{fixture.cpp,targets.py}` | Actual data-section relocation mapping, O0/O2 execution/native capture and fail-closed retained-label tests |
| `llvm/cff/generated_ownership.{hpp,cpp}`, `tools/{generated_ownership,function_inventory,generated_function_subject}.py` | Typed compiler helper provenance and complete generated-code subjects; detailed source/test map in the generated-subject guide |
| `tools/{reference_identity,code_reference}.py`, `src/measurement/reference*`, `tests/measurement/*reference*` | Independent reference key/payload framing, reused archive AEAD and move-owned native decode; detailed file map and boundaries in the reference codec guide |
| `tools/{reference_plan,reference_slots,prepare_references,finalize_references,pe_data_patch}.py`, `cmake/ReferenceSlots.cmake`, `tests/measurement/*slot*` | Frozen selection, private read-only slots and data-only finalization; full file map and dependency/negative tests in the reserved reference guide |
| `src/measurement/observer*`, `tests/measurement/*observer*` | Private owned observations, exact age bounds, independent cache publication and lifecycle/failure tests; full file map in the owned observation guide |
| `src/release/measured*`, `tools/measured_release.py`, `tests/measurement/*measured_key*` | Complete-observation key expansion, v2 record admission and actual/fault/CFF consumers; detailed map in the measured key guide |
| `measurement/`, `src/measurement/` | Private source-only raw capture target; separate ownership, admission, framing/read and orchestration modules |
| `backends/windows_user/measurement/`, `tests/measurement/` | Windows module/RX/QPC boundary; real CNG, fault/erasure/lifetime and twelve-core-body CFF contracts; detailed file map in the capture guide |
| `demo/{check_code_subjects,code_subject_cases}.py` | Actual mapped-DLL/LLVM/digest evidence and malformed descriptor/range/relocation/unwind controls |
| `demo/cmake/PayloadBinding.cmake`, `tools/{payload_binding,prepare_payload_binding,post_mixed_binding}.py` | Strict private consumer recipe/reference, frozen-plan late mixed private roots and sites, actual compiler input fingerprint and package consistency |
| `demo/cmake/PostRelease{,Checks}.cmake`, `tools/{prepare_scope_material,post_reference_plan,finalize_post_release}.py` | Optional early root, two-role plan with opt-in mixed private/edge identity, exact data composition and actual loaded checks |
| `tools/post_subjects.py`, `demo/check_post_subjects.py` | Early exact section/function selectors, strict actual-object consumer inputs and host-composer acceptance |
| `demo/cmake/PostSubjects.cmake`, `demo/recipes/post_functions.json` | Opt-in production function profile, configuration validation and per-role actual-object bindings |
| `demo/bootstrap/post_{handoff.hpp,preparation.cpp,dispatch.cpp,owned_dispatch.cpp}`, `demo/post_payload.{hpp,cpp}` | Session-owned observations, exact registered source admission, opt-in owned-site allowlist and invocation-owned child scopes |
| `llvm/cff/owner_post_flow.*`, `owner_post_child_flow.*`, `owner_post_mixed_child_flow.*` | Separate parent creator-to-role/ready and child role-to-Snapshot/Scope/site compiler checks; mixed pointer/query source seal |
| `tools/post_role_join.py`, `demo/check_post_role_join.py` | Exact parent/child/release final join and swapped role, shifted slot, remapped site and stale-artifact refusals |
| `demo/{check_post_release.py,post_release_probe.cpp,post_completion_cases.py}` | Actual two-module normal/EH/failure boundaries and composed-finalizer refusals |
| `demo/post_foreign_context.cpp` | Test-only second SDK factory for actual equal-generation key/readiness/post origin negatives |
| `demo/cmake/PayloadBindingChecks.cmake`, `demo/{payload_binding_smoke.cpp,check_payload_binding.py,check_post_mixed_binding.py,check_owned_return_flow.py,release_material_cases.py}` | Actual detached/fake-source refusal, strict schema1 owned query return-flow mutation, late mixed-plan/root input refusals, package controls and early/late non-rewrite contracts |
| `demo/cmake/PayloadMeasurements.cmake`, `demo/measure_payload.cpp` | Existing CFF measurement target's strict actual-entry/CNG/owned-context harness |
| `demo/cmake/SessionChecks.cmake`, `demo/session_{fixture.hpp,backend.cpp,crypto.cpp,common.cpp,protocol.cpp,smoke.cpp,fold.cpp}`, `session_fold_reference.py` | Isolated allocation/loader observations around production CNG, cleanup/order/protocol failures and private-plan transcript checks |
| `demo/{session_build.py,release_flow_mutations.py,release_fault_smoke.cpp,check_session_cff.py}` | Actual73-body source CFF, native record/crypto support and19 bounded post-emission runtime faults |
| `demo/check_release_plan.py`, `demo/lifetime_smoke.cpp` | Strict/fresh host plan, actual AEAD and final-image checks; real DLL exceptions/recovery/reentrant/thread/unload checks |
| `demo/payload.cpp`, `demo/pack_payload.py` | Sample inner DLL and AES-GCM packaging |
| `demo/cmake/Decoy{Configure,Pipeline,Checks}.cmake` | Optional independent decoy configuration/build/test domain |
| `demo/cmake/DecoyRuntime.cmake`, `DecoyRuntimeChecks.cmake`, `demo/recipes/bootstrap-decoy.json` | Explicit outer-decoy variants, eight required event owners and independent runtime/negative gates |
| `demo/decoy/runtime_smoke.cpp` | Actual CNG/DLL accepted/denied/tampered behavior, host observer exceptions, nested and four-thread image cleanup |
| `demo/check_decoy_runtime.py`, `demo/decoy/runtime_{build,mutations}.py` | Actual81-definition none/O2 protection, independent fold reference, native linking/final gates and33 LLVM-valid real/decoy faults |
| `demo/decoy/runtime_{fixture.hpp,backend.cpp,crypto.cpp,cases.cpp,fault_smoke.cpp}` | Exact-child loader observations around production CNG,21 allocation faults, closed-context/record/provider/refusal cases and observed erasure |
| `demo/decoy/{handoff.hpp,payload.cpp,compute.cpp,smoke.cpp}` | Separate POD entry, two-source sentinel sample and actual loaded entry tests |
| `tools/{decoy_contract,check_decoy_input}.py`, `demo/pack_decoy.py` | Source ABI/init policy, exact child coverage identity and decoy AEAD producer |
| `demo/{decoy_test_support,check_decoy_package,check_decoy_build}.py`, `demo/recipes/decoy.json` | Independent package/role/refusal/linked evidence and none/O2/IPO incremental build tests |
| `tests/check_atomic_artifact.py` | Real Windows sharing handles, persistent/unknown failure preservation and bounded host replace/unlink policy checks |
| `demo/{smoke,environment_smoke}.cpp` | Runtime stage and detector-registry smoke checks |
| `demo/check_cff.py`, `demo/check_cff_failures.py`, `demo/check_cff_markers.py`, `demo/check_cff_switch.py`, `demo/check_cff_ssa.py`, `demo/check_cff_tiny.py` | Configured IR/report shape, fail-closed and marked selection, switch behavior, SSA/PHI and small-CFG execution checks |
| `demo/check_cff_region.py` | Explicit region execution, invalid-region rejection, request manifest and linked-code gate |
| `demo/check_cff_variation.py`, `demo/check_cff_wrong_state.py`, `demo/check_cff_deep_constants.py`, `demo/check_cff_deep_calls.py`, `demo/check_cff_deep_decoys.py` | Cross-seed IR, wrong-state execution, deep-literal, linked indirect-call, and decoy checks |
| `demo/check_cff_optimization.py` | O2 marker retention, late-pass execution, and rejection of CFF erased by a later optimizer |
| `demo/check_cff_requests.py` | Request-manifest coverage and optimized-away versus missing failure cases |
| `demo/check_cff_recipes.py` | Composed recipe execution, strict site failure, provenance, configuration and dependency rejection |
| `demo/check_cff_split.py`, `demo/measure_cff_split.py` | Split/SSA/memory/tail differential and budget failures; opt-in isolated size/startup/hot-call cost |
| `demo/check_cff_normalization.py`, `demo/measure_cff_normalization.py` | Dedup/exit/alias differential and failure cases; opt-in paired normalization costs |
| `llvm/tests/expression_fixture.cpp`, `demo/check_cff_expressions.py` | Execute the actual production predicate/mix emitters against boundary and pseudorandom vectors; corrupted-observation negative |
| `demo/check_cff_transition_depth.py`, `demo/check_cff_bogus.py` | Opaque/junk/clone/synthesis combinations, memory/recursive/reentrant equivalence, origins, unsafe donors, budgets and feature-erasure negatives |
| `demo/cff_transition_evidence.py` | Scoped final x86 COFF predicate/product and public coefficient evidence, consumed by the linked gate |
| `llvm/tests/scalar_fixture.cpp`, `demo/check_cff_scalar_expressions.py` | Production expressions at every admitted width, exhaustive small-width injectivity and O0/O2 reference checks |
| `demo/scalar_cases.py`, `demo/check_cff_typed_data.py` | Typed-data IR fixtures separate from full-pass differential, source relocation, wrong-key and unsupported-type checks |
| `demo/cff_data_evidence.py`, `demo/measure_cff_typed_data.py` | Separate literal/comparison retention evidence, isolated data-erasure proof and opt-in paired scalar/equality costs |
| `demo/measure_cff_misleading.py` | Opt-in paired size, transform/link time, startup and hot-call costs for each misleading-CFG component |
| `demo/check_linked_cff.py`, `demo/check_cff_final_report.py` | Demo-only linked PE shape gate, image-bound final report, and negative report check |
| `demo/cff_builder_receipt.py`, `demo/cff_builder_subjects.py`, `demo/cff_builder_entry_states.py`, `demo/cff_builder_replay.py` | Explicit trusted-builder byte receipt, exact COFF-to-PE subjects, owner entry states and deterministic compiler replay; the linked gate consumes their distinct proofs |
| `demo/cff_archive_origin_contract.py`, `demo/cff_archive_origin.py`, `tests/contribution/archive_origin_cases.py` | Closed 20-role O2 archive record, selected producer replay and package authentication, with actual finalizer positives and refusals |
| `tests/contribution/builder_replay_cases.py` | Actual none/O2+archive replay, paired COFF/PE conditional-move edits, legacy admission, role/record refusal and output-alias safety |
| `demo/cff_builder_local_callees.py`, `tests/contribution/builder_local_callee_cases.py` | Bounded local binding-call and status route proof with actual none/O2+archive COFF/PE argument, frame and state-slot bypass regressions |
| `demo/measure_cff.{py,cpp}` | Opt-in same-IR baseline and paired startup/hot-call overhead measurement |
| `demo/measure_marker_cost.py`, `demo/marker_cost.cpp` | Opt-in O2 comparison of inline versus marked `noinline` calls without CFF |
| `demo/measure_cff_region.py` | Opt-in same-IR region size and hot-call measurement |
| `tests/CMakeLists.txt`, `tests/{sdk_smoke,load_smoke,sample_dll}.cpp` | SDK wiring and ordinary Windows DLL load checks |
| `tests/sdk_snapshot.cpp` | Owned legacy table snapshots, callback/context pairing, reentrant publication and borrowed in-flight lifetime |

## Build the SDK smoke test

Use any CMake generator and a C++17 compiler. For example:

```sh
cmake -S native -B build/native -DPYOBF_NATIVE_BUILD_SMOKE=ON
cmake --build build/native --config Debug
ctest --test-dir build/native -C Debug --output-on-failure
```

To compile the SDK source into a user's CMake target:

```cmake
add_subdirectory(path/to/pyobfuscator/native pyobf_native_build)
target_link_libraries(my_dll PRIVATE pyobf_native_sdk)
```

`pyobf_native_sdk` is an INTERFACE source target. It compiles the SDK source in the consumer;
no prebuilt SDK library is distributed. The SDK adds no explicit PE export to a general DLL.
The caller's export policy still controls what its final binary exposes. When added as a
subproject, smoke targets are off by default; set `PYOBF_NATIVE_BUILD_SMOKE=ON` to opt in.
The `BootstrapApi::call` callback is `noexcept`; client callbacks must use that function type.
An exception from a callback terminates the process, matching `call_bootstrap`'s existing
`noexcept` boundary.
Binding copies the v1 table, so the table object may expire or change after bind returns.
Userdata and callback-code lifetime remain borrowed through all already captured calls.
Unbind stops later captures and does not wait for a callback; callers synchronize teardown.
Snapshot synchronization uses backend atomic/pause operations through the semantic macros.

## LLVM pass and encrypted bootstrap demonstration

The additive [owned context runtime](../docs/NATIVE_CONTEXT.md) is enabled separately with
`PYOBF_NATIVE_BUILD_CONTEXT_RUNTIME=ON`. Its move-only owner, retained leases, active frames
and Windows callback-provider references have lifecycle and actual CFF tests. The existing
demo now uses a [version2 owned handoff](../docs/NATIVE_DEMO_HANDOFF.md). Context lifetime and
strict publication are integrated; measured readiness and path-bound key release remain open.

The CFF plugin requires LLVM development files matching the `opt` and Clang toolchain. The
full demonstration currently requires Windows user mode, Clang, `opt`, `llvm-link`,
`llvm-objdump`, and Python with
`cryptography` installed (the repository's `.[machine]` extra supplies it). With MSYS2 CLANG64
and the repository virtual environment, configure it as follows:

```powershell
$clang64 = Join-Path $env:MSYS2_ROOT 'clang64'
$cmake = Join-Path $clang64 'bin/cmake.exe'
$ctest = Join-Path $clang64 'bin/ctest.exe'
$ninja = Join-Path $clang64 'bin/ninja.exe'
$clang = Join-Path $clang64 'bin/clang++.exe'
$llvm = Join-Path $clang64 'lib/cmake/llvm'
$opt = Join-Path $clang64 'bin/opt.exe'
$python = (Resolve-Path '.venv/Scripts/python.exe').Path
& $cmake -S native -B build/native-clang64 -G Ninja `
  "-DCMAKE_MAKE_PROGRAM=$ninja" `
  "-DCMAKE_CXX_COMPILER=$clang" `
  "-DLLVM_DIR=$llvm" `
  "-DPYOBF_NATIVE_OPT_EXECUTABLE=$opt" `
  "-DPython3_EXECUTABLE=$python" `
  -DPYOBF_NATIVE_BUILD_LLVM_PASS=ON -DPYOBF_NATIVE_BUILD_DEMO=ON
& $cmake --build build/native-clang64
& $ctest --test-dir build/native-clang64 --output-on-failure
& $cmake --build build/native-clang64 --target pyobf_native_demo_measure_cff
& $cmake --build build/native-clang64 --target pyobf_native_demo_measure_marker_cost
& $cmake --build build/native-clang64 --target pyobf_native_demo_measure_cff_region
& $cmake --build build/native-clang64 --target pyobf_native_measure_contribution_alias
& $cmake --build build/native-clang64 --target pyobf_native_measure_contribution_scalars
& $cmake --build build/native-clang64 --target pyobf_native_measure_contribution_cost
```

Set `MSYS2_ROOT` to your MSYS2 installation directory before running this example from
the repository root. The pass name is `pyobf-native-cff`.
The optional measurement target writes `build/native-clang64/demo/payload.cff.measurements.json`.
It builds an untransformed DLL from the same linked IR, records whole-file and `.text` sizes,
and alternates 40 load/first-call pairs plus five 500,000-call hot-path samples. It checks
both DLLs return the same results. Timings are medians for the current machine and are not
CI thresholds; this samples one exported demo function, not the encrypted outer startup.
The second target writes `payload.cff.marker_cost.json`: it compares two O2 DLLs before
CFF, one with an inlined helper and one with the real source marker forcing a call boundary.
This isolates the marker's inlining cost for one small function.
The region target writes `payload.cff.region.measurements.json` from an O0 IR fixture with
an O2 caller; it reports linked image and `.text` size, selected-symbol instruction count,
and the median of five hot-call runs. It is a local comparison, not a CI threshold.
The contribution-alias target writes `tests/contribution/alias.measurements.json`. It compares
the same actual CNG source fixture with only compute deduplication off/on: six original
logical edges, six/five physical acquisitions and unchanged common-exit/split/SDK coverage.
Seven alternating pairs at one and 64 workloads record fresh-process elapsed time and
`steady_clock` loop time after one checked warmup. Each workload checks 81 top-level results
and 52 ordinary-call effects. Records include image/input hashes, actual component seeds,
sizes, raw samples and four invalid-harness refusals. This fixed Windows fixture does not
measure complete encrypted-bootstrap cost or imply a general performance improvement.
The scalar contribution target writes `tests/contribution/scalar.measurements.json`.
It compares scalar-off/on images with the same retained source and grouped automatic
owned-CNG policy. Normal results, source refusals, linked images and scalar removal
controls must pass before five alternating warm pairs at one and 64 workloads
record code/data size, process time and checked loop time. The fixed source-none
sample is one D6 cost datum, not a general speedup or bootstrap measurement.
The contribution on/off target writes `tests/contribution/contribution.measurements.json`.
It compares one authored grouped automatic owned-CNG fixture with and without runtime
contribution. The baseline removes no-op marker calls and has a different request
inventory and source-error behavior; the record includes those inputs and any
downstream component-count changes. Actual effects, protected source refusals,
both linked images and forged/removed-gate reports pass before five alternating
warm pairs at one and 64 workloads. This source-none sample includes the host's
manual pre-entry CNG query and is not an isolated query cost or a D6 closure claim.
`-pyobf-cff-functions=foo,bar` adds exact IR names; the legacy singular option still works.
Include `pyobfuscator_native/cff_marker.hpp` and mark a user function definition with
`PYOBF_NATIVE_CFF`; SDK-owned definitions use `PYOBF_NATIVE_CFF_SDK`. Outer glue uses
`PYOBF_NATIVE_CFF_BOOTSTRAP` or explicit `PYOBF_NATIVE_CFF_BOOTSTRAP_EH`; the latter needs a
hybrid recipe and does not silently relax whole-function requests. The Clang IR annotations
survive `llvm-link` and are selected by default. Clang markers also add `noinline` and `used`:
an O2 build must retain the function and its call boundary until the late CFF pass, at the
cost of preventing normal inlining. A test demonstrates that running O2 again after CFF
erases this small fixture's dispatcher, and the linked gate rejects that output.
`-pyobf-cff-markers=false` disables that
discovery when explicit selection alone is required. The macros are empty for non-Clang SDK
builds; the current LLVM pass still requires Clang. CMake exposes `PYOBF_NATIVE_CFF_MARKERS`
(default ON) and `PYOBF_NATIVE_CFF_FUNCTIONS` for additional exact names. At least one marked
or explicit function or region is required.
The demo separately enables `PYOBF_NATIVE_DEMO_OUTER_CFF` by default. Its
`PYOBF_NATIVE_OUTER_CFF_CONFIG` defaults to `demo/recipes/bootstrap.json`, independent of payload
options; `PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT` selects `none` or ordinary `O2` before its late pass.
Default and triggered outer DLLs each emit their own requests, coverage and final JSON files
under the target-name prefix. Disabling outer CFF is an explicitly weaker plain-bootstrap
profile. Neither setting establishes path-bound release, owned oracle lifetime or device
authorization. Only marked authored glue is selected here; backend OS implementations remain
behind the same semantic macros and are not credited as transformed.
`-pyobf-cff-region=foo:region.start:out` selects a named single-entry/single-exit region
within `foo`; repeat the option for different functions. CMake accepts a semicolon-separated
`PYOBF_NATIVE_CFF_REGIONS` list with the same syntax. Region selection also enters the
pre-optimization request manifest. A region supersedes whole-function CFF for its function;
selecting that function for deep CFF at the same time is an error. The first region strategy,
`relative-tree-region`, rewrites only blocks reached from the named entry before the named
exit. The surrounding function remains ordinary code. It requires at least three region
blocks, a conditional branch, branch-only terminators, no external edge into a non-entry
region block, only branch/switch external predecessors of its entry, no PHI at a region
body or exit, no region-defined value used across blocks,
and an exit reachable from every region block. Unsupported selections fail with a reasoned
report. The row uses `coverage_kind=region-decision-flow`, and the linked-code gate sets
`decision_flow_verified` after checking the selected symbol. This is a deliberately narrower
SSA contract than whole-function CFF; neither the report nor symbol-level pattern check proves
that a white-box attacker cannot recover the original region.
The region pipeline also admits `runtime-contribution`, with explicit points or automatically
selected original edges. It freezes surrounding operations, resets state on external reentry
and checks the sole exit; generated routing does not inflate regional density. Other
components still reject in this scope. Source O2 must retain the named legal boundaries.
See [region contribution composition](../docs/NATIVE_CONTRIBUTION_GATES.md#region-composition)
for the source-marker linking rule, proof flag and execution/refusal tests.
`-pyobf-cff-strategy=relative-tree` selects the registered strategy,
`-pyobf-cff-seed=<integer>` changes its state layout; the CMake equivalent is
`PYOBF_NATIVE_CFF_SEED`. `-pyobf-cff-report=<path>` writes a per-function JSON report.
`-pyobf-cff-deep-functions=foo,bar` applies `relative-tree-deep` only to those selected
functions; each selected report row records its effective strategy. The CMake demo option
`PYOBF_NATIVE_CFF_DEEP_FUNCTIONS` defaults to `pyobf_demo_compute` when source markers are
enabled; strict payload mode also applies that selection to its private math helper.
Currently the deep strategy reconstructs eligible 32-bit integer operands from the
runtime CFF state, routes direct calls to defined functions through volatile pointer slots,
and inserts alternate encoded state deltas selected by a lower-range comparison. Correct
execution never selects the decoy delta; the linked demo checks that its conditional move
remains present. A forced decoy changes the fixture's behavior. The decoy is not an
authorization check and does not guarantee a safe result for every invalid state.
Calls to declarations, intrinsics, recursive self-calls, calls with operand bundles, and
`musttail` calls retain their original form. A deep selection with neither an eligible
literal nor an eligible internal call fails as unsupported. This is an obfuscation layer,
not a secret-key boundary; emitted code still contains the reconstruction and call targets.
Its statuses are `transformed`,
`unselected`, `declaration`, `unsupported`, `missing`, and `optimized-away`; marked rows also
include `marker`. `-passes=pyobf-native-cff-requests` with
`-pyobf-cff-requests-output=<path>` saves exact and marked requests before optimization.
The transforming pass reads that file with `-pyobf-cff-requests-input=<path>`; requested
definitions absent later are reported as `optimized-away` and fail the build. The demo
generates `payload.cff.requests.json` before its CFF stage and records `requested` and
`retained` per row. Without a prior request manifest, an absent exact name remains `missing`.
Unsupported or missing selected
functions fail the `opt` command after recording the reason. The relative-tree strategy accepts
ordinary branches, switches, and returns, no unreachable blocks,
ordinary PHI nodes, and sized cross-block SSA values. It rejects entry PHIs, unsized values,
exception edges in the default whole scope, coroutine intrinsics, and other terminators
outside this set. Explicit `hybrid-eh` coverage preserves Windows GNU landingpad
boundaries while routing normal continuations through the dispatcher; see
[hybrid scope](../docs/NATIVE_RECIPES.md#explicit-hybrid-exception-scope) for limits. Before
flattening, LLVM's demotion
utilities save PHI and cross-block values in entry-allocated slots; this preserves normal
loop and merge behavior but adds stack traffic. The strategy uses seeded, nonuniform
state IDs, shuffled body order, varied comparison-tree splits with bounded depth,
comparison pivots between valid states, and runtime state-dependent decoding of
relative transitions. Selected switches are lowered into separate conditional blocks before
flattening; their condition is stored in an entry alloca so the rewritten blocks have valid SSA.
The original switch shape is not retained. These values remain recoverable in a white-box analysis.
One- or two-block functions receive entry transitions before flattening so they still get a
dispatcher. This does not conceal a trivial return constant; it only gives the tiny function
the same CFF shape and a verifiable linked-code gate. The report labels original functions
with a real conditional branch or switch as `coverage_kind=decision-flow`; those without one
are `shape-only`. The final report sets `decision_flow_verified` only for the former. In the
current demo, straight-line context helpers and the return-only SDK backend placeholder are
shape-only; snapshot synchronization loops add real decisions in base SDK definitions. A verified CFF shape is not
itself a claim that a tiny helper is protected.
`-pyobf-cff-require-decision-flow=true` rejects selected shape-only functions with an
`unsupported` report. The CMake equivalent is `PYOBF_NATIVE_CFF_REQUIRE_DECISION_FLOW=ON`.
It is off by default because several context helpers and the backend placeholder have no original decision;
turning it on for all demo markers deliberately fails until selection or source changes.
The linked demo gate also checks the deep strategy's literal-mixing instruction in its
selected symbol. The executable test changes one literal's state read and expects an
incorrect result, while an unmodified build preserves both branches.

The demo compiles the sample payload and backend SDK sources to separate IR files, combines
them with `llvm-link`, then runs the pass before compiling and linking the inner DLL. By default
it selects `pyobf_demo_compute`, `pyobf_native_inner_entry`, the strict private math helper,
all five base SDK definitions,42 context definitions and two contribution client/gate
definitions. Explicit decoupled mode omits the private helper and those two client definitions.
Base SDK functions are `bind_bootstrap_api`, `unbind_bootstrap_api`,
`call_bootstrap`, `inspect_current_process`, and the backend's `detail::inspect_current_process`;
`build/native-clang64/demo/payload.cff.coverage.json`
records every definition and declaration in that combined input module.
`payload.cff.final.json` is written only after every selected linked symbol passes the
shape gate. It records `transform_status=transformed`, `status=final-binary-verified`, and
SHA-256 of the exact DLL and input report. The packer depends on this file; a wrong DLL
cannot acquire a verified report in the negative test. Generated C++ library helpers are
outside this SDK-authored selection. The first report is input-IR coverage, and the `llvm-objdump` test checks
the selected symbols' expected shape in this one linked Windows demo. This check runs before
AES-GCM packaging, so its failure stops the outer build. It is not a general proof that
arbitrary optimizer/linker settings preserve the transform. A new demo strategy needs its own
linked-binary checker before it can be selected.
The default list comes from source annotations, rather than C++ mangled names in CMake. New
SDK definitions need the SDK marker; the demo test expects49 strict annotated SDK
definitions (47 in decoupled mode) and fails if one loses its marker.
The demo IR custom commands use compiler depfiles, so changes to project headers rebuild the
linked LLVM module before CFF.

The build links and verifies the inner DLL before encryption, embeds its AES-256-GCM
ciphertext and finalizes a masked-key record in the outer DLL. Private startup events
reconstruct the transient key. The outer DLL's exported `pyobf_native_demo_run` performs
the fixed stage sequence. Its test-only `corrupt` argument changes one ciphertext byte: the
authentication failure must stop before the inner DLL loads. A second test-only outer build
registers an always-triggered detector and must stop before decryption. `payload.cff.ll`
and the plaintext inner DLL remain in the **build directory**; distribute only the intended
outer artifact. The runtime writes a temporary plaintext DLL for `LoadLibrary` and deletes it
after unloading. This is a pipeline prototype, not a confidentiality claim against someone
who can recover the local key data path, observe the transient key, or read the temporary file.

`PYOBF_NATIVE_BACKEND=windows_user` selects the standard Windows user-mode backend.
`PYOBF_NATIVE_DEMO_ENV_DETECTORS` selects names from its manifest (default `placeholder`), and
`PYOBF_NATIVE_DEMO_ALLOW_UNAVAILABLE=OFF` blocks its unavailable result. The runtime report
contains each detector name and result plus an aggregate. `triggered` dominates `unavailable`,
which dominates `clear`; invalid or empty selections block. The default detector returns
`unavailable`, and the clear/triggered implementations are test fixtures excluded from the
normal outer DLL. Bootstrap call sites use semantic macros in
`include/pyobfuscator_native/system_ops.hpp`; the selected backend owns OS calls. The example
inner DLL has no user TLS callback, global constructor, DllMain side effect, or exported data.
Those cases and a general loader are unsupported.
The strict alternate CTest profile checks that unavailable blocks before decryption.

## Report contracts

The request manifest records exact and marked names before optimization. The transform report
has `module`, `strategy`, and `functions`; each row records the exact IR name, `requested`,
`selected`, `retained`, and `status`, with `reason` for failures and `coverage_kind` for
transformed definitions. This report covers the combined input LLVM module, not linked code.
Implicit component invokers additionally report `generated`, `generation_component`,
`generated_owner` and `generated_site`; they are selected and verified while `requested=false`
keeps them separate from original requests. Their baseline straight-line body is shape-only.
The final report copies those rows, preserves `transform_status`, and sets
`final-binary-verified` only after the linked PE gate checks every selected symbol. It binds
that result to the DLL and transform report with SHA-256. In the default strict demo, three user
and49 SDK-authored definitions pass the linked gate; straight-line helpers remain `shape-only`.
The checker is specific to the CLANG64 demo and needs extension for other targets or stripped
images. The tested CMake IPO profile retains CFF because the transformed IR is compiled to a
native object before the final link. Running an optimizer after the CFF pass can erase it.

The runtime environment `Report` in `environment.hpp` has `valid`, `overall`, `count`, and up
to eight named `observations`. The backend registers detector functions; common code validates
the complete selection before invoking any detector and combines results as
`triggered > unavailable > clear`. The bootstrap stores the in-memory report before release
and uses `valid` plus the configured unavailable policy to decide whether to proceed. The SDK
demo operation returns only the aggregate status. No detailed detector report is exported or
written to disk by default; a future diagnostic surface needs an explicit interface and policy.

Windows is the first runtime target. The `portable_stub` backend retains a non-Windows SDK
placeholder, but cannot build the encrypted demonstration. The SDK smoke previously passed with
MSVC and MSYS2 CLANG64. The current CLANG64 demo, CFF coverage/failure paths, blocked detector,
and SDK smoke tests pass together; MSVC has not built the CFF demo.
Use the repository source tree for now. No Python packaging rule for `native/` has been added
or validated.
See [the native design guide](../docs/NATIVE.md) for integration and security boundaries.

## Add a CFF strategy

1. Put its transformation in its own `llvm/cff/<strategy>.cpp`; keep reusable validation and
   dispatcher helpers in separate files. Export a `Strategy` descriptor with a unique name,
   a preflight validator returning an error reason, and an apply callback.
2. Add that descriptor to the explicit table in `llvm/cff/registry.cpp`, and its source to
   `llvm/CMakeLists.txt`. `pass.cpp` owns selection and reporting, so a new strategy does not
   add another LLVM plugin entry point.
3. Add a positive IR-shape/behavior test and an unsupported-shape case. A selected function
   must appear as `transformed` or fail the build with `unsupported`/`missing` in the report.

Composable component hooks live in `component_registry.cpp`; see the
[component extension contract](../docs/NATIVE_RECIPES.md#adding-a-component). A component that
wraps the normal encoded transition registers a pure entry-identity emitter in
`transition_registry.cpp` and references it from `Component::transition_model`. Add its
symbolic/constant identity and graph-refusal cases before admitting composition. Its own
emitter remains a separate file; `TransitionLayers` and the existing normal/source consumers
own proof composition. A component that
needs helpers registers `module_prepare`, generates internal definitions before scope sealing,
and returns a `GeneratedDefinition` for every helper with its original owner/site/component.
`module_prepare.cpp` validates that inventory and selects each helper with baseline CFF.
An explicit `support` override may add registered components already enabled by the original
owner, without resetting the baseline or recursively requesting the creating component.
Call-frame invokers use this to receive required preparation support and their owner's budgets.
Source calls remain available until coverage discovery; a later normalize hook records the
actual source-to-generated-use relocation. No normalize/bind callback creates late helpers.

## Add a backend and environment detector

1. Copy `backends/template/Backend.cmake.in` to `backends/<name>/Backend.cmake`. Give it an ID,
   SDK sources, capabilities, system-operation sources, environment sources, detector names,
   and required link libraries. `cmake/Backends.cmake` loads exactly this manifest.
2. Implement the operations declared in `include/pyobfuscator_native/system_ops.hpp` in
   backend-owned files. Keep target APIs inside those files; bootstrap call sites retain the
   semantic macros. Only set `PYOBF_NATIVE_BACKEND_CAN_ENCRYPTED_DEMO=TRUE` when all demo
   operations and an environment catalog exist.
3. Put each environment detector in its own backend file. Return `clear`, `unavailable`, or
   `triggered` without performing policy decisions. Add its name and function to that backend's
   `environment/registry.cpp`, add the source and name to its `Backend.cmake`, then select it
   with `PYOBF_NATIVE_DEMO_ENV_DETECTORS`. The common `src/environment.cpp` creates the named
   report and aggregate; `demo/bootstrap/environment.cpp` applies the early release policy.
4. Add a registry test and a bootstrap gate test. A real detector must not be represented by
   the test-only clear/triggered fixtures. The public SDK's `inspect_current_process` remains
   a separate unavailable placeholder until its backend implementation is provided.

To add a bootstrap subflow, declare it in `demo/bootstrap/flow.hpp`, put it in a dedicated
source file, list that file in `demo/CMakeLists.txt`, and call it in order from `entry.cpp`.
To add an SDK operation, extend the versioned table in `bootstrap_api.hpp`, route it in
`demo/bootstrap/bridge.cpp`, and add a test. Generated IDs identify operations; they are not
authorization material.

Post-release helper-selected host records accept exact private ownership manifests and CFF
reports through the existing finalizer and consumer argument seams. Production CMake wiring
and fresh ordinary/protected counterpart inventories are implemented with integration
checks for none, O2/archive/IPO/decoy and outer-CFF-OFF; see
[compiler-generated subjects](../docs/NATIVE_GENERATED_SUBJECTS.md).

The optional [owner reader/cache path](../docs/NATIVE_OWNER_READERS.md) is being implemented
with separate byte-reading algorithms, early source generation and owned callback lifetime.
Its actual same-subject execution, callback/binding compiler and final-image gates, and
shared-reader/alias/tamper refusals pass for none/O2, including parent IPO. Pre-key and both
post-release roles now bind generated readers through the existing reference plans; the
ordinary outer-CFF-OFF path also executes them. Composed production and paired release checks pass;
fixed generated creator functions and exact final creator code are checked. The POST
compiler reports now connect each parent creator to its role and each child role to
its Scope and selected site, and the final checker joins their exact artifacts.
This bounded flow proof does not establish individual-site machine survival or
independent generated-owner contribution; both report flags remain false.
The owner fixture additionally exercises actual same/split capture/codec DLL lifetime through
retained snapshots, using a private test factory and loader detach counters.
