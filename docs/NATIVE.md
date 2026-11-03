# Native protection prototype

The `native/` tree now has a source-only C++ SDK, an explicit LLVM CFF strategy registry, a
target-backend manifest, and an opt-in Windows
end-to-end bootstrap demonstration. The demonstrated build order is:

```text
independent early events -> strict source reference + payload/SDK C++ -> IR -> CFF -> verified inner DLL
    -> late exact-child plan -> AES-GCM ciphertext + masked-key record
    -> outer IR/CFF -> raw link -> reserved data fill -> exact final report
    -> owned context/environment/support events -> fold/key reconstruction -> decrypt -> LoadLibrary
    -> owned handoff/strict inner publication -> inner entry -> retire/unload/erase
```

The SDK is compiled into the user's target rather than distributed as a prebuilt `.lib`. A
generic protected DLL has no explicit Python dispatcher export. On ELF and Mach-O, visibility
of linked C++ symbols depends on the host target's build settings and is not validated here.
The planned Python-specialized native component will use the same SDK and build pipeline, then
add a Python dispatcher export for the SDK's machine-verification operation. It is part of the
Python bootstrap: native machine verification is disabled for its own startup release, and
function-level lazy decryption is disabled. Python calls the exported operation on demand to
authorize its separately encrypted body. The native component itself is assumed to be
dumpable; it cannot be the confidentiality boundary for that body. The Python dispatcher,
machine verification, TPM use, and Python-body decryption are **not implemented** here.

## Current API and behavior

An optional [owned context runtime](NATIVE_CONTEXT.md) adds move-only owners, retained leases,
active-call references, irreversible close and Windows callback-module lifetime. Its 42
authored core definitions and five actual SDK definitions are exercised through CFF with and
without source O2. Scoped strict publication compares actual expected context identity and
never falls back to v1. The [demo owned handoff](NATIVE_DEMO_HANDOFF.md) integrates lifecycle
pairing and cleanup. Its opt-in post-release profile binds two actual parent/child code
observations to invocation-owned CFF consumers; the full configured model remains open. Lifecycle status does
not authorize a device.
The two-owner mixed POST extension is a bounded Windows x64 CLANG64 production
path. Its frozen original-edge plan drives separate owned release and measured
Scope private roots, the parent owned-site allowlist, and the child lease/Scope
ABI. The linked child PE verifies 7/4 owner edges without source O2 and 6/3
with PRE+POST/O2+archive; the packer and parent finalizer require both owners'
proofs and the cross-artifact role/site join. Actual linked plan, helper-call,
RSI prologue and unwind mutations are refused. The corresponding mixed tests
and legacy measured-only POST consumers passed in independent worktrees.
This establishes the stated local build and PE contract. An optional
[builder-fixed receipt](NATIVE_CONTRIBUTION_GATES.md#builder-fixed-mixed-post-receipt)
freezes the child PE, report, private input, edge plan, input IR and object
before finalization. A five-role version covers the standalone schema4
source-mixed finalizer without an edge plan. Actual mixed none/O2+archive
builds and the original source-mixed PE bypass samples reject changed or
paired inputs under their fixed receipts. The optional four-subject profile
also ties the two mixed owners and two contribution helpers to disjoint exact
COFF-to-PE extents in actual none/O2+archive builds, including a changed-object
negative that re-freezes the receipt. A further opt-in check derives both
mixed owners' entry states from frozen CFG seeds and compares their actual
linked PE writes; paired COFF/PE changes with fresh receipts are refused.
An additional opt-in trusted-builder replay compares the pass output IR,
raw report and Clang object against exact compiler reexecution before
freezing a 13-role receipt. Actual mixed none and O2+archive builds and
paired COFF/PE conditional-move negatives pass; the finalizer checks the
fixed record without rerunning the tools.
For the selected PRE+POST/O2+archive profile,
`PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN` adds a separate, manually frozen
20-role record. Its freeze replays the archive plan, request merge, link and
materialization from snapshotted inputs, authenticates all 36 existing
AES-GCM records and reconstructs the generated C++ source. The finalizer
checks that fixed record and its exact inputs before and after other proof
work. An actual plan mutation accepted by the older full finalizer is
refused by this option. Runtime C++ compilation and loaded-byte authenticity
remain outside its record replay.

The separate default-off `PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR` fixes the
requested IR, optimized IR and optimizer executable paths and bytes. The
builder explicitly freezes it after producing `payload.optimized.ll`; the
finalizer replays exact `default<O2>` and joins the optimized IR and tool to
the archive-origin record. The main seed-692 joint report and dedicated
CTest pass. Changed input/tool/command, wrong path and hardlink negatives
refuse. C++ source provenance, optimizer DLLs and publisher signing remain
unverified.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION` closes a bounded selected O2
machine route: six wrapper ABI/frame bodies, writable output/cache extents,
the two same-slot reads, comparisons and single-entry CFG paths. It binds
all 21 owner calls to their exact PE/COFF targets. Actual paired slot,
callee, frame, storage and branch bypasses refuse; the full finalizer first
validates mixed POST helper routes. Both observed O2 seed-248 and seed-692
comparison orders pass, including seed-692 with binding-status effects
enabled. Other lowerings fail closed. Runtime decoder writes,
ready-cache destination integrity, complete O2 predicate equivalence and
loaded-byte authenticity remain open.

The further default-off `PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES`
joins the requested, optimized and archive-prepared wrapper condition to
one exact COFF/PE compare and encoded allow/deny successor route. Together
with archive publication's two compute conditions, the seed-692 final
report proves three selected original predicate routes. Four actual paired
COFF/PE edits that the preceding publication proof admitted now refuse:
comparison-register clobber, two CFF state-slot overwrites and frame
replacement. The main joint O2/archive product and focused CTest pass.
Observation/callback/decoder effects, general O2 equivalence and runtime
loaded-byte authenticity remain unverified.

The further default-off `PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE`
binds `require_record` to `acquire_record` and the selected parse,
access-check and decode calls to exact COFF/PE roots, local arguments and
Win64 frame routes. A seed-692 O2/archive worktree product passed its
origin/publication/decoder CTests 3/3. Paired call, frame, jumps into
instruction interiors and captured-slot edits refuse. Decoder/cache semantics,
platform crypto and acquire inter-state reachability remain unverified.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM` further checks one conditional
cache first-use machine route: state-zero read, CAS from zero to one, decode
result, failure erase, and state two/three publication. The seed-692
O2/archive worktree passed the finalizer and four affected archive CTests;
main independently reran its focused actual-product test. Paired COFF/PE
call and state-source changes pass the prior decoder-linkage proof but fail
this gate. Its report leaves normal entry-to-arm reachability, platform
crypto/atomic effects, cache content and external destination integrity
unverified.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE` binds the selected parse,
storage and access success guards from `acquire_record` entry to that
first-use arm in exact seed-692 O2/archive COFF and PE bytes. Paired parse
and access selector, key comparison and overlap-call changes pass the two
preceding local proofs but fail this one. Its option-on worktree and a joint
main product passed the dedicated test. Parse, overlap, access and atomic
callee effects, arbitrary-input reachability and cache integrity remain
unverified.

Another opt-in check maps `require_binding` and `Scope::binding_status` from
COFF to PE and proves the bounded zero/nonzero status route, including
Scope/lease argument identity and Win64 stack-slot constraints within the
local function. Actual none/O2+archive builds and paired COFF/PE bypass
negatives pass. Upstream helper arguments, callback effects and unwind/EH
remain outside this local proof.
The further default-off `PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS` gate
checks the selected `binding_status` pointer identity, nonzero/equal lease
generation and availability routing, plus the `state`, `generation` and
`availability` accessor return paths. Exact call-site COFF symbols and raw
PE E8 targets are bound. Source-none and O2/archive real products reject
paired control, field, overlapping stack and Win64 call-shadow mutations.
The further default-off `PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT`
checks the called `context_availability` body's closing-field selection,
closed/ok status, exact lock/unlock targets and local CFF transition route.
Actual source-none and O2/archive products reject paired closing-mask and
lock-target edits after a fresh six-role receipt. Platform lock effects,
transitive request/callback routes and arbitrary runtime memory integrity
remain outside this local proof. A joint seed-692 main build with archive
publication, binding status and context availability enabled passed their
focused checks after its own receipt and archive-origin freeze.

`PYOBF_NATIVE_DEMO_G3_BOUND_CALL` additionally checks the exact local
`call_bound_bootstrap` pointer comparison, retain-status route, captured
lease and unchanged request at invoke in source-none and O2/archive COFF/PE.
Both option-on products and paired old-admitted pointer and request bypass
negatives pass after a latest-main worktree merge. Publication-source,
retain/invoke body, platform lock and transitive binding effects remain
explicitly unverified.

`PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL` further binds the selected
`retain_context` closing and reference-limit guards, successful reference
increment write, status route and exact lock/unlock calls in both source-none
and O2/archive COFF/PE. Both worktree final reports and dedicated CTests
passed after the latest-main merge; main independently reran both actual
product tests with paired prior-local-admitted bypasses. Full retain
lifecycle, platform lock, publication source, invoke/callback effects and
transitive binding remain unverified.

`PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL` binds the selected `BootstrapContextLease::invoke`
request guards, admit-status route, captured callback arguments and indirect
call, completion call and returned result in source-none and O2/archive
COFF/PE. Both worktree products and a joint main product passed their focused
tests. A paired callback-call removal passes the preceding bound-call proof
but fails this gate. Admit/complete effects, callback identity and behavior,
platform lock effects and arbitrary runtime memory integrity remain
unverified.

G3 machine-profile closure, request
freshness, distribution authority, loaded-byte authenticity and D7/D8
closeout remain open.
The [path-fold component](NATIVE_PATH_FOLD.md) provides a portable value model, independent
build reference and explicit whole/hybrid site binding. The demo carries initialization,
environment, owned-support and pre-decrypt events. The Windows backend's macro-mediated
SHA-256 expands their actual runtime fold to reconstruct a transient key from the
[masked record](NATIVE_RELEASE_RECORDS.md). The packer uses private per-build event inputs
and emits no raw key. Data-only parent finalization precedes exact final CFF verification.
The optional [decoy domain](NATIVE_DECOY.md) has independent sources, recipe, private events
and an exact image/report-bound AEAD package. Named outer-decoy variants close real admission
before releasing it with independent state/key ownership. Ordinary outer failure behavior
is unchanged. Separate actual-CNG observations classify exact child plaintext and check emitted
faults, allocation failures, closed contexts and erased ownership; actual DLL tests retain
exception/nesting/thread coverage. The combined D5 cost/readiness audit remains separate.
See the [bootstrap composition and cost boundaries](NATIVE_BOOTSTRAP_ACCEPTANCE.md) for the
actual startup ledger and the isolated full-release measurement target.
The first [contribution units](NATIVE_CONTRIBUTIONS.md) supply portable/host word framing,
typed LLVM correction arithmetic and source-only owned-context acquisition. The demo now
freezes private source material after authenticated decryption and serves derived words
after payload entry. Opt-in [contribution gates](NATIVE_CONTRIBUTION_GATES.md)
acquire those words and seal corrections at explicit points or automatically selected
retained-input normal edges, including the Windows x64 GNU hybrid profile, with
count/density/budget checks and explicit unwind exclusions. Whole/hybrid frame and call-step
composition explicitly tracks original invoke replacement and completion routes before result
RAUW. Branch-only regions and ordered owned-context source groups have their own contracts;
The [ordinary strict payload consumer](NATIVE_PAYLOAD_BINDING.md) now uses an independent
early root, private required recipe and late exact-child binding; `decoupled` names the
weaker sample profile. Other provider classes and genuine measured readiness remain required. Internal
source/site resolution now rejects unsupported capability/stage/reference/freshness contracts
and keeps observation-only/diversity sources outside required binding counts.
The [canonical code subject tooling](NATIVE_CODE_SUBJECTS.md) now defines bounded host .text/
unwind-interval references and tests actual mapped-DLL equivalence. The separate
[private native capture](NATIVE_CODE_CAPTURE.md) adds actual Windows x64 byte acquisition,
CNG hashing, clocks and target-module ownership. Independent observation state/cache and
invocation-bound transitions exist in the explicit two-role profile; generated independent
observer code and compiler/linker anti-merge acceptance remain open.
The [function contribution producer](NATIVE_FUNCTION_SUBJECTS.md) verifies admitted complete
COFF root/associated-fragment ranges against final bytes, with explicit alias/ICF rules.
The private object emitter supports opt-in separate function contributions without changing
default commands; actual ownership and final bytes remain authoritative.
The [reference codec](NATIVE_CODE_REFERENCES.md) adds independently keyed authenticated
metadata and native ownership. [Reserved reference slots](NATIVE_REFERENCE_SLOTS.md) add
frozen early identities and authenticated data-only finalization. The optional post profile
composes their stage2 materials with the startup record without a code/hash cycle.
The [owned observation runtime](NATIVE_OBSERVATIONS.md) introduces per-owner contexts,
immutable snapshots, exact read-start deadlines and independent synchronous caches; actual
configured stage/provider/reporting combinations remain required beyond the first post profile.
The private [measured key primitive](NATIVE_MEASURED_KEYS.md) feeds full actual digests, fixed
identities and fold words into key reconstruction. Its opt-in actual outer-stage/finalizer
integration now gates child release on actual outer code; full D5-D8 acceptance remains required.

Versioned composable recipes, function/marker overrides, per-component site coverage and
declared dependency checks are documented in [Native recipes](NATIVE_RECIPES.md).
Their files keep CLI registration, selection, configuration, component hooks and reporting
separate. The request pipeline now preserves site provenance in intermediate LLVM IR.
The opt-in `split-blocks` component adds budgeted whole/GNU-hybrid normalization before final
states. Independent conservative deduplication and typed common-exit components now run before
splitting and state binding. They preserve alias/relocation links to later actual protection,
check PHIs/tail constraints and report unsupported sites. Bounds, supported subsets and paired
measurement targets are in the recipe guide; these facilities are not secrecy boundaries.
Four further opt-in components add finite-width opaque choices, safe arithmetic donor clones,
independent synthesized decoys and reachable transition work. Structural preparation finishes
before state assignment; late binding cannot add CFG edges. Reports distinguish original,
shape, routing and decoy flow, and the Windows x86 final-code gate checks retained component
features. These components provide static-analysis obstacles, not device authorization or
continuous environment integrity. Their paired costs and supported donor subset are in the
recipe guide.

`include/pyobfuscator_native/sdk.hpp` exposes `inspect_current_process`, a detection report,
and an optional callback. It is a small C++ integration surface; a C adapter is not part of
the initial scope. The Windows backend and Linux/macOS placeholders all return
`DetectionStatus::unavailable`. No result claims the process is safe, and no callback can
authorize machine-gated content. The callback shape is intentionally small while detector
policy remains undecided.

`bootstrap_api.hpp` adds a versioned, same-process call table. In the demo, a generated
operation ID lets the inner SDK ask the outer bootstrap for its recorded environment status.
The ID is a routing value, not an authorization secret. The CMake target
`pyobf_native_sdk` contributes source files to the consuming target. For build and test
commands, see [`native/README.md`](../native/README.md).
Its `call` callback type is `noexcept`, matching the SDK dispatch boundary. Existing clients
must annotate their callbacks accordingly when rebuilding from source.
The SDK smoke detects a broken callback path or a placeholder that incorrectly reports
`clear`. On Windows, another smoke loads a sample SDK-consuming DLL through `LoadLibrary`
and calls its own exported function. Neither test proves debugger detection or code
obfuscation.

The optional LLVM new-pass-manager plugin transforms source-marked or explicitly named functions using a
registered strategy. Its pass entry, registry, strategy adapter, reachability validation,
source-marker parser, state and body layout, SSA/PHI and switch lowering, transition encoding, state
rewrite, and dispatch tree are separate C++ files. It
also has an optional per-function `relative-tree-deep` strategy that reconstructs selected
scalar i1-i128 literals from the current CFF state and routes eligible direct internal calls through
volatile pointer slots. The linked executable fixture checks that a call remains indirect.
The deep strategy also adds an alternate encoded transition for an abnormal state range;
its comparison does not use an exact state equality, and the demo checks the emitted
conditional move. It does not make arbitrary corrupted states safe.
The separate opt-in `comparison-constants` component hides an i2-i128 eq/ne literal behind a
state-keyed finite-width bijection. It bakes the constant's encoding at build time; only the
live operand uses the observed state, preserving a real dependency instead of canceling it
between both operands. Ordering, pointer/vector and Boolean comparisons are outside this
component's subset. A same-sign flag is not copied to a non-monotonic replacement. Exact type
counts and a distinct final-code feature check are documented in the recipe guide.
The separate opt-in `reference-routes` component normalizes direct defined function-address
uses into a bounded invocation-owned pointer table. Its layout varies with the public build
seed, and each use derives an index from the actual CFF body state. Calls retain their exact
lowered ABI; callback/returned/stored pointers retain true function identity. Self/mutual
recursion, reentrant callbacks, PHI/select references and concurrent invocations are exercised.
It conflicts with legacy `internal-calls` in one function. Global-initializer tables, unknown
dynamic targets and nested aggregate references are not claimed as covered; unsupported required
sites fail. This is static obfuscation, with public table targets and possible wrong-state index
collisions. The opt-in `call-frames` component separately moves admitted arguments/results
through a typed stack frame owned by each original call site and recursive invocation. Its
internal invoker retains the true target ABI and is generated/selected for baseline CFF before
any scope is sealed. Original requests and generated helper rows remain distinct. Real frontend
C++ aggregate ABI and exception propagation through callers without local cleanup are checked;
explicit hybrid landingpad cleanup is also covered. Frame ownership/ABI/closure, budgets and final invoker presence
have independent negative checks. Opt-in `call-preparation` adds distinct preparation/dispatch/
result states and bounded state-dependent byte addresses, with an exact graph/dispatcher-route
verifier and explicit support recipes for invokers. Zero-byte fields are uncredited; padding
and added stack/SSA work count toward the stated budgets. Opt-in `indexed-locals` preserves
original typed stack objects while routing their address uses through per-invocation indexed
tables with actual-state-dependent lookup. Alias/escape identity, alignment, lifetime and
atomic/volatile accesses retain their original semantics; original-object requests and physical
routes report separately. The same routes compose with admitted Windows GNU hybrid source
gates while preserving catch/cleanup objects and lifetime identity. Generated key/frame/SSA
storage is uncredited. Source objects removed
by O2 remain lost required requests. Opt-in `external-calls` admits exact nonvariadic strong
external declarations through separate typed private adapters, with independent source/helper
accounting and optional cross-state preparation. Real provider-DLL ABI/callback/effect tests
and actual Windows memory-backend operations are checked. Separate `hybrid-eh` profiles cover
default-exceptions cfg, framed/prepared and imported-address operations; the ordinary
no-exceptions adapter profile remains separately tested. Opt-in
`import-routes` separately protects strong-declaration scalar
address uses and imported call targets, including original uses moved into frames/common exits.
It has its own bounded tables/budgets/mask domain and verifies actual immutable slot contents,
exact index arithmetic and real dispatcher-state reachability. Imported C++ ABI/identity,
backend composition and malformed/canceled graph cases are checked. Final import names/ABI
and OS loader ownership are preserved; no import resolver or anti-hijacking guarantee is added.
An opt-in [typed archive runtime](NATIVE_ARCHIVE.md) now provides AES-256-GCM typed pools,
strict packaging and per-record caches over stable caller-owned storage. Its source target
supports Windows MSVC/CLANG64; the CLANG64 test also protects the actual runtime/wrappers with
CFF. The LLVM planning pass now collects admitted constants, proves selected use closure and
creates zero storage/pending gates. A materialization pass verifies the actual pool/wrappers;
the registered archive component reconstructs per-site keys from CFF states and reports
source coverage separately from physical lanes. A real protected-DLL fixture covers data,
lifetimes/concurrency/recursion, wrong keys/state and combined strategies. CMake integration
and deterministic protected assets are available as opt-in demo options. The same pipeline
supports ordinary O2 before planning and emits a native object before parent IPO; source and
helper requests both reach the final gate. Empty compiler plans can continue without a pool
while preserving required/lost-site failures. Paired archive costs and reproduction steps
are documented. General call routing and bootstrap/integrity coupling remain later stages.
Ineligible deep selections fail with an
`unsupported` report. The default marked demo applies it to `pyobf_demo_compute`; this
raises static recovery cost without creating a cryptographic boundary. It
rewrites supported branches into encoded relative state updates and routes through a comparison
tree whose split positions vary with the build seed. Selected body blocks are also shuffled.
A selected switch is first lowered into conditional blocks with an entry alloca for its
condition; the dispatcher still avoids equality tests against state IDs.
It lowers ordinary PHI nodes and sized cross-block SSA values to entry-allocated slots. It
rejects entry PHIs, unsized cross-block values, exception terminators in the default whole
scope, coroutine intrinsics,
known returns-twice/SJLJ nonlocal control, declarations and functions with unreachable blocks.
The nonlocal-control gate also applies to explicit regions across their entire owning function;
an optional call component cannot make an unsafe state-resumption boundary eligible.
An explicit [hybrid exception scope](NATIVE_RECIPES.md#explicit-hybrid-exception-scope)
protects normal CFG in the evidenced x64 Windows GNU landingpad model while preserving
exceptional edges. It admits cfg, typed internal/external frames, preparation and reference/import routes.
Integer/equality hiding also applies to admitted normal bodies. Comparisons retain their frozen
condition identity; a separate typed literal-return proof permits only the exact planned return
operand to change, preserving invoke/resume and other terminal boundaries.
Normal-edge dominance and original exception inventories guard result acquisition and unwind ownership.
Framed call counts/edge weights and typed target VP retain their respective event ownership;
immutable pre-helper snapshots are checked after caller/helper transformation.
Request collection retains eligible required local frame targets through `llvm.compiler.used`
before ordinary O2, preventing dead-argument/return ABI rewriting at those boundaries. This also
applies to optional frames with required preparation; optional-only frames remain unconstrained.
It does not preserve arbitrary inlined/deleted source sites, export targets or retain code at
the linker. Required coverage checks remain active.
Immutable pre-bind states/choices and exact final decode/storage/tree checks also reject
same-leaf fake states and canceled state dependencies; these are compiler construction proofs.
Hybrid reports retain partial coverage and distinguish linked normal-dispatch presence
from whole-function decision coverage.
A real multi-source CMake fixture exercises callbacks through a separate provider DLL into a
recursive hybrid owner, whole-scope SDK/asset work, catch/cleanup/rethrow and four concurrent
callers. CFG, framed/prepared/reference/import and real archive configurations run after source
O2 with parent IPO. Archive admission validates only archive-enabled sources, so an explicitly
archive-disabled hybrid owner can coexist with protected whole-scope assets. Separate CNG/data
fixtures also cover archive-enabled GNU hybrid owners, preserving EH type identities and
current context acquisition through warm caches. A required original-literal-loss profile still fails before
producing a DLL/final report. Separate final negatives reject a same-named unprotected image,
actual post-CFF dispatcher erasure, mismatched selected symbols and private input artifacts.
Final reports bind exact image/report digests and retain the partial hybrid scope.
An opt-in `pyobf_native_demo_measure_cff_hybrid` target separately measures normal/local-catch/
external-rethrow paths with paired plain/CFG/frame/composed builds and scalar additions against
matching CFG/composed baselines, raw samples and behavior
negatives; see the [measurement scope](NATIVE_RECIPES.md#hybrid-exception-costs).
Tiny CFGs receive entry transitions before flattening;
this does not hide a constant returned by a one-block function. Coverage reports therefore
separate original decision flow from `shape-only` padding, and only the former sets
`decision_flow_verified` after the linked check. A strict CFF option rejects shape-only
selected functions with a report instead of treating padding as full coverage. The demo first
links payload
and SDK LLVM IR, selects three application plus49 SDK/context/client definitions in strict
mode (two plus47 in explicit decoupled mode), and emits
a JSON record for every function and
declaration in its combined input IR, with transformed/unselected/unsupported/missing
statuses. A pre-optimization request manifest also distinguishes selected definitions
removed before the pass as `optimized-away`; selected unsupported, missing or removed
functions fail the build after writing the report. The demo records `requested` and
`retained` per function before checking linked code.
The demo uses unoptimized, source-built IR and checks that its linked Windows DLL retains
the selected symbols' comparison tree and transition mixing instructions before packaging.
A failed linked check stops the outer build. Successful checks write a separate final JSON
with an image SHA-256 and `final-binary-verified` for each selected symbol; the packer depends
on this result. This is a scoped
machine-code smoke, not general final-binary coverage or resistance to other optimizer/linker
settings. Generated standard-library helpers are not included in the SDK-authored selection.
An opt-in CMake measurement target compares a same-IR untransformed DLL with the linked demo
for file and `.text` size, repeated DLL load/first-call latency, and one hot exported function.
Another opt-in target compares O2 callers with and without the source marker to measure the
`noinline` boundary separately from CFF.
An explicit `relative-tree-region` strategy accepts repeated
`-pyobf-cff-region=function:entry:exit` selections, exposed in the demo as
`PYOBF_NATIVE_CFF_REGIONS`. It leaves blocks outside the named region intact, rewrites
region-local branches into state transitions, and rejects multi-entry, PHI, cross-block-use,
non-branch, or non-exiting regions before transformation. Its report labels successful
selections `region-decision-flow`. A linked fixture verifies the comparison tree and encoded
transitions. Opt-in [contribution gates](NATIVE_CONTRIBUTION_GATES.md#region-composition) also
support this branch-only subset, with scoped source/edge inventory, repeated-admission state
reset and a separate proof that surrounding operations and admission routes are preserved.
Invalid fixtures fail with reasoned reports. The opt-in measurement compares
one region fixture against its same-IR baseline; it does not establish an overhead bound for
other hot paths. Region selection is independent of source markers and conflicts with deep
selection of the same function.
Clang source annotations select marked user and SDK functions after `llvm-link`; explicit IR
names remain available as additional selection. The demo requires all49 strict SDK/context/client
markers (47 in decoupled mode) in its test, so removing one is visible. Clang markers apply `noinline` and `used` so O2
before the late pass retains a tested call boundary; this has an inlining cost. A test proves
that another O2 pass after CFF can erase the transform and that the linked gate rejects it.
The Windows demo also passed with CMake IPO enabled: its transformed IR was compiled into a
native object before the final ThinLTO link. Arbitrary post-CFF LTO and optimizer pipelines
remain unverified.
The demo applies a separate outer-bootstrap recipe to23 authored glue definitions:
21 ordinary and2 explicit hybrid-EH markers, plus42 context definitions and one SDK derivation
helper, totaling66 selected definitions. Default and triggered outer DLLs
retain independent source requests, native objects and exact final reports. The outer switch,
recipe and pre-CFF source optimization are independently configurable; see
[outer build integration](NATIVE_RECIPES.md#build-integration-and-provenance).
Backend OS implementations stay behind their semantic macros and are not credited as selected
outer glue. A runnable same-source unprotected DLL fails the final gate, and forced whole
coverage on the EH bodies is rejected. Owned context/session handoff, cleanup and local
fold-dependent release are integrated. Oracle integration and measured readiness remain
unfinished. Wrong-fold tests use production CNG and check that loader and entry stay untouched.
Optional outer-decoy variants add seven ordinary helpers and one hybrid subflow, for74
selected definitions including context. Their eight required fold owners keep real and
decoy storage separate. Extra decoy helpers are not credited as real-application gate density.

The Windows SDK smoke and `LoadLibrary` smoke previously passed with MSVC and MSYS2 CLANG64.
The CLANG64 end-to-end build checks SDK/context wiring, DLL loading, source CFF IR/report shape,
transformed switch execution across case and default values,
loop/merge PHI and cross-block SSA execution,
single-block return and side-effect execution,
cross-seed variation, one bounded wrong-state path, linked PE shape, fail-closed CFF selection,
detector registration and aggregation, and an always-triggered test detector that rejects before
decryption. The default configuration
also checks encrypted execution and tampered-ciphertext rejection; the strict configuration
instead checks that `unavailable` blocks before decryption.
Linux/macOS execution, real detector effectiveness, broad CFF coverage, and MSVC compilation
of the encrypted demo remain unverified.

## Planned fixed pipeline and target backends

The full design has fixed build and runtime stages with selectable backends. The current demo
implements a narrow Windows user-mode route: explicit function selection, CFF transform,
inner DLL link, AES-GCM packaging, outer DLL link, early environment observation, local-key
decryption, OS loading, versioned SDK binding, and entry invocation. It does not implement
device-gated native release, plain-mode identity stages, package policy manifests, or a
general-purpose build configuration validator.
An encrypted inner image must finish its own code generation and link before packaging;
the plain profile links its objects with the outer bootstrap. User code starts only after
payload preparation and SDK binding. The first implementation must declare unsupported
early DLL initialization and export behavior rather than claiming arbitrary DLL support.

The bootstrap main entry, generated-config reader, environment gate, payload release, and SDK
bridge are separate source files. `windows_user` owns the standard user-mode heap, CNG, and
disk-backed loader operations, plus its environment detector catalog. Demo bootstrap call sites
route memory management, crypto, payload loading and unloading through semantic macros in the
shared system-operation header. The broader production macro catalog,
cross-platform backends, and kernel-safe memory/IRQL contract remain open. The SDK can call
the outer bootstrap through the new versioned in-process API table.

The local AES key is reconstructed from obfuscated events and a public masked record; this
only raises static extraction cost. Private build plans and plaintext children must stay private. The
current loader writes a decrypted DLL to a temporary file for `LoadLibrary`, then deletes it
after unloading. It is deliberately unsuitable for a stronger confidentiality claim. The
plaintext inner DLL also exists in the build tree. The demo supports a single declared entry
and avoids user TLS callbacks, global constructors, DllMain side effects, and exported data.
Replacing the disk-backed loader with an in-memory format remains a separate engineering unit.
The temporary DLL can be replaced between closing its write handle and `LoadLibraryW`; an AEAD
check on the original bytes does not authenticate whatever image the OS finally opens. This
loader must not be used for a device-gated authorization profile.

The legacy SDK now copies its complete table under backend-mediated synchronization and
executes callbacks outside that lock. The descriptor object may expire after bind returns;
userdata and callback code remain caller-owned through every captured call. Unbind does not
wait for in-flight work. The demo uses an owned expected lease and outer-owned inner token.
Its synchronous entry, host observer exceptions, nested and concurrent separate sessions
have dedicated cleanup tests. Measured readiness and general asynchronous code/exception
object ownership remain separate from these scoped lifetime guarantees.

A future HVCI-compatible Windows kernel profile will disable runtime executable-code
decryption and enter a plaintext, statically linked main flow after its bootstrap. Static
CFF remains a separate build-time option. Microsoft [requires HVCI-compatible drivers to
avoid dynamic kernel code and modification of executable memory](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hvci-compatible-code).
An experimental non-HVCI kernel mode may opt into runtime decryption later; it is not
implemented or validated. Loading a driver normally at runtime is distinct from generating
executable kernel code at runtime.
The current `WIN32` CMake path is a user-mode placeholder. A kernel profile requires a
separate WDK driver build, signing and HVCI/Driver Verifier validation; MSYS2 CLANG64
user-mode smoke results do not verify a driver.

## Boundary and next implementation units

- The selected backend registers its own environment detectors. The common report records
  each name, tri-state result, validity and aggregate; the early bootstrap gate applies the
  release policy. The default Windows detector returns `unavailable`; test-only clear/triggered
  fixtures are excluded from the normal outer DLL. Actual debugger/dump detection and
  per-signal policies remain unimplemented. The report is held in memory; only its aggregate
  is returned through the demo SDK operation, and no detector details are logged by default.
- The CFF pass transforms source-marked or explicitly listed IR functions and fails on
  unsupported selected shapes. It writes a per-function IR coverage report, including marker
  identity. It has no general linked-binary coverage proof yet.
- The DLL starts protecting itself only after its host loads it. `LoadLibrary` and the Python
  or PyInstaller startup path before it remain outside this boundary.
- Neither a placeholder environment report nor local-key native obfuscation authenticates a
  replacement DLL. Machine authorization still needs issuer-approved key material and the
  enrolled device capability.
- Arbitrary already compiled third-party DLL rewriting and a separate IPC service are outside
  the selected source-first, in-process design.
- The `native/` source tree is available in the repository. No Python packaging rule for it
  has been added or validated, so consume the source from a checkout for now.

The current high-level design is also recorded locally in the ignored
`plans/2026-10-26-native-bootstrap-payload.md` file. That local plan is not part of
the public documentation set.
The [native developer guide](../native/README.md) maps each file and gives the steps to
register a CFF strategy, target backend, detector, bootstrap stage, and SDK operation.
