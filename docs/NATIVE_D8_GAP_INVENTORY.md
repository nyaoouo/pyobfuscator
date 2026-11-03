# Native D8 gap inventory (pre-acceptance)

This preparation inventory began at `15c6c3b` and includes bounded updates through
G4 `ca7404a`/`3d2e8b2`, G3a `24887bd`/`8e88649` and F6 `86c18b4`; it is not D8
acceptance. The source of the
completion conditions is `plans/2026-10-27-native-cff-python-parity.md`, D8, with the
D5/D6/D7 implementation ledgers and the 2026-10-31 dependency allocation. Those plans
are local planning inputs, not release artifacts in this worktree. The linked source,
tests and public guides below are present at the recorded revisions. Inventory edits
use files and recorded evidence; they do **not** themselves rerun a compiler, CTest or costs.

`supported` means a named, bounded shape/profile has implementation and recorded
positive, refusal and artifact evidence. `partial` means some such evidence exists but
the stated D8 scope remains open. `unsupported` means the current admission contract
rejects the shape or the recipe is unavailable. `unverified` means no applicable
runtime/final evidence is established; it does not mean a negative test passed. A
historical pass count or timing remains evidence only for its recorded revision, input
and configuration. Current source inspection does not refresh those measurements.

## Profiles and function shapes

| Profile or shape | Status | Positive and negative evidence | Final artifact and cost boundary |
| --- | --- | --- | --- |
| Windows x64 CLANG64/LLVM, selected whole normal functions; source `none` or `O2` before late CFF | supported (bounded) | [Recipes and selection](NATIVE_RECIPES.md), [recipe/optimization tests](../native/demo/check_cff_recipes.py), [wrong-state test](../native/demo/check_cff_wrong_state.py); strict required sites fail on loss | [PE checker](../native/demo/check_linked_cff.py) binds a scoped report to an exact image; per-site machine survival is still false. Component cost targets in [demo CMake](../native/demo/CMakeLists.txt) are fixture-specific |
| Explicit Windows GNU hybrid EH normal CFG with retained invoke/unwind boundaries | partial | [Hybrid contract and tests](NATIVE_RECIPES.md#explicit-hybrid-exception-scope), [hybrid final test](../native/demo/check_cff_hybrid_final.py); other personalities/funclets reject | Scoped normal dispatcher presence, not full EH machine-edge proof; [hybrid cost section](NATIVE_RECIPES.md#hybrid-exception-costs) is historical |
| Named branch-only regions with admitted `cfg`/`runtime-contribution` | partial | [Region composition](NATIVE_CONTRIBUTION_GATES.md#region-composition), [region gate cases](../native/tests/contribution/region_gate_cases.py); unsupported components reject rather than widen | Selected region, not outside code; no combined D8 region cost matrix |
| Windows outer CFF ON, ordinary bootstrap release and optional pre-code-hash | partial | [Startup phases](NATIVE_BOOTSTRAP_ACCEPTANCE.md#actual-startup-and-protection-order), [outer failure test](../native/demo/check_cff_outer_failures.py); local key, owned lifetime and actual CNG release exist | [Outer checker](../native/demo/check_cff_outer.py) and [bootstrap costs](NATIVE_BOOTSTRAP_ACCEPTANCE.md#isolated-measurement-target) cover exact sample images; genuine D5 L2/L4 and Unit5b remain open |
| Windows outer CFF OFF or `allow-unavailable` environment | partial | [Recipes build order](NATIVE_RECIPES.md#build-integration-and-provenance), [startup limitations](NATIVE_BOOTSTRAP_ACCEPTANCE.md#actual-startup-and-protection-order) | OFF lacks outer CFF; allowing unavailable environment supplies no machine authority even with CFF ON. Neither is strict protection acceptance |
| Windows MSVC | partial | Source-only translation-unit compatibility is recorded in the D7 ledger for creator/bootstrap units | No LLVM pass, linked PE, runtime or full MSVC pipeline acceptance follows |
| Linux ELF and macOS Mach-O runtime/final images | unverified | Backend-neutral format/macros are design constraints; no applicable final-code/runtime suite in this inventory | Cross-compilation alone cannot certify loader, EH, hash or teardown behavior |
| Kernel/HVCI and dynamic executable decryption | unsupported | User-mode loader, TLS/allocator and writable executable memory assumptions cannot be inherited | No kernel final artifact/cost claim; dynamic driver behavior remains an optional separate design |

## Feature and acceptance matrix

`P` and `N` name existing positive and negative evidence locators. `F` names the
current final-artifact check and its limit. `C` names cost evidence or its gap.
The statuses describe the whole D8 obligation for each row, so a working component
can remain `partial` until combined acceptance.

| Feature / recipes | Status | P: positive | N: negative / missing | F: final artifact | C: cost |
| --- | --- | --- | --- | --- | --- |
| D0 recipe/selection registry, required-site and readiness DAG contracts | supported (bounded) | [Recipe guide](NATIVE_RECIPES.md#build-integration-and-provenance), [request tests](../native/demo/check_cff_requests.py), [recipe tests](../native/demo/check_cff_recipes.py) | Unknown component, lost required site, malformed/stale request and dependency-cycle refusals are in those fixtures; full D8 mixed-domain mutation set remains open | Request manifest and private map stay separate from release; exact final-report hash binds retained image | No independent D0 runtime cost; request/ordinary-opt phases appear in [bootstrap measure](NATIVE_BOOTSTRAP_ACCEPTANCE.md#isolated-measurement-target) |
| Baseline `cfg`, relative tree, explicit site recipes | supported (bounded) | [Recipes](NATIVE_RECIPES.md), [recipe tests](../native/demo/check_cff_recipes.py), [shape test](../native/demo/check_cff_switch.py) | [Fail-closed tests](../native/demo/check_cff_failures.py), lost required sites and wrong-state cases | [Linked checker](../native/demo/check_linked_cff.py) checks shape/presence and image/report digests, not individual edges | [CFF measure driver](../native/demo/measure_cff.py) is a fixture, not complete D8 costs |
| `deep`/selective overrides and strict non-detection `parity` | partial; `parity` unsupported | [Recipe resolver/tests](NATIVE_RECIPES.md), [recipe tests](../native/demo/check_cff_recipes.py) | Unknown fields/components and incomplete `parity` reject; combined strict all-feature ablation is missing at proposed `native/demo/check_cff_parity_matrix.py` | Per-component presence only; no strict multi-source parity release report | No paired full-parity build/startup/hot costs |
| D1 CFG normalizers: `split-blocks`, `deduplicate-blocks`, `common-exit` | partial | [Normalization tests](../native/demo/check_cff_normalization.py), [split tests](../native/demo/check_cff_split.py) | Required unsupported/lost cuts, alias and ABI cases have bounded checks; mixed D6/D7 source ablation missing | [Linked checker](../native/demo/check_linked_cff.py) supplies scoped presence | [Normalization](../native/demo/measure_cff_normalization.py) and [split](../native/demo/measure_cff_split.py) fixture costs |
| D1b GNU hybrid EH normal flow and region scopes | partial | [Hybrid tests](../native/demo/check_cff_hybrid_eh.py), [region tests](../native/demo/check_cff_region.py) | Nonlocal admission in [test](../native/demo/check_cff_nonlocal.py); D8 mixed EH/region/provider negatives remain | [Hybrid final](../native/demo/check_cff_hybrid_final.py) proves bounded normal flow only | [Hybrid](../native/demo/measure_cff_hybrid.py) and [region](../native/demo/measure_cff_region.py) fixture costs |
| D2 `opaque-choices`, `reachable-junk`, `decoy-transitions`, `bogus-clones`, `bogus-synthesis` | partial | [Transition depth](../native/demo/check_cff_transition_depth.py), [bogus](../native/demo/check_cff_bogus.py), [D6 composition](NATIVE_CONTRIBUTION_GATES.md#transition-layer-composition) | Isolated bad-predicate/body checks exist; full multi-source independent ablation missing at proposed `native/tests/contribution/d8_ablation_cases.py` | Component-specific final presence remains scoped; fake claimed coverage must fail the combined gate | [Misleading cost](../native/demo/measure_cff_misleading.py), not combined startup/hot cost |
| D3 `integer-literals`, `comparison-constants`, `constant-archive` | partial | [Typed data tests](../native/demo/check_cff_typed_data.py), [archive composition](NATIVE_CONTRIBUTION_GATES.md#archive-data-composition) | Altered coefficient/target literal and archive source/key/wrapper negatives exist; combined source-specific ablation missing | Distinctive wide literal absence and archive wrapper evidence are bounded; no complete multi-source clear-data scan | [Typed data](../native/demo/measure_cff_typed_data.py), [archive](../native/demo/measure_archive.py) fixture costs |
| D4 `internal-calls`, `reference-routes`, `call-frames`, `external-calls`, `import-routes`, `call-preparation`, `indexed-locals` | partial | [Call/frame tests](../native/demo/check_cff_frames.py), [reference tests](../native/demo/check_cff_references.py), [import tests](../native/demo/check_cff_imports.py), [local tests](../native/demo/check_cff_locals.py) | ABI, unsupported target and removed-route cases are bounded; complete final clear-call-form ablation per selected site missing | [PE checker](../native/demo/check_linked_cff.py) checks scoped forms; `individual_sites_verified=false` for components | Individual [demo cost targets](../native/demo/CMakeLists.txt), no combined SDK/bootstrap hot cost |
| D5 `path-fold`, authenticated outer release, decoy and lifecycle | partial | [Bootstrap acceptance](NATIVE_BOOTSTRAP_ACCEPTANCE.md), [release records](NATIVE_RELEASE_RECORDS.md) | Wrong fold/phase/key, failed CNG/loader and decoy fault cases recorded; genuine L2/L4 plus Unit5b refusal matrix remains | Exact outer and child images checked separately; full first-release authority remains open | Historical six-pair `68900f1` costs in [bootstrap guide](NATIVE_BOOTSTRAP_ACCEPTANCE.md#isolated-measurement-target); newer `15c6c3b` creator costs only in local D7 ledger |
| D6 owned `runtime-contribution`: whole/hybrid/region, original edges, grouped sources and admitted compositions | partial | [Contribution gate guide](NATIVE_CONTRIBUTION_GATES.md), [group cases](../native/tests/contribution/group_gate_cases.py), [F2 detached Scope test](../native/tests/contribution/unit6_scope.py) | Source/bypass/flow/query mutants, bounded detached-body none/O2 refusal, F5 schema1 and F6 whole schema2 linked return-route refusals exist; complete D6 closure remains open | Runnable forwarding-query image is refused; F2 measured flow, F5 strict schema1 owned flow and F6 whole non-hybrid schema2 grouped route have bounded Windows x64 checks. G2h proves only local schema4 two-site numeric sensitivity; generic numerical influence, global state preservation, per-site equivalence and complete main payload proof remain open | Scoped [alias gate cost](../native/tests/contribution/alias_gate_cost.py), [F2 Scope cost](../native/tests/contribution/unit6_scope.py), [F3 paired scalar cost](../native/tests/contribution/scalar_gate_cost.py) and [F4 contribution on/off cost](../native/tests/contribution/contribution_gate_cost.py); full startup/provider/combination costs open |
| D7 independent code observation, owned readers/cache, creator and measured key | partial | [Owner readers](NATIVE_OWNER_READERS.md), [creator refusal test](../native/tests/measurement/check_owner_creator_refusals.py), [G1 two-Scope test](../native/tests/contribution/site_scope_cff.py), [G2a mixed-site test](../native/tests/contribution/mixed_site_cff.py), [G2c original-edge test](../native/tests/contribution/multi_scope_edge_cff.py), [G2d-G2l source-mixed tests](../native/tests/contribution/source_mixed_cff.py), [G4 two-edge test](../native/tests/contribution/source_mixed_original_edges.py), [G4 3-8-edge test](../native/tests/contribution/source_mixed_bounded_edges.py), [mixed POST plan](../native/tests/contribution/post_two_real_plan.py), [mixed POST final](../native/tests/contribution/post_mixed_final_cases.py) | Parent-child role join, two measured labels, cross-site mix, one-site owned/measured and bounded multi-Scope original edges pass none/O2. G2f admits two explicit schema4 sites, G2g compares raw independent private policy, G2h refuses linked numeric cancellation/unknown reads, G2i refuses actual PE routing/domain/owner argument changes when that private input is supplied, G2j refuses empty unsigned dispatcher intervals and skipped tree instructions, G2k refuses direct helper writes into caller or return stack, and G2l refuses owned/measured binding call redirects and bypasses. G4 admits a two-edge source-none schema4 function and a separate 3-8-edge schema2 plan with wrapper/compute none/O2 linked PE/CNG cases (4/7/3/6 edges). Every planned edge has a reachable normal and deny-site path; plan/private/report, PE helper, leaf and saturated-state mutants refuse. Mixed POST two-owner none and PRE+POST/O2+archive builds pass with 7/4 and 6/3 bound edges plus plan/PE/root/role refusals. G3 builder authority, request freshness and broader generated-owner independence remain open | Compiler role/site join and function-level final presence exist; G2e adds exact-PE caller flow, G2h local numeric sensitivity, opt-in G2i fixed-policy call-argument consistency, G2j local interval-to-helper-group evidence, G2k exact-helper-body direct-stack-write evidence, and G2l bounded binding-before-query routes. G4 ties verified frozen plan bytes to the raw compiler report and every reported edge state to one actual PE leaf/source group; the N-edge profile also checks local helper-return sensitivity. Mixed POST adds exact two-owner plan, PE and parent/child role-site proofs. Exact 32-bit predecessor state equality and original-predicate machine binding remain unproved: a two-edge PE mutation making the original condition select one branch still passes the static checker. G3 builder-controlled authority and loaded-byte authenticity remain open; publisher signing is deferred. Without `--contribution-input` the G2i check is absent. Transitive binding effects, all-input caller argument identity, symbol identity beyond selected subjects, policy authenticity, global state reachability and full owner binding remain unproved. `joint_caller_pointer_provenance_verified` and `cross_provider_owner_binding_verified` remain false | `15c6c3b` local creator sample, F2 Scope hot-path, F3 scalar and F4 contribution on/off costs exist; complete policy/source/hotness matrix open |
| D8 selected multi-source user/SDK/bootstrap, exact release image, independent ablation | unverified | Individual source domains and several combined fixtures exist; no D8 end-to-end matrix | Missing cross-feature ablations and failure-origin matrix in next section | [Final report test](../native/demo/check_cff_final_report.py) checks report/image consistency, not each claimed machine site or targeted clear form | Full code/data growth, warm startup and protected hot-path costs across D8 profiles remain open |

G3a through `8e88649` adds an opt-in builder-fixed six-input receipt to the
mixed POST build and a five-input source-mixed CLI profile. Actual none and
PRE+POST/O2+archive child/parent builds and fixed-receipt replacement
negatives pass; old schema2 O2 affected tests pass.
This is build consistency within a trusted builder, not the D7 machine-profile
or D8 acceptance gate. The original non-mixed branch-NOP, entry-state and
paired PE/report/private reds now reject under a fixed five-role receipt;
the baseline without a receipt still accepts them. Receipt
replacement with the whole input set, single-snapshot disassembly, exact
transitive effects, request freshness and loaded-byte authentication remain
outside this verified unit. G3b1 `f4d1eaf` adds four exact mixed owner/helper
COFF-to-PE extents with function sections. Actual mixed-none and
PRE+POST/O2+archive child/parent CTests passed 9/9 each; old schema2 O2
affected checks passed 8/8. Seven direct mutations and a production
changed-object mutation with a newly frozen receipt were refused at the
subject proof. Entry-state value semantics, original-predicate equivalence,
transitive callee effects, whole-distribution authority and runtime loaded
bytes remain open. The G3b1 result does not close D7 or the D8 matrix.
G3b2a `c5cb9f5` adds a bounded two-owner entry-value proof from the frozen
CFG seeds to decoded linked PE state writes. Actual mixed-none and
PRE+POST/O2+archive child/parent affected CTests passed 9/9 each; old schema2
O2 checks passed 8/8. For each owner, a matching COFF+PE immediate change
with a newly frozen receipt passes the receipt and G3b1 subject checks but
is refused by the production entry-state proof without stale JSON. This
does not establish the entry leaf's behavior, original-predicate semantics
or transitive helper effects; G3, D7 and D8 remain open.
G3c `724b121` adds a default-off deterministic opt/Clang replay before a
13-role trusted-builder receipt is frozen. Both actual mixed-none and
PRE+POST/O2+archive child/parent affected tests passed 5/5, and old schema2
none/O2 checks passed 8/8. In both profiles, a paired COFF/PE edit to the
actual `require_binding` conditional move passes the older re-frozen
six-role receipt/finalizer but is refused by replay before a new receipt is
issued. The finalizer checks the fixed record and inputs; it does not
reexecute the compiler. `fca30c4` replays CFF opt from pre-read scratch
copies of the five mutable data inputs, checks option-path identity, and
normalizes only verified LLVM ModuleID/plan/report path-dependent fields
before exact transformed IR, report and object comparisons. Five transient
original-path swaps, a wrong plan digest and an option-path mismatch now
refuse or leave the fixed record unchanged as appropriate; actual none and
O2/archive dedicated tests pass. Provenance upstream of frozen pre-CFF IR,
toolchain behavior during subprocess execution, transitive
tool DLLs, semantic equivalence, callback effects, distribution replacement
and runtime loaded bytes remain outside this proof. G3, D7 and D8 remain open.
G3b2b `1a754ee`/`d599d09`/`7497244` adds an opt-in exact local
`require_binding`/`binding_status` COFF-to-PE proof with a bounded status
route and argument/frame constraints. Actual mixed-none and
PRE+POST/O2+archive child/parent affected tests passed 10/10 each, then
local/mixed-final/role-join 3/3 each after the final frame fix. In both
profiles, newly frozen old receipts admit paired COFF/PE condition-move,
Scope/lease alias, frame escape, temporary-spill overlap and state-shadow
changes under the older finalizer, while the local gate refuses with no
stale report. Main reran both actual regression scripts after merge, exit 0.
This remains local: `binding_status` internals, callback/platform effects,
full EH and original-predicate semantics remain unverified. G3, D7 and D8
remain open.
G3b2b `bc229ba` closes the same local proof's plain-frame PE unwind
allocation gap. A paired final PE xdata edit with a newly frozen receipt
passes the older finalizer and fails the new local gate in actual none and
PRE+POST/O2+archive artifacts. This does not establish general EH behavior.
G3b2c `6c6ab96` adds an opt-in observed-entry proof for the two mixed
helper argument sources. It binds each exact COFF/PE helper subject and
PE frame, follows the observed entry state through the dispatcher to the
first local `require_binding` call, and checks per-path `RCX=Scope` and
`RDX=lease`. Actual none and PRE+POST/O2+archive final reports and focused
tests pass. Paired COFF/PE Scope/lease source, entry-state and early-branch
mutants with newly frozen receipts pass the older finalizer but fail the
new gate without stale output. This proof does not cover all possible
entry states, transitive binding effects, parent callback effects, original
predicate equivalence, or loaded-byte authenticity. G3, D7 and D8 remain
open.
G3b2c `b7b9e55`/`927834a` adds an opt-in outer parent callback proof.
It binds the selected session, dispatch callback and creator to exact
COFF/PE subjects; checks the adjacent fixed-frame callback/Spec assignment
and direct creator call; and follows the observed entry through a bounded
static CFG. Real and triggered parent final reports pass with outer source
optimization `none`, including a child-O2 PRE+POST/archive build. Six paired
COFF/raw-PE edits with regenerated ownership inventory, final PE and release
record pass the previous gate but fail this gate without stale output:
callback substitution, entry
return, entry skip, dispatcher pivot, `int3` and `ud2`. The proof covers
the admitted static route and does not establish all runtime branch
conditions, creator effects, distribution authenticity or bytes loaded
by Windows. `5df5cdb` removed a false PE address-order assumption after
the actual seed `61594286` placed the valid entry leaf after the return
epilogue; both real and triggered images pass, and existing bypass mutants
still refuse. `6a241e2` adds a second, exact outer source-O2 lowering with
two observed dispatcher temporary slots and PE unwind allocation binding
for both frames. Actual O2 real/triggered final reports and paired callback,
entry and xdata old-admit/new-refuse cases pass; the six original source-none
negatives remain valid. Runtime branch outcomes and transitive effects remain
unverified by these static parent profiles. G3, D7 and D8 remain open.
G3c outer `fd69f18`/`ec5f5e4` adds an opt-in fixed builder replay for the
outer chain. It snapshots combined IR, replays request, optional source O2,
CFF, Clang and ownership inventory through checked scratch outputs, then
freezes a 23-input-role record and receipt independent of finalization.
Actual real and triggered outer-source-none reports pass in mixed-none and
child-O2/archive builds. Paired object/PE and report/inventory changes
with the fixed record pass the older finalizer and fail this gate; transient
original-path swaps cannot enter the replayed IR chain. Its isolated outer
source-O2 fixture proves only compiler replay; the distinct parent O2 proof
above independently admits actual final reports.
Tool, plugin and recipe digests cover files observed before and after freeze;
the controlled builder must keep those paths immutable during subprocesses.
C++-to-IR, linking, transitive tool dependencies, distribution signing and
runtime loaded bytes remain outside this bounded proof. G3, D7 and D8
remain open.
G3 source-none `a9b21b1`/`36cc5cc`/`1ed6fc4`/`86beb45` adds a separate
opt-in machine original-predicate proof for the two mixed POST owners.
It checks three source IR conditions and their linked Win64 argument,
comparison polarity, encoded state and successor-route evidence. Actual
source-none finalization passes; five receipt-refrozen paired COFF/PE
mutations pass the older complete finalizer and fail the new gate without
stale output. Two other valid stack/entry edits are rejected by the module
but already fail the older joint-machine gate; they are not counted as
unique production gains. Actual O2+archive fails closed because its
published archive operands lack source-to-record-to-PE provenance. This
bounded proof does not establish all runtime inputs, compiler correctness,
transitive effects, general O2 semantics or distribution authority. G3,
D7 and D8 remain open.

G3 archive-origin `cc69532`/`bc12fbe`/`50c0b75` adds a separate
default-off 20-role fixed record for the selected PRE+POST/O2/archive
producer. A main-source build froze the child replay and archive record,
generated its final report and passed the focused actual CTest 1/1. The
archive freeze replays plan/pending, merged requests, linked and prepared IR,
authenticates all 36 existing package records and regenerates C++ from the
authenticated package. A record-28 plan zero-value change admitted by the
older complete finalizer is refused with stale output cleared; package,
binding, wrong-key, generated-source and alias negatives also refuse. This
remains trusted-builder consistency. Runtime C++ compilation/request pass,
PE wrapper publication and reads, cached destination integrity, transitive
decoder machine effects, original-predicate O2 equivalence, distribution
authority and loaded-byte authenticity remain OPEN. G3/D7/D8 stay open.

G3 O2 predecessor `47ca657`/`87bea18`/`014a6c8` adds a separate explicit
three-role freeze and exact optimizer replay for requested IR to optimized
IR, with both optimized IR and optimizer paths/bytes joined to the archive
record. A seed-692 isolated worktree and a joint main final report plus
dedicated O2 CTest passed 1/1 each. The same new main inner product passed
the six affected archive, publication, decoder, binding, context and
bound-call CTests 6/6 after explicit O2, child replay and archive-origin
freezes. Changed requested/optimized/tool bytes, forged command/digest,
wrong path/hardlink and missing record refuse. Review
found a record-symlink target deletion bug in the first commit; `014a6c8`
rejects symlink leaf paths before unlink and passed re-review. Actual symlink
creation was denied by Windows (`WinError 1314`); the sentinel preservation
fixture simulated the early guard, so that OS negative is UNVERIFIED. C++
source provenance, optimizer DLL dependencies, publisher signing and whole
distribution replacement remain OPEN.

G3 binding-status effects `9afe878`/`d0338dc`/`7692ad2` add a default-off
machine check for selected source-none and O2/archive Scope/context pointer,
generation and availability routes. The two real final reports and focused
tests pass. Paired COFF/PE guard, field, call-relocation alias, overlapping
stack and Win64 outgoing shadow-space edits pass predecessor gates but fail
the new check with stale output removed. Its accessor and call-site proof is
local: a separate gate now checks the `context_availability` callee body;
the wider request-to-dispatch chain, arbitrary runtime pointer writes and
G3/D7/D8 completion remain OPEN.

G3 context availability `277b443`/`e5b2083`/`d2fe596` adds a default-off
local closing-field/status and lock/unlock call-route proof for the exact
source-none and O2/archive COFF/PE bodies. Both actual option-on products,
paired closing-mask and lock-target old-admit/new-refuse tests, and the
post-base source-none/O2 focused tests passed. A main seed-692 build froze its
own builder/archive records, produced the joint publication+binding+context
report, and passed the registered context CTest after the test receipt
profile fix. Platform atomic effects, request/query/invoke/callback behavior,
arbitrary runtime writes and G3/D7/D8 closure remain OPEN.

G3 bound-call `637ad77`/`87f4c89`/`a9cadd4` adds a default-off local
publication pointer/retain-status/captured-lease/invoke-request route proof.
The source-none and O2/archive worktree products passed exact final reports,
paired old-admitted pointer/request bypass refusals and dedicated CTests
1/1 each after merging the latest main; independent read-only review found
no issue within those local claims. Publication-source, retain/invoke body,
platform lock effects and the transitive request/query/callback chain remain
OPEN. A later seed-692 main product enables this option with retain, invoke,
archive first-use and archive entry checks; five focused CTests pass.

G3 archive publication `888b46d`/`d2a740a`/`045bda2` adds a default-off
selected PRE+POST/O2/archive COFF-to-PE machine check after the archive-origin
record. A separate main-source build with seed `24835963` froze both records,
generated the option-on final report and passed archive-origin/publication
CTest 2/2. The selector-mapped adapter `46a19f5` additionally accepts
seed `69243558` while preserving seed248: its independent worktree passed
the seed692 joint publication+binding 3/3 focused CTests and seed248
origin+publication 2/2. Six wrapper frames and output/
cache extents, two same-slot reads and 21 direct call targets are checked.
Paired call, storage, alias and CFG bypasses fail the local proof, while the
fixed child replay independently rejects changed code bytes. The full
finalizer requires the earlier mixed POST helper-route check; standalone
publication assumes normal helper returns. Decoder/cache runtime writes,
complete O2 predicate equivalence, other layouts, distribution authority
and loaded-byte authenticity remain OPEN. A separate main seed692 joint
build passed archive-origin, publication and binding CTests; the context
test initially failed only because its standalone positive used a replay-
profile receipt as a six-role receipt. `d2fe596` generates the correct
six-role receipt and the affected registered CTest then passed 1/1. The
original failed 3/4 run is retained; the three unaffected passes and the
new context 1/1 constitute the current joint evidence.

G3 archive decoder-linkage `53d7843`/`2d9dcef`/`38b471e`/`66c2958`
adds a default-off selected require/acquire/three-child call and local
argument proof. The seed-692 O2/archive isolated product passed its final
report and archive-origin/publication/decoder CTests 3/3 after merging the
latest code base; a later docs-only merge required no rebuild. Independent
read-only review replayed six earlier paired COFF/PE false accepts and found
all refused after frame, alias, call-interval and opcode repairs. Decoder/
cache effects, platform crypto and acquire inter-state reachability remain
false; a later joint seed-692 main product passes the selected archive tests.

G3 selected follow-on units `23dea22` (O2 original predicates), `97214d8`
(conditional archive first-use), `f4f1440` (retain-local), `a03b470`
(invoke-local) and `09cf7d0` (archive entry route) each add a separately
checked local COFF/PE route. P112 and P113 passed independent worktree
option-on reports, paired predecessor-admitted/new-refused mutations and
focused CTests after latest-base merges. A main seed-692 product enables
both together with bound-call, retain-local and first-use; those five
consumer CTests pass 5/5, and the final target has no incremental work.
Archive-origin mutation tests now run serially (`c4789e8`) because they
temporarily change shared build inputs; the archive suite passes 5/5 with
CTest `-j 2` after that fix. These checks do not prove admit/complete or
callback effects, parse/overlap/access/decoder/cache effects, arbitrary
runtime memory, distribution signing or loaded-byte authenticity. G3,
D5 Unit5b, D6/D7 closure and D8 acceptance remain OPEN.

## Required independent ablations and final checks

These are proposed additions to existing test/checker locations, not tests created by
this inventory. Keep the positive semantics identical while removing only the named
protection mechanism; a different component's surviving report must not satisfy the
targeted gate. Run both the requested original-site accounting and final-image check.

| Gap / proposed locator | Failure the negative must expose | Dependency |
| --- | --- | --- |
| A1 `native/demo/check_cff_parity_matrix.py`, `native/demo/check_cff_final_report.py` | Disable each of CFG, scalar literal, archive, call/frame/route and bogus components separately in the same selected user/SDK/bootstrap recipe; the matching required site and final clear-form check must fail, while unrelated components still pass | D5/D6/D7 closure and D8 combined recipe |
| A2 `native/tests/contribution/d8_ablation_cases.py`, `native/demo/check_cff_contribution.py` | Replace one grouped source with a clean zero or duplicate another source, retain plausible aggregate query count and all other components; reject at source/site/flow and exact child artifact | Remaining F/G compositions and D8 combined recipe; F2/G1/G2a local detachments do not close this combined ablation |
| A3 `native/tests/measurement/check_owner_creator_refusals.py`, `native/demo/check_cff_outer.py` | Swap or omit a parent creator row while child site report remains internally valid; join must reject role/site mapping and stale parent/child object, manifest, plan or release image | E joined role proof exists; D8 combined stale-artifact ablation after G closure remains |
| A4 `native/tests/measurement/check_observer.py`, `native/demo/check_cff_outer.py` | Reuse an expired/previous-request observation or another owner's immutable snapshot without fresh acquisition; metadata and CFF contribution must refuse independently | C snapshot copy, G policy, H report/freshness |
| A5 `native/demo/check_cff_final_report.py`, `native/demo/check_linked_cff.py` | Preserve a valid CFG presence count while restoring one selected clear literal/direct call/import route or removing one archive use in the linked image; reject the affected component, not merely a global symbol count | D8 final checker extension after complete recipe/site map |
| A6 `native/demo/check_cff_outer_failures.py`, `native/tests/contribution/check_gates.py` | Fault each L2/L4 real-release source and detached-body admission independently; prove refusal before the first sensitive release and no false real-gate credit from a decoy/fallback path | D5 Unit5b, F, G |
| A7 `native/demo/measure_bootstrap.py` plus existing component cost drivers | Same-source plain/protected pairs for final multi-source strict configuration: separate code/data size, ordinary-opt/CFF/link costs, first release, warm startup and protected hot use; record exact object/plan/recipe/image hashes | D5/D6/D7 closure; D8 final matrix |

## Acceptance order and scope

The allocation ledger makes D8 preparation independent, then requires B before F,
A before E, B+E before G, C+G before H, E+G before D5 Unit5b, F+G before D6
closure, and G+H before D7 closure. Full D8 follows those closures. This document
unlocks planning only. The final run must include complete supported Windows CLANG64
profiles, combined refusals and artifacts, with distinct evidence for changed behavior.
Reuse historical unaffected logs only with their revision, input and applicability
limits. Unsupported and unverified rows stay explicit; no stage completion follows
from a module test or from this inventory.

Environment/detection providers are excluded from the non-detection CFF parity
recipe. A future provider needs its own backend and contribution proof; the
current placeholder is not counted as machine verification or anti-debugging.
