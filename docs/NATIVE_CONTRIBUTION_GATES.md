# Native contribution gates

The opt-in `runtime-contribution` component turns source points into actual owned-context
queries and CFF transition corrections. Explicit points remain the default. Opt-in automatic
selection now protects retained input normal successor edges with a required count/density
and bounded query budget, including verified Windows x64 GNU hybrid EH and explicit
branch-only region profiles. Sites can select and combine distinct owned-context sources.
Whole-function and supported hybrid normal bodies also compose the registered opaque,
reachable-junk and decoy transition layers. The [ordinary strict payload consumer](NATIVE_PAYLOAD_BINDING.md)
now uses independent early material and late exact-child binding. Contribution reports carry
`private_input_sha256` of the bytes actually read; its packager verifies that reference,
early fold and final owner coverage. This is trusted-build consistency, not authentication
of fabricated reports. Other provider classes and remaining compositions stay open. See the
[source contract and arithmetic](NATIVE_CONTRIBUTIONS.md).

## Source and build inputs

```cpp
#include "pyobfuscator_native/contribution_marker.hpp"

int compute(const pyobfuscator::native::BootstrapContextLease &expected, int value) noexcept {
    pyobf_native_contribution_site_v1(expected, 101);
    return value + 11;
}
```

The caller keeps the lease object and executing module alive through normal return or
unwinding. Each generated
query independently uses strict owned publication and retains its admitted provider through
that synchronous call. It does not infer expected identity from whichever publication is
present. Point labels are nonzero uint32 values; optimization may clone a point into separate
body states, each with its own query. These are shared context-material acquisitions, not
D7 independent code observations or caches.

Enable the component on the intended owner with the existing recipe/selection API:

```json
{"schema_version":1,"functions":{"compute":{"components":{"runtime-contribution":"required"}}}}
```

Use the actual LLVM function name for C++ linkage. Supply a separate private build file
through `-pyobf-cff-contribution-input=reference.private.json`:

```json
{"schema_version":1,"provider":"owned-context-v1","routing_tag":7,"domain":11,
 "source":17,"private_words":[1,2,3,4,5,6,7,8],"owners":{"compute":13}}
```

Those numbers are test examples, not production secrets or a machine identity. The actual
private words must match the authenticated provider's immutable snapshot. Route/domain/
source/function identifiers must be nonzero; owner IDs must be unique. Widths, provider,
reference class, readiness and required group use the compiler source resolver. The initial
adapter is specifically `owned-context-v1`; schema2 below exposes its per-site source subsets.
Other provider classes and symbolic program-value adapters remain unimplemented.
Malformed input, absent owner reference and unsupported ABI/scope fail compilation.

`pyobf_native_contribution_gate` adds the source-only scalar query shim and strict client.
Include its source closure in the protected IR. Keep the source marker implementation out
of that IR: protected inputs require the closed direct nounwind declaration. Ordinary source
builds link `pyobf_native_contribution_reference` for the no-op marker implementation.
The shim is an internal source ABI with no explicit DLL export; the host linker/export policy
still controls symbol visibility. No C SDK or Python bridge is introduced.

## Per-site source subsets

Private input schema2 replaces the single `source` field with a catalog and owner rules:

```json
{
  "schema_version": 2, "provider": "owned-context-v1",
  "routing_tag": 7, "domain": 11, "private_words": [1,2,3,4,5,6,7,8],
  "owners": {"compute": 13},
  "sources": [
    {"id": "alpha", "word_label": 17, "group": "bootstrap"},
    {"id": "beta", "word_label": 29, "group": "bootstrap"}
  ],
  "bindings": {
    "compute": {
      "default": {"sources": ["alpha", "beta"], "mixing_domain": "normal-path",
        "groups": [{"id": "bootstrap", "minimum": 2}]},
      "sites": {"101": {"sources": ["beta"], "mixing_domain": "entry",
        "groups": [{"id": "bootstrap", "minimum": 1}]}}
    }
  }
}
```

An exact canonical nonzero uint32 point label overrides that owner's default. Cloned retained
instances of a point use the same rule; an exact rule whose label is lost rejects when that
owner is bound. Automatic generated edge labels normally use the default. Missing rules,
duplicate IDs/labels, unknown sources or provider versions, empty subsets and unsatisfied
groups reject. Sources may explicitly name `provider` and `provider_version`; the current
registered adapter defaults to `owned-context-v1`/1. Every selected source is 32-bit,
authenticated-context, per-use, ready at L4 and shared context material. It cannot satisfy an
`independent_evidence` group. Source/domain identities are public framing, not extra secrets.

A4 emits one actual query per selected source using the same caller-held lease and live
state. Each query retains provider admission for its synchronous request. A5 frames and
combines the ordered observations with the existing two-lane word mixer before unsealing the
transition; it emits no expected-word lookup. Domain/function/site, source label/encoding/
length and source order participate. The compiler freezes the actual acquisition identities
and private subset/domain/encoding plan. Replacing a secondary call cannot acquire its
predecessor's authority through LLVM RAUW. Retained proof checks every actual result's
contribution to the real wrapping state update, not just query presence.

`max_contribution_sites` caps total acquisition calls for this format. Component `applied`
and original-edge density still count bound sites/edges; adding more sources cannot increase
density. Reports separately expose `query_count`, public per-site subsets/required groups and
`source_subset_contract_verified`, without private words or body-state maps. The final gate
checks report consistency and actual query/mask presence; private reference validation occurs
in the compiler, not from an arbitrary report supplied after linking. This remains finite32
obfuscation with collisions, not a MAC or a guarantee that every bad combination crashes.
Several derived sources from one snapshot are not independent code observations or caches.

For whole, non-hybrid `relative-tree` schema2 `owned-context-v1` functions, the
Windows x64 final gate also checks the linked grouped helper returns through
their state write and direct route back to the dispatcher. It admits only
modeled machine instructions, a stable query/dispatcher stack frame, bounded
state and outgoing-argument byte writes, and fresh argument stores after each
helper call. Unsupported lowering fails closed for this subset. Actual linked
mutations retain helper calls while detaching a return, skipping an argument
rewrite, changing the frame or redirecting the post-query route; the final
gate rejects them without producing a final report. Explicit/automatic source
`none`/`O2` cases pass. Hybrid and region profiles retain their previous
presence check because their machine routes differ.

This proves a bounded immediate return-to-state-to-dispatcher structure. It
does not prove dynamic branch feasibility, pivot authenticity, arbitrary
numeric influence, helper memory effects, global state preservation or
per-site machine equivalence. `individual_sites_verified` remains `false`;
these gaps and full D6 acceptance remain open.

## Mixed providers across explicit sites

Private input schema3 uses `provider: "site-mixed-v1"`. Each catalog source must
name `owned-context-v1` or `measured-scope-v1` and provider version 1. Every
owner supplies explicit site rules, without a default, and retains at least
one site of each provider. A site selects sources from one provider only:
one measured Scope source or one or more owned context sources. The marker
name and its caller-held reference must match that site's source provider:
`pyobf_native_contribution_site_v1` for owned context and
`pyobf_native_measured_contribution_site_v1` for measured Scope.
The existing seven-argument query ABIs remain unchanged. For example:

```json
{
  "schema_version": 3, "provider": "site-mixed-v1",
  "routing_tag": 4128, "domain": 1, "private_words": [1,2,3,4,5,6,7,8],
  "owners": {"compute": 7},
  "sources": [
    {"id": "context", "word_label": 13, "group": "owned", "provider": "owned-context-v1", "provider_version": 1},
    {"id": "code", "word_label": 29, "group": "measured", "provider": "measured-scope-v1", "provider_version": 1}
  ],
  "bindings": {"compute": {"sites": {
    "701": {"sources": ["context"], "mixing_domain": "owned-site",
      "groups": [{"id": "owned", "minimum": 1}]},
    "702": {"sources": ["code"], "mixing_domain": "measured-site",
      "groups": [{"id": "measured", "minimum": 1}]}
  }}}
}
```

The scheme3 report lists each site's provider/version, ordered source subset,
the two helper counts and the private input digest. It keeps
`generated_owner_independence_verified=false`. The compiler rejects a wrong
marker/helper, mixed providers within one site, missing or unused explicit
rules, unknown provider/version and detached query results. The Windows x64
CLANG64 final gate checks that both helper calls and the supported query-return
to state-slot paths remain in the linked image; unknown lowering fails closed.
The actual none/O2 fixture uses a live owned context and CNG-backed measured
Scope, and rejects wrong references, bad observations/material and separate
owned/measured result detachment. A self-consistent forged compiler report is
not authenticated by the generic final gate against an independent private
input; the fixture compares that input separately.

Schema3 currently requires explicit points. Multiple-Scope automatic original-edge
selection is admitted only for the separate homogeneous measured schema2 profile
below; strict POST payload binding is not admitted by this increment.
This is not D7 completion or generated-owner independence.

The `pyobf-native-cff-edge-plan` pass plans a bounded schema4 automatic-edge
profile. Run it on the exact retained IR with
`-pyobf-cff-edge-plan-output=<private JSON path>`. It emits the selected
owner, a SHA-256 of LLVM's printed input module, the effective recipe and
stable original-edge IDs/labels. The two-edge recipe emits plan schema1; the
explicit 3-8-edge recipe emits plan schema2 with one ordered owner record. Also pass
`-pyobf-cff-edge-ir-input=<retained IR path>` so the writer can reject
output aliases to that input, the configuration or request files. It requires
a whole `relative-tree` function with two distinct pointer arguments,
at least one conditional branch with different normal successors,
100% selection and source-retained terminator provenance. The schema1 recipe
requires exactly two edges; plan schema2 requires 3-8. It performs no CFF
transformation. The `pyobf-native-cff-edge-plan-verify` pass and opt-in CFF
`-pyobf-cff-edge-plan-input=<same JSON>` rederive the plan from the exact
retained IR and recipe before any transformation; a changed plan, IR or
recipe fails. A schema4 original-edge CFF request without that frozen plan
is rejected before mutation. The compiler report carries
`original_edge_plan_sha256` from the exact plan buffer it verified; the
opt-in final checker `--source-mixed-original-edges=<plan>` for plan schema1 or
`--source-mixed-bounded-edges=<plan>` for plan schema2 compares this with the
supplied plan bytes and the selected source/edge identities.
Without this opt-in, a schema4 original-edge report remains unsupported by
the ordinary final checker.

The plan schema1 automatic profile covers one Windows x64 CLANG64 source-none
function with exactly two selected original successor edges. Plan schema2
profile covers one such whole function with 3-8 selected edges at source-none
or pre-CFF `default<O2>`. The registered wrapper and compute fixtures have
4/7 edges at source-none and 3/6 at O2, respectively. Each edge has its own
schema4 source rule, including at least one owned-context source and one
measured-Scope source; the owned subsets are pairwise distinct. The default
explicit schema4 parser still permits at most two sites; up to eight are
admitted only with a verified frozen plan schema2 original-edge record. The compiler
inserts grouped queries at each edge gateway and reports the gateway's CFF
dispatch state. The strict final checker reads the actual linked PE, verifies
every helper group and its return-to-state route, and requires each reported
dispatch state to land in the dispatcher leaf interval for that edge's planned
site. Its admitted PE model also exhibits local numeric sensitivity to each
helper return and checks the linked helper bodies and routes. Changed plan
bytes, private rules, PE site immediates, helper routes, state writes, leaf
targets and saturated-state mutations are refused without a final report.
The registered fixtures exercise every planned edge with real CNG observations
and an individual deny-site path.

The older plan schema1 two-edge planner still rejects the ordinary dual-return
input after `default<O2>` expands it to four edges; use the explicit schema2
bounded recipe for admitted O2 shapes. The final PE checker proves reported
state-to-site intervals under its supported Windows x64 model, not exact
32-bit predecessor state equality within an interval or numerical influence
for every possible runtime value. It does not prove that an altered original
condition still reaches both branches for arbitrary inputs: replacing its
conditional move with NOPs
currently passes the static check. The dual-branch runtime evidence applies
to the unmodified fixture. Compiler report, private input and PE consistency
alone do not authenticate a jointly replaced set of artifacts; builder-input
consistency and loaded-byte binding remain separate G3 work. Publisher signing
is deferred. This single-owner
unit does not close D7.

### Two-owner mixed POST original edges

`PYOBF_NATIVE_DEMO_POST_MIXED` uses a frozen schema2 plan with profile
`schema4-original-edges-post-two-v1` for the child compute and protection
wrapper. Both owners have whole relative-tree coverage, 3-8 normal edges,
100% selected original edges, distinct edge labels and distinct owned-source
subsets followed by one measured Scope source. The late private input derives
separate owned and measured roots from the early release and Scope material.
The child final checker maps every planned state to its exact linked PE helper
group and checks the bound arguments, direct helper writes and binding-before-
query route. The packer and parent finalizer require both owner proofs; the
parent/child join checks role, site, root and plan identity.

The [plan tests](../native/tests/contribution/post_two_real_plan.py) reject
changed owner/edge/recipe/IR inputs. The [linked child tests](../native/tests/contribution/post_mixed_final_cases.py)
reject plan replacement, helper redirection and, for the source-none PE,
saved-RSI prologue/unwind changes. Actual mixed-none and PRE+POST/O2+archive
builds pass with compute/wrapper edge counts 7/4 and 6/3. The linked proof
does not establish arbitrary original-predicate equivalence or every helper
return leaf under a corrupted dispatcher state. G3 machine-profile closure,
request freshness and loaded-byte authenticity remain open.

### Builder-fixed mixed POST receipt

The opt-in `PYOBF_NATIVE_DEMO_BUILDER_RECEIPT` names a builder-controlled
receipt path. Configure the mixed POST build with that path, run
`cmake --build <build> --target pyobf_native_demo_freeze_builder_receipt`,
then build `pyobf_native_demo_outer`. The freeze target first links the inner
DLL and explicitly records exact SHA-256 values for the child PE, raw CFF
report, private source input, frozen edge plan, CFF input IR and emitted
object. The finalizer consumes the receipt as a file input and has no rule
to regenerate it. If it is absent, the final target fails. The finalizer
compares all six files before analysis, rechecks them before writing its
report, and records `builder_consistency.verified=true` only on success.

The standalone non-POST schema4 source-mixed profile uses
`cff_builder_receipt.py create --profile builder-fixed-source-mixed-v1`
with the PE, raw report, private policy, input IR and object. It has no
frozen edge plan, so the receipt requires exactly five roles. Pass that
fixed receipt, IR and object to `check_linked_cff.py` together with its
existing `--contribution-input`. The finalizer selects the expected
profile from its input mode; a mixed POST receipt cannot satisfy it.

Actual mixed-none and PRE+POST/O2+archive child/parent builds and their
affected mixed CTests passed 8/8 in each configuration. The
[receipt regression](../native/tests/contribution/builder_receipt_cases.py)
rejects a same-length `.text` change with fixed report, paired PE/report/
private replacement, every individual role change, malformed receipts and
a PE changed after machine analysis. The old schema2 O2 affected checks
passed 6/6. The independent [non-POST two-site fixture](../native/tests/contribution/source_builder_receipt_cases.py)
passed 1/1, old source-mixed none/O2 consumers passed 2/2, and the exact
earlier non-POST `require_binding` branch-NOP, entry-state `0xffffffff`
and paired PE/report/private samples now reject under the fixed five-role
receipt; the original sample passes. Without a receipt, those three
mutants still pass the old finalizer.

The optional `PYOBF_NATIVE_DEMO_G3_SUBJECTS` profile requires mixed POST
and the fixed receipt. It emits the child object with function sections and
checks the exact COFF relocation and linked PE extents of the two owner
functions and the owned/measured contribution helpers. The four extents must
be nonempty and disjoint; the final report records them under
`builder_subjects` without changing the semantic binding flags. The
[subject regression](../native/tests/contribution/builder_subject_cases.py)
passed against actual mixed-none and PRE+POST/O2+archive child/parent builds:
affected mixed CTests passed 9/9 in each profile, and the old schema2 O2
affected checks passed 8/8. Seven missing-root, alias, fragment, object,
relocation and PE mutations were refused. A changed COFF byte with a newly
frozen six-input receipt also failed at the production subject proof with no
stale final JSON; this distinguishes the subject check from the receipt gate.

The additional opt-in `PYOBF_NATIVE_DEMO_G3_ENTRY_STATES` profile requires
those exact subjects. For both mixed owners, it independently derives the
first CFF body state from the frozen recipe's CFG seed and function name,
then compares it with the linked PE's decoded `C7 /0` entry write to the
dispatcher state slot. The report records this bounded proof in
`builder_entry_states`. Actual mixed-none and PRE+POST/O2+archive child/
parent builds passed the affected CTests 9/9 each; old schema2 O2 checks
passed 8/8. The [entry regression](../native/tests/contribution/builder_entry_state_cases.py)
changes the entry immediate in both COFF and PE for each owner, re-freezes
the six-role receipt, confirms that the receipt and exact subject proof
still pass, and requires the production finalizer to reject at the entry
proof without stale JSON. Seed, encoding and displayed-immediate mutants
also refuse. This checks the entry value; it does not prove the destination
leaf's behavior, original-predicate equivalence or helper effects.

The further opt-in `PYOBF_NATIVE_DEMO_G3_REPLAY` profile requires the entry
check. Its explicit freeze target reruns the configured `opt` pass and Clang
object emission with the frozen input IR, request manifest, recipe, private
input, edge plan and exact ordered options. It compares the transformed IR,
raw report and COFF object byte for byte before issuing a distinct 13-role
receipt and replay record. The finalizer verifies their fixed bytes and record
consistency; it does not rerun either tool or recreate the receipt. Actual
mixed-none and PRE+POST/O2+archive child/parent builds passed their affected
mixed tests 5/5 each, and the old schema2 regression passed 8/8. The
[replay regression](../native/tests/contribution/builder_replay_cases.py)
changes the real `require_binding` conditional move in both COFF and PE,
re-freezes the older six-role receipt, and confirms that the older finalizer
accepts while strict replay refuses the object and clears stale outputs.
Post-freeze role changes, inconsistent records, altered invocation options
and output-path aliases also refuse. An unchanged outer target does not
implicitly rerun the compiler; an explicit no-change freeze took about 1.1 s
in the measured worktree build.
`fca30c4` closes the child replay's original-path read window for its five
mutable CFF opt data inputs: input IR, request manifest, recipe, private
contribution input and original-edge plan. The freeze copies their pre-read
bytes to scratch and verifies the three path-valued opt options against
their frozen roles before replay. It validates the plan's LLVM module-print
digest against the original IR path, adjusts only that digest for the
scratch path, then restores only verified path-dependent fields before
the transformed IR/report/object byte comparisons. The
[child replay regression](../native/tests/contribution/builder_replay_cases.py)
temporarily replaces each original data path during opt; the repaired
freeze still produces the same record and receipt. Actual mixed-none and
child-O2/archive final reports and dedicated tests pass after the repair.
Concurrent replacement of the compiler executables or plugin and their
dependencies remains outside this controlled-builder proof.

The separate opt-in `PYOBF_NATIVE_DEMO_G3_LOCAL_CALLEES` profile requires the
four exact subjects and two owner entry states, but can run without replay
so its own refusal can be tested. It adds exact COFF-to-PE extents for
`require_binding` and `Scope::binding_status`, checks both mixed helpers'
direct call target and the local call target, derives the binding entry state
from the build seed and raw recipe, and traces the admitted none/O2 linked
status transition: zero reaches the normal return leaf; nonzero reaches the
platform failure call. The proof binds the original Scope and lease entry
arguments through distinct in-frame spills to the status call, constrains
the state and temporary slots against frame escape and overlap, and keeps
the cross-call state outside Win64 shadow space. Actual mixed-none and
PRE+POST/O2+archive child/parent builds passed their affected mixed/G3 tests
10/10 each; after the final stack constraints, local, mixed final and parent
role-join tests passed 3/3 each. The
[local callee regression](../native/tests/contribution/builder_local_callee_cases.py)
re-freezes the older six-role receipt for paired COFF/PE changes to the
condition move, Scope/lease load, out-of-frame spill, dispatcher temporary
alias and state shadow slot. The older finalizer admits them; this local
gate rejects each at its own proof and removes stale final JSON. The old
five-role no-option consumer passed 1/1. Main independently reran both
actual regression scripts after merging `7497244`; both exited 0.
The later `bc229ba` correction checks the exact plain-frame PE unwind
allocation, including a paired xdata edit in the final PE. The older
finalizer accepts that changed image after its receipt is re-frozen; the
corrected local gate refuses it in none and PRE+POST/O2+archive builds.

`PYOBF_NATIVE_DEMO_G3_HELPER_ARGUMENTS` additionally follows the observed
entry state through each mixed helper's dispatcher to its first local
`require_binding` call. Its exact COFF/PE subject and Win64 frame proof
preserves `RCX=Scope` and `RDX=lease` on every admitted pre-binding route.
The [helper regression](../native/tests/contribution/builder_helper_argument_cases.py)
uses paired COFF/PE argument-source, entry-state and early-branch changes
with newly frozen receipts. The older finalizer accepts each, while this
gate rejects each without stale final JSON in none and O2+archive builds.

`PYOBF_NATIVE_DEMO_G3_PARENT_CALLBACK` separately checks the outer
`initialize_session` producer. It binds the exact selected session,
dispatch callback and creator COFF/PE subjects, fixed-frame callback/Spec
assignment and direct creator call, then traces the observed entry through
a bounded static CFG. The [parent regression](../native/tests/contribution/parent_callback_cases.py)
rebuilds final PE, ownership inventory and release report after six paired
COFF/raw-PE changes. The older gate accepts callback substitution, entry
return/skip, dispatcher pivot and `int3`/`ud2`; the parent gate refuses them
with outer source optimization `none` in both baseline and child-O2
PRE+POST/archive builds. Both real and triggered final reports pass the
enabled gate in those profiles. `5df5cdb` removed a false address-order
constraint: seed `61594286` places the valid entry leaf after the return
epilogue, and its real/triggered PE now passes while six existing bypass
mutants still refuse. `6a241e2` adds a separate explicit outer source-O2
lowering, accepting only its two observed dispatcher temporary-slot layouts
and checking the exact PE exception row and xdata stack allocation for both
none and O2 frames. Real and triggered O2 parent images pass the production
finalizer. The [O2 parent regression](../native/tests/contribution/parent_callback_o2_cases.py)
re-finalizes paired callback substitution, entry return and unwind-allocation
edits; the older gate accepts each and the O2 parent gate refuses each
without stale output. The existing six source-none paired refusals still
pass. These are bounded static CFG profiles; transitive callee effects and
all runtime branch conditions remain unproved.

`PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY` adds an explicit, default-off freeze for
the outer producer chain. It snapshots the combined IR, replays the request
pass, optional source O2, CFF pass and Clang object emission through verified
scratch outputs, then recreates the ownership inventory. A fixed 23-input-role
receipt and replay record bind those outputs, the final outer PE, release
record, private inputs, recipe and selected tool files; the finalizer checks
the pre-existing record before and after its proof work. The
[outer replay regression](../native/tests/contribution/outer_builder_replay_cases.py)
passes real and triggered outer-source-none final reports in mixed-none and
child-O2/archive builds. Paired COFF/PE and report/inventory changes with
unchanged frozen records pass the older gate and fail this one. Synchronized
transient input swaps show that later compiler stages consume the verified
scratch chain, including the source-O2 path. The outer source-O2 case proves
only this compiler replay; the separate parent O2 proof above admits actual
final reports, while a combined strict replay and parent O2 final report
has not yet been tested.

`PYOBF_NATIVE_DEMO_G3_ORIGINAL_PREDICATES` adds a separate, default-off
source-none machine proof for the two selected mixed POST owners. It checks
the fixed pre-CFF IR's two compute conditions and one wrapper condition,
then follows the modeled Win64 argument sources through the actual linked
comparisons, polarity, encoded state choices and reported successor states.
Unknown source-path writes and changed register aliases fail closed. The
[predicate regression](../native/tests/contribution/builder_original_predicate_cases.py)
checks the actual source-none finalizer and five paired COFF/PE edits with
newly frozen receipts that the older complete finalizer accepts but this
gate rejects without stale output: two self-comparisons, a changed compute
argument, an overwritten wrapper handoff slot and a `%r10d` alias route.
Two further entry/stack arithmetic edits are rejected independently by
this module but already fail the older joint-machine gate, so they do not
count as new production refusals. Valid IR polarity edits also refuse.
The child O2+archive condition compares against published archive values;
its source-to-publication equivalence is unproved, and this option rejects
that profile rather than granting positive original-predicate evidence.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_ORIGIN` is a separate default-off predecessor
for that O2+archive machine proof. It requires PRE+POST/O2/archive and child
G3 replay. The builder first constructs the child, explicitly freezes its
replay receipt, then explicitly freezes a distinct 20-role archive-origin
record before finalization. The archive freeze replays the deterministic
plan, pending IR, request merge, link and materialization stages from byte
snapshots. It checks all 36 descriptors, access and body AES-GCM tags and
typed plaintext against the plan, then regenerates the exact C++ source.
The finalizer verifies the fixed record, roles and child-replay join before
and after other checks; it never refreshes the record automatically. The
[actual archive-origin regression](../native/tests/contribution/archive_origin_cases.py)
shows an altered record-28 zero value passes the older complete finalizer
but fails this option with stale output removed. Authenticated-package,
wrong-key, generated-source and output-alias negatives also refuse. This
establishes controlled-builder consistency only: runtime C++-to-IR and its
request pass are fixed inputs, and the wrapper's PE publication/read effect,
cache integrity and O2 machine comparison remain unproved.

The separate default-off `PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR` closes the
selected requested-to-optimized IR edge before archive-origin. An explicit
freeze target records exact requested IR, optimized IR and `opt.exe` paths,
digests and the fixed `default<O2>` command; the finalizer never refreshes
the record. It replays the optimizer from snapshotted input, normalizes only
the temporary first-line ModuleID, joins optimized IR/tool paths and bytes
to both the archive record and CLI roles, and checks inputs again before
writing its report. Main seed-692 finalization and its dedicated CTest pass.
Old-finalizer-admitted requested IR changes, forged digests, changed tool/
output/options and same-byte wrong paths or hardlinks refuse with stale
output removed. A record hardlink to an input refuses before unlink. The
record symlink guard was tested with a simulated path because this Windows
environment denied real symlink creation (`WinError 1314`); that OS case is
UNVERIFIED. C++ source provenance, dynamically loaded optimizer libraries,
publisher signing and concurrent replacement remain outside the claim.

The further default-off `PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES`
binds the wrapper's requested `ne` comparison, O2 `eq` inversion and
archive-prepared branch identity to its exact linked comparison and encoded
successor states. It joins the two compute archive-publication conditions,
yielding three selected original predicate routes in one seed-692 O2/archive
product. The actual pre/post-reload source intervals are checked as closed
machine inventories. Independent review replayed four paired COFF/PE
register/state/frame bypasses admitted by the preceding publication gate;
all now fail this gate. The main joint final report and dedicated CTest pass.
Its report keeps observation body, callback, decoder/cache, general O2
equivalence and runtime loaded-byte effect claims false.

The receipt is trusted only because the builder freezes and retains it
independently of finalization. Replacing it together with every input in
any profile can pass if internally consistent, as the regressions demonstrate.
It does not sign the
distribution, authenticate runtime loaded bytes, establish an atomic
disassembly snapshot or prove original-predicate semantics outside the
bounded source-none option above, or transitive helper effects. The
four-subject profile proves those exact
COFF-to-PE extents; the entry-state profile proves only the two owner
initializers relative to frozen recipe seeds. Replay proves a deterministic
producer chain only under the trusted builder, frozen pre-CFF IR and the
selected toolchain. The outer record's tool, plugin and recipe digests bind
files observed at freeze and final verification. They do not prove the bytes
actually executed if those paths can be replaced during a subprocess; this
unit assumes immutable toolchain and recipe paths in the controlled builder.
C++-to-IR and native link replay, transitive tool DLLs and distribution
authentication remain outside its proof. G3's
local-callee result proves only this bounded route and its input identities
within `require_binding`. The subsequent helper gate proves the first
observed-entry Scope/lease acquisition but not all input states or transitive
binding effects. The parent gate proves a bounded static callback route but
not all runtime branches, creator effects or platform failure semantics.
The separate opt-in `PYOBF_NATIVE_DEMO_G3_BINDING_STATUS_EFFECTS` checks the
selected `binding_status` pointer, generation and availability decision and
the three local accessor bodies in actual source-none and O2/archive PE/COFF.
It binds exact E8 targets to function-root relocations and refuses paired
guard, field, same-address section-symbol alias, overlapping stack and
Win64 outgoing shadow-space mutations; both profiles pass their focused
real-product tests. Its final report keeps `transitive_binding_closed=false`
and `context_availability_body_verified=false`. The latter callee body,
request/query through `invoke`, platform callbacks and arbitrary runtime
memory integrity remain open. Full EH, original-predicate equivalence and
loaded-byte authenticity remain open. G3's closed machine profile and D7
acceptance remain open.

The further default-off `PYOBF_NATIVE_DEMO_G3_CONTEXT_AVAILABILITY_EFFECT`
requires binding-status effects and proves the selected called
`context_availability` closing-field bit/status selection, local CFF route,
and exact lock/unlock PE targets with COFF root relocations and Win64 frame/
unwind. Source-none and O2/archive actual products pass. Paired COFF/PE
closing-mask and lock-target edits pass predecessor gates with a new six-role
receipt, then fail this local gate and clear stale output. Its report sets
`context_availability_body_verified=true`, `closing_field_route_verified=true`,
`lock_pair_route_verified=true`, `platform_lock_effect_verified=false` and
`transitive_binding_closed=false`. The platform lock body, request/query/
invoke/callback chain and arbitrary runtime writes remain outside this proof.

The further default-off `PYOBF_NATIVE_DEMO_G3_BOUND_CALL` requires context
availability and binds the selected `call_bound_bootstrap` publication
pointer guard, retain-status branch, captured-lease construction and
unchanged invoke request to exact source-none and O2/archive COFF/PE routes.
Both real option-on products pass dedicated CTests after a latest-main
worktree merge. Paired pointer self-compare and wrong-request changes pass
the predecessor proofs but fail this gate, with stale output cleared;
frame, call-target and unselected-dispatcher negatives also refuse. Its
report keeps `publication_source_verified`, `retain_effect_verified`,
`invoke_body_verified`, `platform_lock_effect_verified` and
`transitive_binding_closed` false. Those callee and platform effects and
the request/query/callback chain need separate proof.

The further default-off `PYOBF_NATIVE_DEMO_G3_RETAIN_LOCAL` binds one
`retain_context` local route: closing and `UINT32_MAX` guards, successful
reference increment writeback, returned status and exact lock/unlock calls.
The two observed source-none and O2/archive lowerings have separate exact
COFF/PE body inventories and numeric-limit helper shapes. The independent
worktree passed both option-on final reports and focused CTests after a
latest-main merge; main reran both actual-product scripts. Paired no-write,
self-compare, comparison-input-zero and changed-maximum mutations pass the
preceding local gate but fail this one and clear stale output. The unchanged
fixed replay receipt independently refuses changed object bytes. The report
keeps `full_retain_effect_verified`, `platform_lock_effect_verified`,
`publication_source_verified`, `invoke_body_verified`,
`callback_effect_verified` and `transitive_binding_closed` false. Full
ownership/lifetime and cross-function effects need separate proof.

The further default-off `PYOBF_NATIVE_DEMO_G3_INVOKE_LOCAL` requires the
bound-call and retain-local checks. It binds the selected source-none and
O2/archive `BootstrapContextLease::invoke` entry arguments, request guards,
admit status selection, captured context dispatch/userdata, exact indirect
callback call, normal completion call and result return in COFF/PE. Both
latest-base worktree products passed their final reports and focused CTests;
a paired callback-call removal passes the prior bound-call proof but fails
this gate and clears stale output. The joint seed-692 main product also
passes. `admit_effect_verified`, `complete_effect_verified`,
`callback_identity_verified`, `callback_effect_verified`,
`platform_lock_effect_verified`, `runtime_memory_integrity_verified` and
`transitive_binding_closed` remain false.

The further default-off `PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION` requires
the fixed child replay and archive-origin records plus mixed POST subjects
and entry states. In the selected PRE+POST/O2/archive lowering it checks six
archive wrapper COFF/PE machine frames and exact decoder/cache/package
arguments, all six writable output and cache extents, two published-slot
reads, original argument reloads, comparison polarity and single-entry
call-to-state CFG paths. Every owner direct call has an exact raw E8 target
and COFF function-root relocation; intra-owner and indirect calls refuse.
Actual paired read-only slot, cache/argument alias, wrong callee, wrapper
frame, local jump and call-target bypasses refuse. The full finalizer first
checks the mixed POST helper bodies and routes; the standalone publication
verifier assumes those external calls return normally. Its report sets
`decoder_effect_verified=false`,
`original_predicate_equivalence_verified=false` and
`transitive_callee_semantics_verified=false`. Runtime decoder/cache effects,
other emitted O2 layouts, loaded bytes and distribution authority remain
outside this selected proof. The seed-248 and seed-692 physical comparison
orders both pass; seed-692 also passes when publication, binding-status and
context-availability checks are enabled together. This is a fixed-builder
input-to-PE consistency claim, without final-distribution signing or
runtime loaded-byte authentication.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE` additionally binds the
selected `require_record -> acquire_record` and acquire -> parse/access/decode
call roots to exact COFF relocations and PE targets, with local argument,
frame and return-region constraints. The seed-692 O2/archive isolated product
passed origin/publication/decoder-linkage CTests 3/3 after a latest-main
code merge. Paired call retarget, wrong argument, frame, captured-stack-slot
and jump-into-protected-instruction edits refuse. Its true call-linkage
fields do not imply decoder/cache effects, platform crypto or acquire
inter-state reachability; all four stay false in the report.

The further default-off `PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM` binds
one conditional first-use arm to the selected cache state read, zero-to-one
CAS, decode result, failure erase and state-two/three publication in actual
seed-692 O2/archive COFF/PE. Paired call-target and state-source mutations
pass the preceding decoder-linkage verifier and fail this gate; the unchanged
fixed receipt independently rejects changed object bytes and clears stale
output. The worktree passed origin/publication/decoder/first-use CTests 4/4,
and main independently reran the focused actual-product test. Its report
keeps `normal_first_use_reachability_verified`, `decoder_effect_verified`,
`cache_effect_verified`, `platform_crypto_verified`,
`cache_content_integrity_verified`, `external_destination_integrity_verified`
and `transitive_archive_effect_closed` false. Loaded-byte authenticity and
whole-distribution replacement resistance are not claimed.

`PYOBF_NATIVE_DEMO_G3_ARCHIVE_ENTRY_ROUTE` adds the selected success path
from `acquire_record` entry through parse, key, capacity, destination,
alignment, package/cache overlap and access guards to that first-use arm.
Its exact COFF/PE state and call-target checks reject paired parse/access
selector, key comparison and overlap retarget mutations that both preceding
decoder and first-use proofs admit. The worktree option-on report/test and
joint seed-692 main report/test pass. The report leaves parse, overlap,
access, atomic and cache effects, arbitrary-input reachability and
transitive archive closure false.

## Mixed providers within one explicit site

Private input schema4 uses `provider: "source-mixed-v1"` and one or two explicit
site rules per owner in the bounded Windows x64 whole-function profile. Each
site selects exactly one `measured-scope-v1` source and
at least one `owned-context-v1` source in catalog order. The three-argument
`pyobf_native_mixed_contribution_site_v1(owned_lease, measured_scope, site)`
marker supplies distinct references at that site; its ordinary definition is a
no-op. The admitted source profile requires both references to originate
from distinct function arguments, directly or through one immutable entry
pointer spill each. Dynamic aliases and global references are unsupported.

Each source selects a schema4-specific eight-argument query helper with its own
marker reference and the other reference as the final argument. Each helper
compares the Scope's captured parent with the supplied lease by exact non-null
context-state pointer, nonzero generation, initial status and availability
before producing its word; a failed check stops with `0x702`. Both helpers
observe the same pre-transition state word; ordered results enter one framed
state update. The compiler freezes both reference operands, per-source
provider, query order, helper, argument origins and result flow, and rejects
changed references, helper/word substitutions and detached results. The report
records scheme 4, `joint_helper_contract: "source-mixed-context-v1"`,
per-source provider/version, separate helper counts and the private input
digest. The contract label describes runtime helper ABI and LLVM proof; it
does not certify final machine argument provenance. It sets
`cross_provider_owner_binding_verified=false`,
`generated_owner_independence_verified=false` and
`individual_sites_verified=false`.

The bounded CLANG64 Windows x64 final checker verifies each helper return
reaches its effective CFF state write. It rejects intervening clean overwrites,
overlapping wide writes, unsupported calls or conditional terminators, and
changed helper order. The two-site profile additionally maps each ordered
provider/source group to an exact PE caller path and demonstrates local numeric
sensitivity of every helper return under its admitted instruction model. Actual
none/O2 linked executables exercise owned context and CNG-backed Scope success,
denied owned/Scope/Snapshot/material, and equal-generation foreign context
refusal before the protected effect. Linked PE cancellation and unknown-read
mutants are refused; this local sensitivity does not establish globally reachable
states or rejection of every wrong return value.

The opt-in `--check-joint-caller-flow` diagnostic checks exact PE bytes in one
Windows x64 unwind interval, direct CFG paths, stack/register aliases, entry
spills and first/eighth pointer arguments. With a separately supplied
`--contribution-input`, the final checker first compares the raw private
schema4 policy SHA, owner, sites and source catalog with the compiler report.
For two explicit sites, it then checks every helper call's RDX/R8D/R9D routing,
domain and owner ID against that fixed private input through a conservative
32-bit CFG constant flow. Missing, ambiguous, partially written or changed
arguments refuse finalization without JSON. The live `current` state argument
is checked by its existing state-origin route, not compared with a policy
constant. Without `--contribution-input`, this private argument check is absent.
For two explicit sites, the linked-image gate also checks each admitted
`cmpl imm32; jae` dispatcher split as a nonempty unsigned 32-bit interval,
tracks the state slot through permitted copies, and requires a deterministic
leaf route to each real helper group. Overlapping state writes, empty or
ambiguous intervals, duplicate leaves and skipped tree instructions refuse
finalization without JSON. This is a local proof from an arbitrary dispatcher
state; it does not show that entry state or earlier helper returns reach each
interval. The actual linked root-pivot-to-zero mutation passed the earlier
finalizer and is refused by this gate.
The finalizer also requires both owned and measured helper symbol blocks from
the same linked image before the two-site site-map check. A missing helper
block refuses finalization and clears a stale final JSON. Each helper block
is checked against its exact PE bytes and unwind interval. A bounded CFG
analysis tracks RSP and stack-derived aliases, allowing proven local writes
while refusing direct writes into the caller frame or return address, writes
below the reserved frame, unknown writes or adjustments, ambiguous merges,
and hidden non-padding instructions. The fixed caller-Scope-slot write mutant
passed the previous finalizer but is now refused without final JSON. Separate
disassembler calls and PE reads still do not form an atomic image snapshot.
The linked route gate checks the rel32 bytes and decoded target of each direct
call in both helpers. Each query path must first reach the expected binding
call; duplicate, missing, redirected, skipped or branch-bypassed binding,
query and failure calls refuse finalization without JSON. Fixed owned and
measured helper `require_binding` calls redirected to `Scope::binding_status`
passed the previous finalizer and now refuse. These checks bind routes to
linked symbol names, not the symbol table's authenticity or the binding
callee's body and argument semantics.
The generic finalizer clears an earlier `--output` before validation while
rejecting output paths that alias an input.

These are bounded caller and helper-body diagnostics. A first helper's callee
or callback can still write a prepared caller slot before the second call;
the checker does not authenticate transitive memory effects or external object
aliases. A replaceable private policy also needs an earlier trusted or signed
manifest binding before it can serve as an authorization anchor. Each helper
call remains a separate transaction. `joint_caller_pointer_provenance_verified`,
`cross_provider_owner_binding_verified`, generated-owner independence and
individual-site machine equivalence remain false or unproved. The bounded
automatic mixed-provider two-edge and 3-8-edge profiles above are separate
from strict POST payload binding and arbitrary CFG support.

## Transformation and proof

A4 splits each explicit point into a routing gateway, then issues a query with its live CFF
state. A5 derives the normal word from private build input and seals the encoded correction.
Only sealed constants and public query fields are emitted. The expected word or its mask is
not emitted alongside the correction and there is no runtime expected-value table. The
status-returning `contribution::request` primitive clears the word on failure; the generated
owned scalar helper now terminates with protection reason `0x702` on a failed or zero result,
before that value enters the CFF state. The measured helper uses the same failure reason.

The private source/state/target plan is frozen before binding. The compiler checks the final
wrapping state update, actual query-result mask, source/state ownership, query inventory and
sealed targets. `pyobf-native-contribution-verify` independently checks the retained IR
acquisition/dataflow shape. The linked Windows x64 checker additionally requires exact query-call
count and mask presence, then binds its report to exact image bytes. Machine presence is
weaker than a full native dataflow proof; it does not establish authorization or resistance
to arbitrary coordinated binary replacement.

The collection/transformation stages reject already generated contribution artifacts and raw
calls to the reserved scalar query ABI. Use the public C++ request API for ordinary manual
queries. An optional component with zero source points preserves ordinary reference behavior
and receives neither IR binding nor final query-presence credit.

The default report calls this `explicit-source-point`, and
`original_real_edge_density_verified` remains false. Whole and the verified hybrid scopes
are admitted, including the registered transition layers below. Region gates follow their
separate boundary contract and still reject these function-only layers.
Other component compositions remain subject to their actual validation, not an assumed
blanket compatibility promise.

## Automatic original-edge selection

Set this per-function override, while keeping at least one explicit source point:

```json
{"schema_version":1,"functions":{"compute":{
  "components":{"runtime-contribution":"required"},
  "contribution":{"selection":"original-edges","minimum_edges":1,
                  "minimum_percent":100,"maximum_edges":256}
}}}
```

`explicit-points` is the default selection. Count and maximum accept integers0..65536;
percentage accepts0..100. Defaults are1,100,256. The separate
`budgets.max_contribution_sites` bounds automatic and explicit queries together. Required
count is the greater of `minimum_edges` and the ceiling of the requested percentage of
original edges. An insufficient budget rejects compilation, including an empty denominator
with positive percentage. Explicit zero requirements are preserved. Zero selected edges
never receive verified density; an empty denominator reports a null percentage.

The denominator is every normal `br`/`switch` successor operand and admitted `invoke` normal
edge retained in the actual CFF input, including duplicate switch targets and loop back
edges. Invoke unwind edges are excluded and reported separately as `excluded_unwind_edges`.
The inventory is captured before CFF
gateway preparation, splitting, padding, switch lowering and dispatcher generation. Source
optimization may already have removed or cloned flow: this is explicitly
`retained-cff-input-normal-successor-edges`, not a raw source/pre-O2 count. Returns, resume and
unreachable terminators have no successor edges. Generated CFF edges cannot increase density.

The original automatic profile requires all source points in one owner to name the
same canonical lease argument or explicit global object. Simple single-assignment
entry spills are admitted; ambiguous sources, mutable spills and an absent source
point reject. The caller holds that lease object, its admission and executing module
through return or unwinding. The compiler does not infer a lease from process-global
publication. Per-build seeded ranking selects up to the edge budget;
nonzero site identities are checked against each other and explicit labels for collision.
Selection is reproducible for the same retained input, function name and seed.

Each selected successor receives its own routing gateway, with parallel-edge PHIs repaired.
The compiler freezes source-to-gateway routes, records switch lowering, and verifies its
condition store, case/default chains and private storage. Before binding it freezes normal
branch choices; afterward it verifies encoded destinations, live state updates, initial
state, complete comparison-tree partition and absence of extra state writers/escapes.
The separate gate seal checks the query-bearing gateway corrections. These checks earn
coverage only after actual transition binding succeeds. Other components with preparation
hooks currently reject in this mode until their route composition is verified, except the
registered opaque/junk layers, non-CFG initializers and framed call-step preparation described below.

The report identifies `original-edges-and-explicit-points`, lists selected/bound original
edges, explicit points, thresholds, budgets and exclusions, and verifies density only for a
nonempty bound subset. The final-image checker rejects inconsistent counts, entries,
thresholds or density flags, then checks exact query/mask presence and image ownership.
Source-route seals are compiler-private checks at their stated stages; the standalone
retained-IR verifier checks query/dataflow shape. Neither is an arbitrary post-link semantic
equivalence proof.

### Multiple Scope references on original edges

The bounded schema2 `measured-scope-v1` profile permits distinct live Scope
arguments or explicit globals in one whole ordinary branch/switch function.
Author the private mapping in two passes over the same retained IR, recipe,
seed and source optimization. A first pass with zero selected edges reports
seeded original edge IDs and labels without emitting generated queries or
claiming density. For every edge selected in the second pass, add its label
as an explicit site rule with a nonzero `reference_site` naming one retained
explicit measured marker. Its source, word label and mixing/derived domain
must match that marker's rule. The marker must dominate the original edge
source; the generated query must retain its exact argument/global origin.
Unselected rules, a `reference_site` on an explicit marker or single canonical
Scope, missing/duplicate/stale anchors, pointer swaps and changed entry-spill
writes fail closed.

The compiler freezes the original anchor and pointer before CFG normalization,
then checks the generated marker/query, immutable entry spill and explicit
anchor query after transformation. The report records each selected original
edge's `reference_site`; zero selected edges still earn no density. Actual
Windows CLANG64 source-none/O2 executables use two CNG-backed Scope snapshots,
exercise both generated sources and reject swapped references, failed material
and a linked EXE with a detached query return. A separate compiler fixture
covers global Scope origins. This first profile rejects EH, region,
deduplication, `split-blocks` and `common-exit` with multiple Scopes; the
existing single-reference paths retain their prior contracts. The standalone
final checker does not prove generic per-edge machine pointer equivalence,
and a coordinated self-consistent IR/metadata rewrite is outside this unit's
independent authority. `individual_sites_verified` and generated owner
independence remain false.

## Hybrid EH composition

Set `"coverage":"hybrid-eh"` on the same function override. This supports the existing
`x86_64-w64-windows-gnu` C++ landingpad profile with explicit points or `original-edges`.
Unsupported target/personality models still reject. Explicit source points inside the
landingpad header reject; points in ordinary catch/cleanup continuation bodies are admitted.

The compiler records the exact invoke-to-EH-return-gateway-to-contribution-gateway chain
and original unwind destination before lowering. The existing hybrid proof still owns
invoke/pad/resume, armed unwind corrections, initial state, state storage and dispatcher.
Normal original-edge density does not certify transformed unwind edges or full-function EH
coverage. Final reports cross-check unwind exclusions against the actual hybrid scope.

`TransitionBinding` is a compiler-only proof interface. Consumers first verify the full
frozen producer plan, then accept only an exact unconditional body/state/ordinary-target
reference from that plan. Contribution normal targets remain private compiler data.
Query metadata alone cannot exempt a branch from route verification. The gate seal also
freezes its decoder salt: changing both
retained decode code and its metadata cannot substitute another state layout.
The private source plan separately freezes the contribution salt and routing/domain/function/
source identities. Coordinated edits to query arguments and their retained metadata must
still reject, even when the standalone retained-IR shape checker accepts their consistency.

## Transition layer composition

Enable any subset of `opaque-choices`, `reachable-junk` and `decoy-transitions` alongside
`runtime-contribution`. The registered order remains opaque, junk, then decoy. Explicit and
automatic selection accept these layers in whole functions and supported hybrid normal
bodies, with single or ordered grouped owned-context sources. The original-edge inventory
and source query counts remain independent of generated preparation/transition structure.
Invoke/landingpad boundaries retain their existing path; the layers do not certify EH flow.
Hybrid normal layers also work without runtime contribution. Region capabilities remain
function-only for these three components, so their region combination still rejects.
Ordinary O2 can eliminate original branch requests. A required request still rejects when
its original site disappears; use optional structural requests when that loss is permitted.
The O2 composition fixture keeps contribution required and independently requires each
intended layer to have nonzero applied sites and final presence. It also explicitly verifies
the corresponding strict lost-original-site refusal. This does not promise that arbitrary
source branches survive optimization or credit optimized-away requests as protected sites.

```json
{"schema_version":1,"functions":{"compute":{"components":{
  "runtime-contribution":"required","opaque-choices":"required",
  "reachable-junk":"required","decoy-transitions":"required"}}}}
```

Each layer registers its actual emitter and a pure entry-state identity capability. The
compiler builds a reference in an isolated LLVM module using the frozen owner, original
provenance, expected state, seed and rounds. Evaluating its private state reads at that entry
must leave an arbitrary symbolic normal encoded value unchanged. A constant return or a
cancelled normal input cannot satisfy this capability. Reference construction never adds
users, predecessors or instructions to the actual function.

The exact graph matcher unwraps the actual emitted expression in reverse registration
order, preserving operation types, predicates, poison flags, repeated operands, distinct
instruction/observation identities, read
identity/volatility/alignment and state storage. Only a complete successful match exposes
the normal core and exact owned reads to the existing source and normal-flow proofs.
Those consumers still prove actual query influence, private source/correction identities,
ordinary branch choices, decoder and all authorized state users/writers. A layer never
grants a query gateway or an unrelated read/write an exemption. Unreachable bogus-body
effects belong to their own existing path; a local layer-shape proof does not grant those
effects a normal-route obligation. Bogus controls use their separate predicate/write contract
below; other not-yet-admitted data/provider compositions remain open work. Normalized
snapshots preserve source/frame routing roles, and bogus placement excludes those boundaries.

Frozen compiler plans independently bind selection, order, states, seeds and provenance.
Retained `pyobf.transition.layers` metadata permits standalone shape reconstruction, but
cannot replace that independent plan: a coherently rebuilt, differently seeded/reordered
layer can be internally consistent and still fail the frozen compiler proof. Verification
clears compiler-only normal/read caches before each attempt and publishes them only after
full success. These are not runtime observation caches or D7 independent evidence.

Rows expose `transition_layer_contract_verified` only after the combined compiler proofs.
The final x86 COFF gate requires that flag plus the existing opaque products, per-site junk
coefficients and distinct decoy coefficients/selections. Decoy's dynamic wrong-state arm
uses a dense public coefficient disjoint from the mandatory junk coefficient bits; an
opaque conditional selection alone cannot certify it. Individually erased layers remain
runnable under correct input but must fail retained and final presence checks. Such checks
remain scoped presence evidence, not an arbitrary post-link equivalence or authenticity
proof. Finite-width collisions and controlled-runtime replacement remain outside this claim.

## Initializer preparation composition

Whole-function and admitted Windows GNU hybrid explicit/automatic contributions compose with
`reference-routes`, `import-routes` and `indexed-locals`, independently or together.
These function-only components remain unsupported in regions. Framed structural call
steps and bogus controls follow their separate contracts below; other data/provider compositions remain open.

The automatic guard admits existing `changes_cfg=false` preparation hooks through their
full per-hook CFG/definition seal. Source/gateway proof still runs after preparation, and
normal-flow proof still checks actual choices, query corrections, root users and dispatcher.
Declaring a non-CFG initializer does not exempt a changed source edge from those proofs.
An initializer never contributes an original edge to the density denominator.

Both reference and frame discovery preserve closed compiler source markers. Contribution
points and path-fold markers cannot become ordinary routed imports or framed user calls
before their compiler stages consume them. Defined user targets and strong imported targets
remain actual candidates. The existing source checks still reject malformed, escaped or
defined contribution point markers; the shared name predicate is not an ABI validation bypass.

The shared state-binding proof compares reference, call-preparation and local data bindings
with the independently frozen body-state map. Tagged reads must use the actual CFF root
through the exact ordinary i32/alignment/read contract. Wrong states, foreign roots, moved
bindings and malformed/wrong-width words reject. Each component's existing target, table,
frame and expression verifier still proves its own graph; metadata grants no read/write
authority. This shared boundary runs in whole contribution and supported hybrid flow proof,
and does not claim arbitrary post-link dataflow authentication.

The executable fixture keeps a real defined identity function, a separate imported identity
and volatile local storage, preserving the independent arithmetic reference. It asserts
nonzero applied features, source counts/density and exact final-image evidence under
none/O2, explicit/automatic and single/grouped sources. Structural O2 requests follow the
optional/strict-loss distinction above. A representative grouped hybrid O2 path also retains
all three transition layers. Individually disabling each initializer remains runnable but
must fail the original final protection claim. A separate frame inventory control proves
that one real external call, rather than source markers, creates the helper.

The hybrid local fixture independently counts retained source stack objects and lifetime
markers, including catch/cleanup storage. Its real CNG/EH execution covers caught and escaping
exceptions, exact destructor effects, reentrancy and concurrent invocations. Disabling only
the hybrid owner's local component preserves these semantics but fails that owner's original
final-image claim; perturbing its actual local-state reads prevents successful execution.
Source O2's lost original objects separately fail a required request. Production table/state
contracts also reject thirty-three valid-IR mutations in both ordinary and invoke/landingpad
fixtures, including an altered lifetime operand. Final checks remain scoped presence evidence.

## Framed call and preparation composition

`call-frames`, `external-calls` and their `call-preparation` steps compose with explicit or
automatic contributions in whole functions and admitted Windows GNU hybrid normal bodies.
The existing frame ABI, target, storage, ownership and unsupported-subset rules still apply.
Frames can be enabled independently of call steps. Reference/import initializers, whole
indexed locals and the three transition layers keep their own checks when combined here.
Generic `split-blocks` also admits the existing GNU hybrid scope; see the structural
normalization contract below. Region normalization remains unsupported.

The frame normalizer explicitly transfers an original invoke's source identity to its real
replacement before result RAUW or deletion. It registers the typed-result completion corridor,
whose exact unconditional chain must reach the frozen original contribution gateway through
the admitted EH-return route. Original normal/unwind destinations are preserved. Only registered
call-step or generic normalization splits can extend that corridor. Replacement, completion and
EH bridge identities cannot follow RAUW into a lookalike; wrong routes, replay, deleted nodes
and unregistered splits refuse. Successor queries first require an actual terminator, so an
unregistered invoke-result replacement refuses instead of treating a result load as a branch.

This trace owns source continuity, not frame ABI authority. The existing module frame verifier
still proves the actual typed target and argument/result behavior; preparation proves its field
steps and frozen state/root bindings. Source, normal-flow, gate and dispatcher proofs then run
on the actual composed path. Generated invokers, result completions, EH bridges and preparation
states never increase the original normal-edge denominator or original authored definition count.

Production contracts exercise the historical i32-invoke RAUW defect, preserved original normal
and excluded unwind counts, registered completion splits, changed normal/unwind registration,
conditional completions, unknown sources, bypasses, deleted/replaced nodes and replay. The actual
multi-file CNG fixture covers internal/external frames with call steps under source none/O2,
whole/hybrid and explicit/automatic selection, including ordered sources and a retained
initializer/layer/whole-split composition. Catch/escape/cleanup, nesting and concurrency keep
independent reference results. Correct-input executables with a directified typed target or a
forwarding wrapper retain normal behavior but must fail the original final invoker/owned-route
claim; omitted helper rows must also refuse. These remain scoped final-image presence checks,
not arbitrary post-link equivalence, authentication or protection against runtime extraction.

## Bogus control composition

Whole and admitted Windows GNU hybrid normal bodies accept `bogus-clones` and
`bogus-synthesis` with explicit or automatic contribution gates. They remain function-only
components; region selection still rejects them. Existing donor, growth and site budgets
continue to apply. Clones require self-contained wrapping i32 argument arithmetic; raw
frontend-O0 spills may make a donor unavailable. Ordinary promotion/optimization can expose
one. Required absence rejects; optional clones can remain unapplied while synthesis uses
available allocation. Changing shared quotas requires collecting requests for that recipe;
the compiler does not silently discard the previous recipe's original obligations.

```json
{"schema_version":1,"functions":{"compute":{"components":{
  "runtime-contribution":"required","bogus-clones":"optional",
  "bogus-synthesis":"required","integer-literals":"optional"},
  "contribution":{"selection":"original-edges"}}}}
```

A4 creates the actual opaque predicate, normal/fake destinations and decoy result store before
normal-flow conditions are frozen. A5 may hide constants without replacing that condition.
The model uses the same pure scalar literal emitter under the frozen state/seed to prove
raw or decoded predicate graphs. It retains exact operation/type/poison/alignment/root and
distinct-observation checks. Moving an acquisition from its tagged transition remains illegal;
query gateways and frame/EH completion routing are indivisible bogus-placement boundaries.

Compiler construction records non-RAUW guard/predicate/result/store identities, destinations,
states and codec plan. Private proof validates the actual normal/fake encoded choices and
decoy continuation, then authorizes only that precise result store. Whole/hybrid flow still
checks initial state, dispatcher and every other state read/write. No conditional bypass or
body-role tag grants general write permission. Each attempt clears compile-time proof caches;
exact capabilities publish only after all its control sites verify. These caches are not
runtime observations or independent D7 measurement caches.

Typed retained descriptors permit standalone shape reconstruction. The compiler additionally
cross-checks its independent frozen plan: a coherent new descriptor or same-shaped replacement
store can pass reconstruction while failing that plan. Missing/duplicate/malformed descriptors,
constant conditions, altered routes, merged observations, foreign roots and unowned writes
refuse at their respective boundaries. Reserved descriptors/attributes are rejected as input.

Rows expose `bogus_control_contract_verified` after combined IR checks. The final Windows x64
gate requires it and the existing opaque products/per-site work coefficients, binding its
report to exact image bytes. Control proof establishes guard/write authority, not every decoy
arithmetic instruction: removing unused decoy mixing can leave its control shape valid but
must still fail final work presence. Runnable guard/work erasures preserve normal output while
losing the original protection claim. This is scoped presence evidence, not arbitrary post-link
equivalence, remote attestation or protection against dumping a valid body and context.

Actual multi-file CNG cases exercise each strategy across whole/hybrid, explicit/automatic and
source none/O2, using explicit mem2reg source inputs for conservative donors. Separate raw
input synthesis and required-absence checks distinguish that input contract. Grouped sources,
both strategies with scalar hiding/transition layers, and a framed/prepared hybrid synthesis
composition preserve independent results and failure behavior. Generated guards, fake work and
their state writes cannot increase original-edge density or satisfy source requirements.

## Scalar data composition

Whole and admitted hybrid owners accept `integer-literals`, `comparison-constants` and both with explicit or
automatic contribution acquisition. They use the existing independent data strategy files,
state masks and normal/source flow proofs. No additional provider or bootstrap ABI is needed.
Region data admission keeps its existing component-specific restrictions.

Hybrid comparisons rewrite operands in the original ICmp, retaining the independently frozen
condition identity and clearing its same-sign assumption. A separate `HybridScalarBindings`
adapter freezes each eligible literal return, body, original value/type, state root/label and
seed before binding. Its isolated literal model admits bounded integer arithmetic/casts and
requires the exact emitter graph and actual root. Only a successfully proved original return
operand may change; replacement returns, metadata claims, arbitrary RAUW, invoke/resume and
other terminal changes cannot gain that permission. Failed proof clears the adapter's private
verified operand map. Identity, predicate and literal model roles are not interchangeable.

```json
{"schema_version":1,"functions":{"compute":{"components":{
  "runtime-contribution":"required","integer-literals":"required",
  "comparison-constants":"required"},
  "contribution":{"selection":"original-edges"}}}}
```

Required means the original requested sites must survive optimization and receive protection.
An optional lost request may instead report `optimized_away` with zero applied sites; it cannot
earn final feature coverage. Source-O2 composition fixtures use optional data requirements and
independently demand nonzero actual application. Separate required-loss negatives retain the
strict refusal. Configuration does not turn optimized-away work into protected work.

Actual multi-file CNG fixtures exercise each data strategy and both across source none/O2 and
explicit/automatic acquisition, with normal and wrong/missing/foreign context results. The i32
integration fixture supplements the existing independent typed scalar tests; it does not by
itself prove every width or all possible recipes. A grouped promoted-source composition also
retains both bogus strategies, all three transition layers, frames, call preparation and data
initializers. It deliberately includes real argument arithmetic as a conservative clone donor;
a call-result-only fixture still cannot demand a clone. Independent host results match that
source variant. Removing either scalar strategy preserves normal execution but must fail its
original final-image claim. These are scoped feature-presence checks, not arbitrary linked-code
equivalence or protection from dumping a legitimate context.

The opt-in `pyobf_native_measure_contribution_scalars` target builds scalar-off
and scalar-on grouped automatic owned-CNG images from one retained source,
private input, request inventory and common seeds. Both retain the other
composed strategies. It verifies normal effects, seven source-error modes,
linked final images and six scalar removal/original-request-loss refusals
before writing a bounded Windows CLANG64 source-none cost record. Five
alternating warm pairs at one and 64 workloads report `.text`, `.data` plus
`.rdata`, fresh-process time and checked loop time. This fixed fixture is one
D6 Unit6 cost datum, not full provider, startup or complete D6 cost coverage.

The opt-in `pyobf_native_measure_contribution_cost` target compares one authored
grouped automatic owned-CNG fixture with runtime contribution on/off. The off
baseline removes no-op marker calls; its request manifest and source-error
behavior intentionally differ. The on image must keep seven source refusals
before effects; both images must pass actual linked checks, with removed-gate
and forged-report negatives. Five alternating warm pairs at one and 64
workloads record code/data size, fresh-process and checked loop times, exact
input/image hashes, and downstream component-count changes. This fixed
source-none fixture includes a manual pre-entry CNG query in both builds. It
is one additional D6 Unit6 cost datum, not a pure query overhead, complete
bootstrap cost, or D6 closure.

Scalar-removal controls require both full-image refusal and the production data checker to
reject the corresponding strategy independently. Removing literal hiding can also change
transition-layer mask evidence; an earlier transition error cannot supply the data proof.

Hybrid cases add two equal constant returns at distinct normal continuations, a real equality
condition, escaping int/double exceptions, cleanup counters and concurrent invocations. The
fixture explicitly retains closed marker calls with `nomerge` through source O2; this is not a
promise to retain arbitrary optimized source sites. Each strategy/both runs in explicit/automatic
none/O2 modes. Heavy grouped compositions cover clone donors separately from framed synthesis,
so a call-result-only body does not falsely claim a safe clone. Runtime contribution OFF preserves
ordinary data/EH semantics. Production contracts cover 44 width/seed combinations through i128,
12 valid-IR bypass/flow mutations, owner/proof reset and the i129 refusal.

Archive composition has its own contract below. Other provider adapters remain required
follow-through; scalar acceptance cannot stand in for them.

## Structural normalization composition

Whole common-exit, split-blocks and deduplicate-blocks compose with explicit or automatic
source acquisition under their eligibility and source-policy contracts. They can be combined with
explicit grouped acquisition, scalar/equality hiding and all three transition layers.
The existing GNU hybrid scope admits these normalizers; selected regions retain their
component-specific boundary.

Splitting excludes closed contribution/path-fold source descriptors from the instruction
budget while retaining ordinary calls. A fixed source fixture checks the original named cut
after a multiply plus an ordinary call, and independently checks 52 host effects and results.
Compatible return merging and duplicate arithmetic blocks are exercised independently and
combined. Source O2 may remove original redundant work: optional loss earns no protection,
and separately required original losses still refuse usable output.

Deduplication can leave a conditional whose two successors are identical. Whole contribution
flow accepts its exact frozen-condition Select with both planned encoded arms, or the equal
constant form; arbitrary conditions, wrong arms and wrong constants still fail. Production
contracts cover eight seed/form positives and four valid-IR mutations.

Automatic deduplication snapshots and selects original retained-input edges first, normalizes
the function, then materializes gateways using private original-to-retained aliases. Other
automatic profiles retain their earlier ordering. The D1 normalizer grants a private `DedupAlias`
witness after semantic/safety checks; IR metadata cannot grant that permission. Void terminator
identity is transferred before deletion, including the canonical source of lowered switches.

Selected aliases share one physical acquisition only when selection and ordered owned-material
source policies agree, including domains, encoding, readiness and group requirements. Only the
existing immutable owned-context material is admitted; independent observations/providers gain
no permission from this rule. A required incompatible dedup request refuses output. Optional
incompatible candidates retain their separate blocks/queries and report `unsupported` while
ordinary protected execution continues. Both-unselected aliases may normalize without earning
selected-edge coverage. Compatible exact rules on original aliases remain valid; unused rules
still fail.

Reports preserve `original_edges`, `selected_edges` and `bound_edges` as logical counts.
`physical_selected_edges` counts actual automatic acquisition sites and
`coalesced_selected_edges` records the difference. Each original entry retains its `id`/`point`
and names its rooted `canonical`/`canonical_point`; `alias_contract_verified` records compiler
construction proof. Total applied points equal physical automatic sites plus explicit points;
member-query budgets apply to actual source queries. Automatic reports missing these fields
must be regenerated with matching plugin/checker versions. Recipe/private-input schema and SDK
query ABI are unchanged.

Independent fixtures pin six logical/five physical edges for one duplicate branch pair,
eight/seven for an additional duplicate return (which has no outgoing edge), and ten/seven for
three switch-ordinal aliases. They check normal results and 52 ordinary-call effects, compatible
exact policies, physical budget boundaries, partial/zero selection and required/optional failures.
Forged links/counts are rejected structurally; an internally consistent wrong source map is
also rejected against the authored input. The final machine gate still proves scoped query/mask
presence, not per-edge machine-code equivalence from an untrusted report alone.

The existing Windows GNU hybrid EH scope admits common-exit, split and dedup before EH/SSA
preparation and final state assignment. The original personality, landing pads and unwind
routes remain under `ExceptionalOrigins` and `HybridFlowSeal`; this does not admit other EH
models or region normalizers. Required original split cuts survive preceding normalizers,
including typed ordinary-call cut relocation to its frame target store. Already existing
boundaries receive explicit `retained_existing_cuts` credit without empty prefix blocks.

For automatic dedup with framed invokes, the private registered completion chain must finish
before acquisition. `insertion_source` verifies that chain and inserts at its final normal
branch, retaining original invoke identity, logical destination and unwind. The later EH bridge
must still reach the chain entry; source/RAUW/bypass/split mutants remain invalid. Runtime query
ABI, context lifetime and source policy are unchanged.
Distinct registered completion owners cannot themselves merge, even when their empty branches
are semantically identical. The optional normalizer leaves them intact with an unsupported
site; a required merge refuses. A compiler fixture checks independent four-edge/two-unwind
inventory, OFF/optional success and required refusal with a genuine eligible original donor.
Its optional output matches a no-work budget refusal's native code, relocations and unwind
records under the same deferred gateway order. Eager OFF has different placement and is
validated separately, not asserted byte-identical.

Hybrid integration uses actual C++ catch/destructor/escaping/nested/thread behavior, used
duplicate arithmetic and an explicitly authored pre-request return fork. Independent source
counts include named blocks such as `invoke.cont` correctly; labels are not instructions.
Source O2 may remove original work, but separately required losses refuse output.

The opt-in CMake target `pyobf_native_measure_contribution_alias` reuses this actual CNG host
for paired dedup off/on sizes, warm-cache process costs and checked warmed-loop costs. See
the [native build guide](../native/README.md) for the workload, output and measurement limits.

## Archive data composition

Whole and admitted Windows GNU hybrid owners combine `constant-archive` with explicit or
automatic `runtime-contribution`
under the existing typed archive restrictions. The build order remains input requests,
ordinary source optimization, archive plan/package, late runtime/wrapper requests, merged
requests/link, materialization, then final contribution/CFF. The actual archive runtime and
every generated wrapper remain selected for CFF. No new bootstrap ABI or provider is added.

```json
{"schema_version":1,"functions":{"compute":{"components":{
  "runtime-contribution":"required","constant-archive":"required"},
  "contribution":{"selection":"original-edges"}}}}
```

Closed fold/contribution source markers describe the later compiler binding. Archive planning
leaves their arguments literal while collecting actual program data. Encrypting a site ID
would replace that descriptor with a runtime load before its compiler consumer. The existing
source-marker exclusion covers these calls; malformed reserved source ABIs still reject at
their source boundary.

Hybrid planning resolves the selected coverage before validation. Landingpad/resume operands,
exception type-ID intrinsics and declared GNU exception-runtime type-info arguments retain
their ABI/control identity. They are excluded consistently from source requests and data
planning; ordinary storage with a shared EH control use fails closure. Normal and
post-landingpad consumers use the existing wrapper/key/clear/context machinery. Archive
insertion can shift instruction budgets, so split inventory retains legal original manifest
anchors as well as newly required cuts. A missing original anchor is still a loss.

The real mixed-scope fixture covers selected hybrid byte storage, caught/escaping exceptions,
cleanup, nested/concurrent calls and cache warmup before context failure. Replacing only one
owner's actual keys with static values remains runnable but fails that owner's final claim;
a corrupted cold key prevents successful execution. Hybrid strict/optional optimized-away
data has a separate empty-plan control. Final evidence remains scoped presence and behavior,
not arbitrary post-link dataflow authentication.

The integration driver independently freezes prepared acquisition/eight-key-lane counts and
the pre-plan retained-input semantic edges. Final rows must match those inputs as well as the
complete source/wrapper inventory. Required original data loss still rejects; an optional
empty plan cannot earn archive coverage or count source-marker IDs as encrypted data.
Ordinary O2 can fold source representations, so optimized cases separately require nonzero
actual acquisitions while keeping original loss visible.

Actual CNG cases consume bytes, UTF16 storage, integers, negative zero and a NaN payload with
independent host results. Source none/O2, explicit/automatic, ordered grouped sources and a
full scalar/bogus/frame/preparation composition are exercised. After warming actual records,
wrong material, unavailable provider, closed context or removed binding still prevents
successful protected execution. Immutable archive caches do not replace those observations;
they are not independent D7 measurement caches. Cold wrong archive keys fail independently.

Replacing state-bound archive keys with correct static keys preserves normal execution but
must lose the original final-image claim. Tests locate actual writes through the existing
private source/child map and CFF provenance; production still erases archive binding metadata.
The fixture checks that distinctive byte/UTF16/NaN storage and full raw archive keys are absent.
These are scoped compiler/runtime/presence checks, not remote authorization, arbitrary linked
equivalence or protection from extracting a legitimate body, keys, caches and valid context.

## Region composition

Combine `-pyobf-cff-region=owner:region.start:region.out` with a required
`runtime-contribution` override for `owner`. The private input still needs that owner's
unique function ID. The existing region subset requires at least three body blocks, a
conditional decision, branch-only body terminators, no body/exit PHIs or region-defined
cross-block uses, external admission only through the named entry, and a route to the named
exit from every body. Other component compositions remain unsupported in this scope.

Only retained selected input blocks supply markers and original-edge density. Its basis is
`retained-cff-input-region-normal-successor-edges`; `region_entry` and `region_exit` identify
the selection. Outgoing exit edges count, while outside code, setup, the sole exit leaf and
generated gateways do not inflate the denominator. Markers outside the selection remain
ordinary source calls and cannot satisfy its required source policy. Link their no-op
reference implementation after compiling protected IR; defining it inside that IR still
rejects. The same caller-owned lease remains valid through the complete function call.

`RegionScope` tracks original bodies and normalized/generated member gateways. The shared
state/dispatcher, acquisition, gate binding and transition emitter operate on those members.
A normal-flow proof freezes setup initialization, each selected decision, dispatcher/state
storage and the sole exit. Every external admission resets state; internal back edges keep
it live. A separate boundary proof freezes all outside operations, flags, metadata, operands
and PHI predecessors. It admits only the root state allocation and planned redirection of
outside entry predecessors through setup. Successful rows require
`region_flow_contract_verified=true`, also checked before final-image certification.

Selections name the actual retained CFF input. Source O2 may erase a named boundary, form
unsupported PHIs or change the legal shape; those cases reject rather than silently broadening
coverage. A fixture that retains observable branch/loop boundaries passes with source O2;
an optimized-away counterpart must fail. This is a region contract, not a claim that outside
code is protected or every arbitrary source region survives optimization.

## Verification and remaining boundary

```powershell
ctest --test-dir build/native --output-on-failure -R "^pyobf_native_contribution_gates_"
ctest --test-dir build/native --output-on-failure -R "contribution_(edges_|edge_(source|flow)_contract)"
ctest --test-dir build/native --output-on-failure -R "contribution_(hybrid_|edge_(invoke|binding)_contract)"
ctest --test-dir build/native --output-on-failure -R "contribution_(region_|edge_region_contract)"
ctest --test-dir build/native --output-on-failure -R "^pyobf_native_contribution_groups_"
ctest --test-dir build/native --output-on-failure -R "contribution_layer|cff_transition_model_contract"
ctest --test-dir build/native --output-on-failure -R "contribution_initializer"
```

The driver protects47 actual SDK/user definitions from multiple files, executes actual CNG
derivation and compares27 sample inputs through both argument-held and explicitly provided
global lease references with an independent arithmetic reference. Wrong
material, failed provider status carrying dirty output, closed/unbound/missing/foreign context
must prevent completion of that fixture. It also verifies LLVM-valid graph changes, private
input and source/ABI/scope refusals. A runnable forwarding-query image must fail final query
presence certification. Plain source executes its reference semantics but cannot obtain a
final CFF certificate. Source none/O2 and parent IPO are separate test configurations.
Separate stage-replay/raw-query refusals and a complete optional-zero profile guard the
absence of false coverage. Source-only CMake target composition is also tested with MSVC.

Automatic fixtures protect48 actual authored definitions across SDK and user sources,
including loops, PHIs, duplicate switch destinations and default routes. They independently
count source IR successors, check partial budgets, threshold ceilings, reproducible/diverse
seeds, generated padding/splitting exclusions, empty inventories and malformed source/options.
Production C++ contract tests reject11 valid-IR source/lowering mutations and12 post-binding
flow mutations. Final-report consistency mutations reject false original-edge claims.

Hybrid fixtures protect48/49 authored definitions for explicit/automatic modes. They execute
caught and escaping exceptions, exact destructor effects, nested calls, four concurrent
readers and six failed-source modes. Query/dataflow mutants and runnable final-query
replacement target the hybrid owner itself. Separate contracts reject6 invoke source/bridge/
unwind mutations and14 binding/route mutations, including internally consistent retained
metadata changes and a gate/flow mismatch that leaves the gate proof independently valid.
Five of those cases change the contribution salt or one public source identity together with
the corresponding retained graph/metadata; the private frozen reference must reject each.
Invalid target/personality, landingpad-header points and insufficient density budget reject.

Region fixtures protect48/49 authored definitions in explicit/automatic modes. An independent
input walk expects five regional blocks/seven normal edges; three inside points and two
outside points distinguish protected scope from ordinary reference calls. Execution checks
27 inputs, repeated external admission, internal loop effects, branch-specific effects and
outside counters under source none/O2. Failed-source modes and graph/query replacement
negatives target the region owner. Removing only inside points, bypassing the entry, missing
the query budget or erasing named O2 boundaries rejects; a budget of exactly three proves
outside points do not inflate the query count. Optional-zero and false report scope/strategy/
proof cases remain explicit. A production contract checks four seeds, entry/non-entry regions
and 10 valid-IR boundary/flow mutants. Detached snapshots must not add CFG predecessors or
canonical source-spill users.

Grouped-source fixtures reuse the actual multi-file CNG host and cover whole/hybrid/region,
explicit/automatic selection and source none/O2. The input rules independently expect one,
two or three ordered sources at different points. Each member can fail separately; a query
budget that fits site count but excludes the extra members must reject. Malformed catalogs/
rules, false reports, source/dataflow mutants, optional-zero and runnable final-query
replacement remain checked. Nine additional production group mutations include omitted or
duplicated values, inconsistent leases/current/ordinals, interleaved state writes and
internally consistent changed domain/order or replacement calls. The pure mix generator
also executes 408 independently generated Python vectors against emitted none/O2 and the C++
model. These fixtures do not add new provider or independent freshness claims.

This fixture deliberately supplies known test material from its host. It proves the selected
gate path, not main-payload confidentiality, machine authorization, exhaustive wrong-state
behavior or the final dumped-body requirement. A wrong state may reach another tree leaf;
bounded fixture failure is not a guarantee that every possible wrong input crashes. Live
querying/dumping remains outside this static obfuscation boundary.

## File responsibilities

| Files | Responsibility |
| --- | --- |
| `llvm/cff/contribution_gate.hpp` | Component hooks and frozen gate-plan interface |
| `include/pyobfuscator_native/contribution_marker.hpp`, `src/contribution/marker.cpp` | Typed C++ point declaration and separate ordinary-source reference |
| `src/contribution/gate.cpp` | Scalar generated-call ABI over the strict owned client |
| `llvm/cff/contribution_private.{hpp,cpp}` | Private owned-context adapter parsing and canonical build reference |
| `llvm/cff/contribution_source_config.cpp`, `contribution_sources.{hpp,cpp}` | Schema2 catalog/default/exact point rules, existing capability resolver, actual query budget and independent grouped reference |
| `llvm/cff/contribution_mix.hpp`, `contribution_mix_plan.cpp`, `contribution_mix_emit.cpp`, `contribution_mix_proof.cpp` | Bounded ordered framing plan, pure32-bit emission and iterative non-mutating exact graph proof |
| `llvm/cff/contribution_groups.hpp`, `contribution_group_acquire.cpp`, `contribution_group_bind.cpp`, `contribution_group_proof.cpp`, `contribution_group_report.cpp` | Separate multi-query A4 acquisition, A5 correction, retained dataflow proof and public subset/query report |
| `llvm/cff/contribution_artifacts.cpp` | Input-stage guards against replayed bindings and reserved generated queries |
| `llvm/cff/contribution_marker.cpp`, `contribution_acquire.cpp` | Closed-marker discovery, then separate source-policy resolution and actual query acquisition |
| `llvm/cff/contribution_normalize.cpp` | Coordinate explicit/automatic A4 routing preparation |
| `llvm/cff/contribution_options.{hpp,cpp}` | Typed selection, count/density/budget overrides and strict parsing |
| `llvm/cff/contribution_edges.hpp`, `contribution_edge_source.cpp` | Original-edge plan and canonical source ownership admission |
| `llvm/cff/contribution_edge_inventory.cpp` | Retained input inventory, seeded selection, budget/identity refusal and density report |
| `llvm/cff/contribution_edge_instrument.cpp` | Per-successor gateway creation and parallel PHI repair |
| `llvm/cff/contribution_edge_lower.cpp` | Frozen source routes, actual switch-lowering trace and source/storage verification |
| `llvm/cff/contribution_edge_invoke.cpp` | Admitted invoke/EH gateway trace and frozen normal/unwind source verification |
| `llvm/cff/contribution_frame_trace.cpp` | Explicit frame replacement and registered completion-corridor splitting without RAUW authority |
| `llvm/cff/bogus_control_plan.hpp`, `bogus_controls.hpp`, `bogus_control_{plan,descriptor,proof}.cpp` | Frozen construction, typed retained shape and exact predicate/read/decoy-write proof, separate from normal flow and source authority |
| `llvm/tests/bogus_control_{fixture,mutations}.hpp`, `tests/contribution/bogus_gate_cases.py` | Actual control/normal-flow and private-plan mutations, reserved inputs, runnable final guard/work erasures and raw donor scope |
| `llvm/cff/contribution_edge_flow.{hpp,cpp}` | Frozen post-prepare normal routes, initial state, dispatcher and state-storage verification |
| `llvm/cff/region_scope.{hpp,cpp}`, `region_pipeline.cpp` | Shared selected-member inventory and modular region orchestration using existing component/state/gate hooks |
| `llvm/cff/region_boundary.{hpp,cpp}` | Detached outside-operation snapshots and exact admission/outside preservation proof |
| `llvm/cff/transition_rewrite.{hpp,cpp}` | Shared normal-branch A5 transition emission for whole, hybrid and region scopes |
| `llvm/cff/transition_binding.hpp`, `contribution_route_seal.cpp` | Compiler-only verified binding interface and exact frozen unconditional normal-target adapter |
| `llvm/cff/hybrid_eh_edges.cpp`, `hybrid_eh_prepare.cpp` | Pure EH boundary preparation shared with contracts, and coverage integration adapter |
| `llvm/cff/switch_lower_edges.{hpp,cpp}`, `switch_lower.cpp` | Pure switch lowering with optional origin/edge tracking, and coverage adapter |
| `llvm/cff/component_seed.cpp` | Public deterministic component/edge diversity shared by production and contracts |
| `llvm/cff/contribution_bind.cpp` | Late sealed transition constants and actual observed-word masking |
| `llvm/cff/contribution_proof.cpp` | Retained query/live-state/wrapping-update graph validation |
| `llvm/cff/contribution_seal.cpp` | Frozen source/body-state/target plan validation |
| `demo/cff_contribution_evidence.py`, `demo/cff_grouped_owned_flow.py` | Final query/mask evidence and bounded Windows x64 grouped owned return-to-state route for whole relative-tree schema2 |
| `tests/contribution/{gate_fixture.cpp,gate_host.cpp,check_gates.py,gate_mutations.py,gate_profiles.py}` | Actual source/runtime execution, independent results, bounded negative cases and optional-zero reporting |
| `tests/contribution/scalar_gate_cases.py`, `contribution/DataChecks.cmake` | Scalar/source recipe selection, actual nonzero coverage, runnable individual erasures and required/optional optimized-away cases; separate test registration |
| `llvm/cff/transition_literal_model.cpp`, `hybrid_scalar_bindings.{hpp,cpp}`, `llvm/tests/hybrid_scalar_{fixture,mutations}.hpp`, `tests/contribution/hybrid_scalar_fixture.ll` | Private typed literal-return proof, role separation and terminal/flow mutants; actual equal-return EH execution fixture |
| `tests/contribution/archive_gate_pipeline.py`, `archive_gate_cases.py` | Existing archive stages, independent prepared counts, actual key/erasure/empty-source controls and private-map consumers |
| `tests/contribution/archive_fixture.cpp`, `archive_host_support.hpp` | Typed source-gated data and independent host results; warmed-record context failure uses the existing host |
| `tests/contribution/check_gate_reference.py`, `tests/contribution/CMakeLists.txt` | Source gate/provider/reference target closure, strict scalar sanitization, generated-helper failure and ordinary marker behavior |
| `tests/contribution/edge_fixture.cpp`, `edge_policies.py` | Automatic switch execution, independent denominator, thresholds/source/options and report negatives |
| `llvm/tests/contribution_edge_{source,flow}_{fixture.hpp,contract.cpp}` | Production source/route proof mutation contracts, separate from executable acquisition tests |
| `tests/contribution/{hybrid_fixture.cpp,hybrid_host_support.hpp,hybrid_gate_cases.py}` | Actual exception/nesting/concurrency execution and hybrid model/point/budget negatives |
| `llvm/tests/contribution_invoke_contract.cpp`, `contribution_binding_{fixture.hpp,contract.cpp}` | Real EH preparation trace and gate/binder/hybrid-flow composition contracts |
| `llvm/tests/contribution_frame_mutations.hpp`, `tests/contribution/framed_gate_cases.py` | Original-invoke result regression, completion/registration mutants and runnable final frame/route erasure controls |
| `tests/contribution/{region_fixture.ll,region_host_support.hpp,region_gate_cases.py}` | Retained branch-only region, actual effects/reentry, scoped inventory and source/report/budget refusals |
| `tests/contribution/group_gate_cases.py`, `llvm/tests/contribution_group_mutations.hpp`, `demo/cff_contribution_groups.py` | Independent configured subsets, member failures, parser/budget/refusal controls, private-plan mutations and final report consistency |
| `llvm/tests/contribution_region_{fixture.hpp,contract.cpp}` | Production outside/flow proof mutants and non-mutating snapshot/source ownership checks |
| `llvm/cff/transition_registry.{hpp,cpp}`, `transition_model.{hpp,cpp}`, `transition_model_{identity,match}.cpp` | Actual emitter capability registration, isolated reference, symbolic entry identity and exact non-mutating matcher |
| `llvm/cff/transition_layers.{hpp,cpp}`, `transition_layer_{selection,descriptor}.cpp` | Frozen per-body plans, retained typed descriptors and verified normal-core/read capabilities |
| `llvm/tests/transition_model_contract.cpp`, `transition_layer_mutations.hpp`, `llvm/cmake/TransitionModelFixture.cmake` | Literal/symbolic model, valid-IR graph, coherent private-plan and ordinary-flow contracts |
| `tests/contribution/layer_cases.py` | Actual per-layer removal, runnable negative images and false composition-proof report refusals |
| `llvm/cff/source_marker.hpp` | Shared closed source-marker exclusion for actual reference/frame candidate discovery |
| `llvm/cff/state_binding_proof.{hpp,cpp}`, `llvm/tests/state_binding_mutations.hpp` | Shared frozen whole/hybrid data-state/root boundary and independent flow mutation contracts |
| `tests/contribution/{preparation_fixture.cpp,preparation_cases.py}` | Conditional real user/import/local fixture, exact frame inventory and runnable per-initializer removal controls |
