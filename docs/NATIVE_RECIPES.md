# Native CFF recipes and site reports

The LLVM plugin accepts `-pyobf-cff-config=recipe.json`. Configuration schema 1 composes the
currently implemented components; it does not enable planned machine or code-hash
providers. Unknown fields/components and the incomplete `parity` recipe are rejected.

```json
{
  "schema_version": 1,
  "domain": "inner",
  "defaults": {"recipe": "baseline"},
  "markers": {
    "pyobf.native.sdk": {"recipe": "baseline"}
  },
  "functions": {
    "critical_function": {
      "components": {
        "integer-literals": "required",
        "internal-calls": "optional",
        "decoy-transitions": "optional"
      }
    }
  }
}
```

Exact function overrides select those functions. Marker overrides apply to actually selected
source marker groups (`pyobf.native.cff`, `pyobf.native.sdk`, `pyobf.native.bootstrap` and
`pyobf.native.bootstrap.eh`); unmatched marker overrides
fail. Resolution order is legacy CLI recipe, target defaults, marker override, exact function
override. A `recipe` field resets inherited component modes before that override's components
are applied. Existing exact-name, source-marker, explicit region and request-manifest selection
remain supported; region scopes currently accept `cfg` and `runtime-contribution` under the
[branch-only region contract](NATIVE_CONTRIBUTION_GATES.md#region-composition). Other components
still reject in region scope instead of widening it to the whole function.
`runtime-contribution` also accepts [ordered per-site owned-material subsets](NATIVE_CONTRIBUTION_GATES.md#per-site-source-subsets)
through private input schema2; the public recipe schema and SDK ABI remain unchanged.
Whole and admitted hybrid contributions accept the existing reference/import/local non-CFG
initializer preparations. Their closed marker,
frozen data-state/root and source-flow boundaries are described in
[initializer composition](NATIVE_CONTRIBUTION_GATES.md#initializer-preparation-composition).
Whole and supported hybrid normal bodies accept the three registered
[transition layers](NATIVE_CONTRIBUTION_GATES.md#transition-layer-composition) with explicit
or automatic contribution gates. Internal/external frames and structural call steps also
compose under their [frozen source/corridor and ABI contract](NATIVE_CONTRIBUTION_GATES.md#framed-call-and-preparation-composition).
Bogus clone/synthesis controls also compose with whole/admitted-hybrid contributions under
their [private predicate/write contract](NATIVE_CONTRIBUTION_GATES.md#bogus-control-composition).
Whole and admitted hybrid contributions also compose with integer/equality rewrites under the
[scalar data contract](NATIVE_CONTRIBUTION_GATES.md#scalar-data-composition).
Typed archives follow the existing source-opt/plan/package/materialization order under the
[archive data contract](NATIVE_CONTRIBUTION_GATES.md#archive-data-composition), preserving
closed source descriptors and original acquisition accounting.
Other preparation/provider combinations retain their
individual admission rules and remaining parity requirements.

| Recipe/component | Current meaning |
| --- | --- |
| `baseline`, alias `relative-tree` | Required legal function/region CFG transformation |
| `deep`, alias `relative-tree-deep` | CFG plus optional supported literals, internal calls and alternate transitions; requires an actual eligible enabled literal or internal call |
| `cfg` | Encoded relative transitions, nonuniform state IDs, inequality comparison tree and body layout |
| `integer-literals` | State-dependent bit-exact decoding of eligible scalar i1-i128 operands; wider/vector/pointer operands are outside this subset |
| `comparison-constants` | Opt-in scalar i2-i128 eq/ne with exactly one constant, using a build-baked target and a state-keyed runtime bijection |
| `constant-archive` | Opt-in typed AES-GCM records with verified wrappers and state-keyed acquisition frames; requires the [archive compiler stages or demo CMake pipeline](NATIVE_ARCHIVE.md), not just a late CFF option |
| `internal-calls` | Eligible nonrecursive direct internal calls through volatile target slots; does not change their ABI |
| `reference-routes` | Opt-in per-invocation target table, public-seeded slots and actual-state-derived indices for direct defined function references; preserves call ABI and true address identity |
| `call-frames` | Opt-in per-original-site typed stack frame and internal invoker, generated and selected for CFF before definition sealing; seeded field order, exact inner ABI and explicit ownership |
| `external-calls` | Opt-in exact nonvariadic strong external-declaration calls through private typed frame adapters; same ABI/ownership proof with separate requests/seeds/helper accounting, no new loader/resolver |
| `import-routes` | Opt-in scalar strong-declaration address/call targets through separate state-indexed tables; exact imported graph/slot/dispatcher proof and original frame/common-exit use accounting |
| `call-preparation` | Opt-in caller/invoker field I/O, dispatch and result steps in distinct states; bounded state-dependent field addresses; requires source `call-frames` or `external-calls` |
| `indexed-locals` | Opt-in original typed local objects behind invocation-owned pointer slots; actual-state address lookup preserves aliases, escaped identities, alignment and lifetime |
| `path-fold` | Opt-in private init/step markers on caller-owned eight-word storage; actual CFF state decodes each fixed event, with frozen source binding and serialized IR dataflow checks; demo startup consumes private per-build events for masked-key reconstruction |
| `decoy-transitions` | Alternate encoded transition for a wrong-state range; no bogus code bodies or promise that wrong states are safe |
| `split-blocks` | Opt-in whole/GNU-hybrid instruction-budget splitting before state assignment; preserves original cuts and instruction order, rejects unsupported required boundaries or exhausted block budgets |
| `deduplicate-blocks` | Conservative structural merging before state keys, with successor-PHI checks and explicit original-to-retained site links |
| `common-exit` | Typed common result/exit for compatible returns, with explicit literal relocation and unchanged function ABI |
| `opaque-choices` | Bounded finite-width predicate families choose the valid encoded transition; no equality dispatch or new authorization claim |
| `reachable-junk` | Bounded arithmetic on live state contributes to the actual transition, with zero correction at the valid state |
| `bogus-clones` | Opaque inbound edges to fresh safe wrapping-i32 donor clones; source site identities are not copied |
| `bogus-synthesis` | Opaque inbound edges to independently generated arithmetic bodies; may fill unavailable optional clone allocations |

Component modes are `off`, `optional` and `required`. Optional ineligible sites remain visible.
An explicitly required component needs eligible sites, rejects unsupported or lost requested
sites, and must apply to all retained eligible instances. The compatibility recipes preserve
their function-level requirement without silently turning every pre-optimization CFG site into
a new strict obligation. Existing strict decision-flow selection remains available.

The public seed is domain-separated by function and component. CFG, literal and transition
hooks consume their respective seeds. The current internal-call route reserves its seed input
but does not yet randomize its slot layout. A seed provides build diversity, not secrecy.

Optional override `budgets` fields include `min_blocks` (default 3), `max_body_blocks` (4096),
`max_block_instructions` (16) and `max_path_fold_sites` (256). They inherit independently of recipe mode resets. The
minimum must be at least three and cannot exceed the maximum. `min_blocks` pads small
whole functions with explicitly counted shape blocks; it does not create real decisions.
Regions must already satisfy their selected body budget and cannot enable `split-blocks`.
The instruction budget counts non-PHI, non-alloca, non-debug, non-terminator instructions.
Closed path-fold/contribution source descriptors are excluded because compiler preparation
replaces or isolates them; ordinary calls still consume the budget. Whole source acquisition
composition and automatic-deduplication limits are in the
[structural contract](NATIVE_CONTRIBUTION_GATES.md#structural-normalization-composition).
For automatic deduplication, source edge selection precedes generic normalization and gateway
materialization follows it. Compatible original aliases share physical acquisition while the
original logical denominator remains fixed. Incompatible required sites fail; optional sites
stay unmerged with explicit unsupported reasons.
The existing Windows GNU hybrid EH scope admits these three normalizers before EH gateway
preparation and state assignment. Original split cuts remain required across source/frame
normalization; replaced ordinary-call cuts relocate to their frame target store. A cut already
at an existing block entry is counted in `retained_existing_cuts`, without adding an empty
prefix or incrementing `real_splits`. New body growth still respects `max_body_blocks`.
Splitting cannot divide one instruction, a musttail call/return span, or an unsized value's
required local use. Optional unsupported spans are reported rather than silently credited;
required unsupported spans fail. Volatile/atomic instructions and calls keep their relative
order, and ordinary cross-block SSA is lowered after splitting. The body budget covers
normalized bodies, including switch lowering, before dispatcher generation; it is not a cap
on final dispatch-tree instructions or whole-image size.

For example, add `"split-blocks": "required"` under a function's components and
`"budgets": {"max_block_instructions": 8, "max_body_blocks": 256}` to the same override.
The optional `pyobf_native_demo_measure_cff_split` target compares CFG-only and CFG-plus-split
builds from the same IR, reporting image size, DLL load/first call and hot-call costs. Its
bounded differential fixture includes volatile/atomic work, switch/loop PHIs and musttail.
The independent `deduplicate-blocks` and `common-exit` components are also opt-in. All three
normalizers are engineering support for later protected routing/gates; their presence alone
is not a new secrecy boundary or a strength multiplier.

### Nonlocal control admission

Whole-function and explicit-region CFF share a selected-function control gate. A
`returns_twice` function or call-site attribute, including the resolved aliased callee's
attribute, rejects transformation. Reserved `llvm.eh.sjlj.*` and `llvm.coro.*` calls are also
unsupported. An unsafe call outside a selected region still rejects its owning function:
the dispatcher has no continuation-state restoration contract for a later nonlocal return.
Optional import/frame components do not bypass this safety gate.

The regression runs a legal C++ `switch(setjmp(...))` baseline, then requires rejection with
an unsupported report and no transformed output. It separately checks target/call-site/owner
attributes, aliases, SJLJ, coroutines and region ownership, plus ordinary symbol-name and
unselected-function positives. This recognizes explicit IR semantics, not arbitrary unannotated
indirect targets or transitive behavior behind opaque calls; ordinary names are not blacklisted.
This admission gate does not implement setjmp/longjmp resumption or coroutine lowering.

### Explicit hybrid exception scope

Set `"coverage": "hybrid-eh"` on a function override to protect its normal CFG while
preserving authored exception boundaries. The default `"whole"` scope still rejects EH;
explicit named regions conflict with hybrid scope. Coverage inherits independently of recipe
component resets and can be overridden back to `"whole"`. The profile supports `cfg`,
`call-frames`, `external-calls`, `call-preparation`, `reference-routes`, `import-routes`, `indexed-locals`, `path-fold`,
`runtime-contribution`, the three transition layers, both bogus controls, `integer-literals`,
`comparison-constants`, `constant-archive`, `common-exit`, `deduplicate-blocks` and `split-blocks`,
with x64 Windows GNU IR and `__gxx_personality_seh0` landingpad-based C++ exceptions.
Other target/personality models, funclet/token operations, operand bundles, nonlocal controls
and other enabled components are rejected. The separate capability registry reports
`supports_hybrid_eh` for each component; adding a registry entry requires target/ABI/exception
evidence, not just a successful ordinary-call test.

Normal-return gates and landingpad continuations are prepared before SSA lowering and state
assignment. The original invoke unwind targets, personality and landingpad clauses stay in
the original function. Each invocation owns an encoded unwind-correction slot armed before
its invoke. Both the normal gateway and exceptional pad entry apply source-state-relative
corrections to reach ordinary continuation bodies. No exception object becomes a state ID,
and no ordinary dispatcher edge enters an EH pad. Typed invoke/pad values retain typed spills.

Framed source invokes retain their unwind destination and call the original typed inner ABI
through a generated helper. A separate normal-result block updates successor PHIs and reads
the result only on helper completion. Structural preparation isolates terminal invoke events
without splitting after a terminator. A pre-state dominance gate rejects early, exceptional
or shared result acquisition. An original exception inventory is captured before normalizers;
an explicit replacement transfers invoke identity while preserving its source unwind target.
Cross-stage checks retain personality, landingpad identity/clauses/cleanup and unwind ownership.
These are compiler construction checks, not a runtime authenticity boundary.

Framed call profiles retain their original event meaning. Two invoke weights stay on the
outer normal/unwind edges; a single call-count weight is copied to both one-to-one call events.
Target VP metadata stays on the actual typed inner target call, not the helper invocation.
The optional `expected` marker and integer widths/values are retained. This follows
[LLVM's call/invoke weight rules](https://llvm.org/docs/BranchWeightMetadata.html#invokeinst)
and [value-profile format](https://llvm.org/docs/LangRef.html#vp).
A source snapshot is captured before helper generation, bound to each original owning call,
and verified after all selected functions/helpers finish CFF, before stripping private frame
artifacts. It checks unique event ownership and frozen profile contents, including in-place
changes to a shared metadata node. Twenty-four valid-IR matrices and eighteen mutations cover
ordinary/invoke and internal/external forms, single/two weights, `expected`, absent profiles
and 64-bit VP values. The executable/PE suite covers eight source-O2/frame/preparation/route
combinations. Source O2 runs before this profile contract: its own profile changes are not
credited to CFF preservation. This adds no runtime verification or profile confidentiality.

Before binding, an immutable flow plan captures exact body states, original normal choices,
invoke/continuation ownership and terminal operands. After rewriting it checks the complete
wrapping-i32 decode graph against those states, invocation-owned correction stores and live
pad reads, closed storage use and every comparison-tree partition/leaf. Gap pivots may vary;
equality dispatch, valid-state pivots, extra/shared/cyclic nodes, altered conditions and
sample-only or canceled state dependencies fail. Data/preparation state labels must equal
their planned body state, even if another integer would reach the same broad leaf. A valid-IR
contract exercises 29 mutations against production binding/codec expressions, plus multiple
seeds, constant conditions, alternate gap pivots and physical body order. No universal
wrong-state crash or mismatch is inferred from this construction proof.

Scalar equality changes its operands in place, preserving the frozen condition object and
clearing same-sign assumptions. Eligible constant returns have a separate private typed model
bound to their original instruction/body/value, exact state root/label and literal seed. Only
that verified operand may differ from the frozen terminal snapshot; invoke/resume and all other
operands remain exact. The adapter clears cached permission on failure and cannot substitute
predicate/identity proofs or a metadata claim for the literal model. Its production contract
and actual source/EH cases are described in the
[scalar composition contract](NATIVE_CONTRIBUTION_GATES.md#scalar-data-composition).

Source function/import uses moved into frame target/argument stores keep original aliases.
Reference/import routes also admit direct eligible invokes without framing, with unchanged
callee ABI and exception destinations. Existing table/state/slot and helper/storage checks
remain enabled. Actual C++ tests exercise internal/external/mixed frames, preparation and
routes, recursive/rethrow/cleanup, sret and small aggregate ABI, shared-pad/invoke-result PHIs,
and actual default-exceptions Windows memory operations across four threads.

Reports use `hybrid-eh-decision-flow` or `hybrid-eh-straight-line`, exclude invoke exceptional
forks from original normal decisions, and list preserved exceptional edges/pads/resumes.
`ir_boundary_contract_verified` checks retained IR boundary identities/clauses;
`ir_flow_graph_verified` records the immutable final-IR flow checks described above. The linked
gate sets `final_normal_dispatch_presence_verified` for scoped dispatcher presence; it leaves
legacy `decision_flow_verified` false and does not claim whole-function exception protection
or individual machine-edge equivalence. Strict decision-flow mode rejects an invoke-only
normal path. Real C++ differential tests cover normal/catch/destructor/rethrow/recursive paths;
the default-exceptions backend has separate cfg, framed and imported/prepared profiles.
Detector, loader, kernel and other-platform execution claims are unchanged.

### Hybrid exception costs

The hybrid regression also executes two ordinary switches around throwing invokes, with
duplicate destinations, default paths, normal-result/shared-pad PHIs and exact cleanup effects.
Across three seeds, CFG and required external-frame/preparation/import configurations preserve
all 63 flag/input cases. Reports retain exactly two original normal decisions and two preserved
exceptional edges; generated switch comparisons and EH forks do not inflate that count.

Run `cmake --build <native-build> --target pyobf_native_demo_measure_cff_hybrid -j 1`
separately from other builds/tests. The opt-in host benchmark uses one O1/no-inline C++ frontend,
then either no additional optimization or ordinary source O2 before late CFF/O0/no-LTO codegen.
It pairs plain code with CFG-only, internal frames and the five-component frame/external-call/
preparation/reference/import composition at seed 17. Integer-only, equality-only and combined
additions pair against CFG; the same additions on the five-component composition pair against
that composition. The JSON records each pairing. Source-O2 scalar requirements are optional
for lost sites but independently require nonzero application; other required components and
linked partial-scope gates must pass before timing. This does not broaden the admitted EH model or permit arbitrary
post-CFF optimization.

`payload.cff.hybrid.measurements.json` records source/IR/config/request/plugin/harness/image/
report digests, single-observation build costs, text/file sizes and raw timing samples. Each
mode separately checks normal return, locally caught throws or externally rethrown ints, plus
guard effects at every call. Four altered fixture DLLs must be rejected for changed normal
results, cleanup effects, thrown values and swallowed rethrows. The frontend O1 prerequisite
removes unreachable frontend cleanup blocks; it is not an unoptimized C++ baseline.

Startup samples cover 20 warm repeated load/lookup/first-checked-call/unload pairs, not cold
process startup. Hot samples alternate pair order, use 64 warmup calls per image and retain
seven samples of 500,000 normal or 2,000 throwing calls. Timings include the harness's own checks
and catch path. Medians/min/max and raw values describe this small Windows x64 CLANG64 workload;
loader/scheduling noise and C++ exception costs prevent a general speed or protection-strength
bound. Frontend, request retention, source optimization, CFF and codegen/link timings are
separate; plugin/harness builds and outer packaging are outside their comparison scope.
One isolated run observed plain/CFG/frame/composed `.text` sizes of 5206/6134/6966/17798 bytes
in both source-optimization profiles. With additional O2, paired normal calls were 15.66 ns for
frames versus 4.46 ns plain, and 105.28 ns for composition versus 4.33 ns plain. Composed local
catch/rethrow calls were 1.820/4.797 us versus their paired 1.546/4.375 us plain samples.
Composed transform plus codegen/link was 0.3405 seconds, excluding request/ordinary-opt costs
recorded separately. Different paired baselines and the retained raw spread are measurement
noise, not evidence of an optimization or general speed ranking.

The later scalar extension measured the following additional-source-O2 pairs from the same
frontend/seed. Source-none retained the same `.text` sizes; the JSON keeps its separate samples.

| Addition | Paired baseline | Baseline/protected `.text` bytes | Baseline/protected normal hot ns |
| --- | --- | --- | --- |
| Integer literals | CFG | 6134 / 6358 | 7.832 / 9.564 |
| Equality constants | CFG | 6134 / 6198 | 7.823 / 9.521 |
| Both | CFG | 6134 / 6758 | 7.494 / 8.598 |
| Both on composition | Five-component composition | 17798 / 18406 | 106.279 / 106.886 |

All 16 images, 42 normal/catch/rethrow pairs and four behavior mutations passed. This
measures the existing C++ EH workload; production width/constant-return proof contracts and
actual source-gated execution are separate evidence. D6 source-integrated costs remain pending.

### Deduplication, exits and site handoff

Structural order is common exit, deduplication, then splitting, all before final state IDs or
state-dependent data encodings. Dedup compares opcodes, types, flags, semantic metadata and
operands using a local instruction correspondence. It does not compare printed block text.
Matching ordinary nonvolatile loads/stores may be retained once at the same dynamic path
position; the pass does not hoist them or remove repeated operations on one path. Entry,
address-taken, PHI/EH, alloca, call, atomic/volatile, freeze, vector-result and explicit
undef/poison-sensitive donors are excluded. Successor PHIs must agree under the correspondence.
Their donor entries are removed before incoming edges and external uses are redirected.
Ambiguous duplicated provenance is unsupported rather than guessed.

`max_dedup_comparisons` is a separate inherited budget (default 65536, configurable from 1
through 1048576). Exhaustion explicitly records unknown remaining eligibility; required
dedup requests fail. Final body budgets are checked after normalizers, so shrinking a scope
can meet its configured limit while a growing normalization cannot silently exceed it.

Common-exit preserves return-value evaluation and ABI. Compatible void returns share an exit
without result storage. Fixed-size non-vector results use an entry result slot; original
return uses move to stores before branches, with one typed load/return at the common exit.
Musttail paths, unsupported result types and naked functions are not normalized. An optional
request can leave explicitly unsupported paths unchanged; a required request rejects them.
At least two compatible returns are needed. LLVM's [poison propagation rules](https://llvm.org/docs/LangRef.html#poison-values)
apply to stored values; the pass does not add `freeze` or assume an undefined value is clean.

Coverage distinguishes `coalesced` and `relocated` original sites from actual `applied`
rewrites. An original literal may point to a generated store, then to a retained store after
deduplication. A required chain must end at an actual applied site of the same component,
with all retained instances covered. Missing, cyclic, cross-component or unapplied targets
fail. These links do not inflate the number of physical decoders/call routes. Private maps
follow the chain to its final transformed consumption location. Reapplying normalization/CFF
to a function already marked state-bound is rejected.

`check_cff_normalization.py` checks loop/merge/PHI behavior, void/volatile effects, float
signed zero, fixed aggregates, mixed calls and combined normalization with required literals.
It also corrupts the relocated decoder's state read and verifies wrong output, and rejects
unsafe donors, differing flags/PHIs, musttail normalization, budget exhaustion and region
widening. The optional `pyobf_native_demo_measure_cff_normalization` target pairs dedup,
common-exit and combined recipes with matching data/call-protected baselines. Final native
inspection still proves overall CFG shape and component presence where declared, rather
than a universal proof of individual normalized sites.

### Opaque choices, bogus bodies and reachable work

Normalized snapshots retain explicit source/frame routing roles. Bogus clone/synthesis
placement excludes these indivisible boundaries while keeping normal/shape candidates;
an unfulfillable original requirement is reported instead of silently skipped. Whole and
admitted hybrid contribution composition now freezes actual guard/result/write identities
and validates the exact predicate, decoder destinations and decoy write. The isolated
entry-state true model uses the existing evaluator and exact two-way graph matcher, including
the same scalar literal emitter when constants are hidden. Constants, merged observations,
foreign roots and changed/poisoned operations cannot substitute for actual volatile reads.
Only complete successful control proof grants its exact reads and decoy result store; other
root users/writers remain subject to normal-flow proof. See the contribution guide above.

These four components are independently opt-in and support the verified whole/hybrid normal
body subsets. Clone donors still require self-contained wrapping i32 argument arithmetic.
Compatibility `deep` recipes
keep their previous defaults. The normalizers run first. Padding, SSA/switch lowering and
entry separation establish stable anchors. A4 `prepare` hooks select bounded sites and build
fake CFG structure, actual opaque predicates and owned result stores. Final state assignment
then precedes A5 `bind` and `transition` hooks; ordinary scalar binding does not require
replacing a frozen branch condition.
Preparation rejects unclassified new blocks or new helper definitions. After structural
preparation, ordinary cross-block SSA is lowered again. Late hooks remain under the full
block/terminator/successor seal and cannot secretly create more CFG structure.

| Additional budget | Default | Meaning |
| --- | --- | --- |
| `max_opaque_sites` | 4 | Maximum selected opaque transition sites |
| `max_junk_sites` | 4 | Maximum selected reachable-work transition sites |
| `junk_rounds` | 2 | Per-site live-state mixing rounds, from 1 through 8 |
| `max_bogus_blocks` | 4 | Shared maximum of actual cloned plus synthesized decoy bodies |
| `max_clone_instructions` | 6 | Per-clone donor instruction cap, from 1 through 64 |
| `clone_percent` | 50 | Nominal clone allocation when both bogus providers are enabled, from 0 through 100 |
| `synthesis_rounds` | 2 | Per-synthesized-body arithmetic rounds, from 1 through 8 |

Counts are upper bounds, not promises of exact padding or a fixed final-image size. Clone
quota rounds upward; synthesis uses the remaining actual shared allocation. A selected
required provider with zero quota fails. Optional unavailable clones may fall back to enabled
synthesis, but the report credits synthesis only and records the fallback. A decoy also needs
a continuation block; `max_body_blocks` covers all prepared bodies, including that routing
overhead. Original eligible requests take priority over generated anchors; exhaustion cannot
silently truncate a required request.

Opaque expressions use correlated volatile observations of the frame's initialized private
state and unsigned wrapping identities valid for all u32 values. They are public algebraic
obstacles; they do not prove a machine is authorized. Python's unbounded cube/modulo identities
are not ported to overflowing native integers. Reachable work contributes its result to a real
encoded transition rather than leave dead locals that codegen discards. Its correction is zero
at the valid state. Wrong-state behavior can be a wrong result, loop or process failure; there
is no universal safe-decoy/crash guarantee and no supported kernel profile for these features.

Clone donors admit only self-contained i32 add/subtract/multiply/bitwise chains whose inputs
are constants, arguments or earlier admitted operations. Memory/calls, invalid values,
division and shifts are not copied. Fresh initialized state-derived inputs replace arguments;
dependency order is preserved and poison-generating flags and source site IDs are not copied.
Synthesis has its own builder and needs no donor. Fake arithmetic feeds the decoy's state
effect so it remains executable code. Its public seeded mix coefficients are intentionally
excluded from subsequent scalar hiding as bounded retention evidence; original user/donor
literals still enter that transformation. Public coefficients are not key material.

`body_roles`, `transition_roles` and per-component `applied_roles` distinguish real, shape,
routing, decoy and reserved reachable-junk roles. Guard obligations relocate to new routing
sites; fake guards/bodies do not inflate original decisions or oracle gates. Normalized real
graph totals are captured before additions. Candidate counts name the frozen non-entry,
non-decoy branch scope; preparation metrics show quotas, donor size, actual allocations and
fallback. Donor IDs appear only in the opt-in private map.

The expression test executes actual emitted LLVM arithmetic against boundary and pseudorandom
u32 vectors and checks a corrupted observation. Transition/bogus fixtures cover branch/switch/
loop, volatile/atomic work, recursion, callbacks, multiple seeds, unsafe donors, quotas and
feature erasure. The scoped x86 COFF inspector checks variable predicate products and expected
public mix coefficients, including their multiplicity, before accepting component presence.
Registered opaque/junk/decoy wrappers also require the combined compiler layer proof. Decoy
uses a distinct dense coefficient on its dynamic wrong-state arm, preventing an opaque
conditional selection from supplying decoy's missing machine evidence.
This is not universal per-site machine-code equivalence; `individual_sites_verified` remains
false. Discarding fake computations while retaining their inbound guards must fail the gate.

`pyobf_native_demo_measure_cff_misleading` pairs CFG-only with opaque, junk, decoy, clone,
synthesis and their
combination from the same IR/public seed. It writes size, transform/link time, startup and
hot-call observations to `payload.cff.misleading.measurements.json`. Run it without concurrent
build/test load. These are workload costs, not protection-strength measurements.

One isolated Windows CLANG64 run (same `heavy` fixture/public seed, 500000 hot iterations,
five hot samples and 40 startup samples) recorded the following. The CFG-only image used
5334 `.text` bytes; each row has its own paired baseline timing. Startup variation is ordinary
machine noise and cannot establish an improvement. Transform/link times were 0.28-0.40 seconds
in this run, including tool startup, not a general scalability bound.

| Component | Protected .text bytes | Baseline / protected hot ns | Baseline / protected startup us |
| --- | --- | --- | --- |
| Opaque choices | 5446 | 14.6102 / 16.6268 | 215.4 / 209.4 |
| Reachable work | 5558 | 14.5246 / 20.7378 | 235.1 / 220.2 |
| Safe clones | 6134 | 15.0896 / 28.2770 | 204.6 / 207.8 |
| Synthesis | 6278 | 14.9634 / 27.7504 | 221.7 / 223.2 |
| Combined | 6822 | 14.7326 / 43.5562 | 189.2 / 201.0 |

## State-dependent function references

`reference-routes` is independent of legacy `internal-calls`; enabling both in one selected
function fails configuration before mutation. With a deep recipe, explicitly turn
`internal-calls` off when selecting the new component. Baseline/default recipes leave it off.

```json
{
  "schema_version": 1,
  "functions": {
    "selected_caller": {
      "components": {"reference-routes": "required", "internal-calls": "off"},
      "budgets": {"max_reference_slots": 256, "max_reference_sites": 4096}
    }
  }
}
```

The supported input is a scalar AS0 reference to a defined, nonintrinsic function used in a
call, return, store, select, pointer comparison, PHI or `ptrtoint`. Target calls need an exact
nonvariadic function type and matching calling convention. Their original instruction,
argument/result attributes, effect order and ABI are preserved, including admitted normal
tail hints. Musttail, bundles, intrinsic/control operands and nested/nonpointer constant
expressions are reported unsupported. EH requires the explicit supported hybrid profile.
`available_externally` bodies are not guaranteed to be emitted: they are unsupported as
required targets and never added as decoys, so unrelated definitions cannot introduce a
new unresolved linker symbol.
Indirect targets already computed by user code, declarations, global aliases and function
tables in global initializers are outside direct-reference coverage. This component does not
turn those into covered sites or claim import protection. The current executable/final-code
evidence is Windows x64 CLANG64; the IR contract requires an explicit 32/64-bit target layout.

Each invocation owns a bounded power-of-two stack table containing its admitted targets,
up to three extra defined module targets as decoys, and at least one null slot. Target count
must leave room for a null slot. `max_reference_slots` defaults to 256 and permits powers of
two from 2 through 4096; `max_reference_sites` defaults to 4096. Reports include actual
`source_uses`, `table_slots` and target-layout `per_invocation_bytes`; these exclude general
CFF/SSA stack costs and are not a total stack bound. Oversized inventories are reported and
required coverage fails. Volatile initialization/load protects the admitted late-codegen
shape; arbitrary optimization after CFF remains unsupported.

Normalization runs after common-exit/dedup/split, before PHI demotion. A PHI's direct reference
becomes a predecessor load while its original source obligation is still available. Padding
may add a new entry; the private table alloca moves there before SSA demotion. Preparation
moves initialization to that final entry, once per invocation. Only arithmetic is bound after
state assignment. No wrapper, new function definition or new CFG edge is added at late binding.
Existing archive acquisition validation resolves the actual immutable table and state-index
expression before trusting a routed callee. Source aliases point to physical loads and do not
inflate the physical `applied` count. `applied_types` distinguishes `call-target` and
`function-address`. Private ownership/construction-state metadata is rejected in source input
and stripped only after archive final verification.

Every use has a site salt and a separate public reference-mask domain. The index depends on
the actual CFF state, then is bounded by `table_slots - 1`. Correct paths retain exact function
addresses, including returned pointers, callback comparisons, recursion and reentrant/threaded
invocations. Wrong states may select null, another real function, or the original slot through
a collision. This is a static-analysis obstacle, not authorization or a universal crash
guarantee. The table still contains ordinary target addresses; the expected construction state
in compiler metadata is not an independent integrity measurement or a general equivalence proof.

`pyobf_native_cff_reference_contract` rejects altered actual target/index/state graphs,
incomplete/duplicate/mutable/escaping tables and missing state dependence. The executable
`pyobf_native_demo_cff_references` compares original/protected ABI, sret/byval/fastcc attrs,
effects, PHIs/selects, pointer identity, recursive/reentrant and four-thread behavior. It tests
equal-seed repeatability, changed-seed table layout, mixed D1-D3 strategies, optional/required
unsupported uses, erased/retained original O2 requests, wrong-state behavior and reference-only
feature erasure. The real archive fixture also executes indexed acquisition targets.

The x86 COFF final gate requires the separate reference multiplier per reported physical use
and enough indirect call/jump transfers for routed callees (a tail call may use an indirect
jump). This is function-scoped component-presence evidence, not proof of every machine site;
the final report keeps `individual_sites_verified=false`. Existing CFG/scalar evidence cannot
substitute for a missing reference feature. Typed owned call frames are a separate component
below, alongside cross-state preparation and indexed locals. Eligible external adapters remain
D4 work.

The opt-in `pyobf_native_demo_measure_cff_references` target compares plain, CFG-only, legacy
slots and state-bound tables on identical source/seed, both before and after ordinary O2.
It records text/file size, separately timed transform and O0/no-LTO codegen/link, and paired
DLL-load/first-call/unload and warm-call medians with result checks. Frontend, plugin build and
outer packaging costs are excluded; this fixture establishes no general performance bound.
One isolated CLANG64 run observed plain/CFG/legacy/table `.text` bytes of
4822/4950/4982/5078 without source optimization and 4822/4982/5014/5126 after ordinary O2.
Table transform-plus-codegen/link was 0.266/0.258 seconds respectively. Paired table hot
calls were 5.64/6.85 ns against their plain 3.16/2.84 ns samples; load/first-call/unload was
211/219 us against 208/221 us. These very small workload timings include measurement noise
and loader effects; they do not show a general speed ranking or predict large tables.

## Typed owned internal-call frames

`call-frames` replaces an admitted original call with typed stores, one internal `void(frame*)`
invoker call and, for nonvoid results, one typed result load. Each original static site owns its
own entry stack alloca for that function invocation. Loop visits overwrite the same site's
arguments; recursive/reentrant invocations have separate stack frames. There is no global/TLS
frame, heap allocation, new runtime API or new exported wrapper. Actual target/user addresses
are preserved. The frame remains storage for the containing invocation; this is not a secure
zeroization or asynchronous retention contract.

```json
{
  "schema_version": 1,
  "functions": {
    "selected_caller": {
      "components": {"call-frames": "required", "reference-routes": "optional", "internal-calls": "off"},
      "budgets": {"max_frame_sites": 256, "max_frame_bytes": 4096, "max_frame_total_bytes": 65536}
    }
  }
}
```

These are the default frame/site budgets. The total counts all per-site entry storage even
on mutually exclusive paths, and excludes ordinary CFF/SSA/backend stack overhead. It is not
a total stack bound. A public per-site seed permutes target, argument and result fields; the
layout and helper ID are diversity, not secrets. An explicit 32/64-bit AS0 stack layout is
required; runtime/final-code validation here is Windows x64 CLANG64. The 32-bit case verifies
IR and target-sized storage only.

Targets that observe physical caller frames are outside the supported contract: the invoker
adds a real call frame. Known direct `llvm.returnaddress`/`frameaddress`/`addressofreturnaddress`
uses in a target are rejected. Opaque/transitive stack inspection cannot be exhaustively
identified; callers must leave such paths outside frame selection. True function-pointer
identity is preserved, while physical stack traces/return addresses are not promised unchanged.

Frame normalization precedes common-exit/dedup/split. Original lowered argument computations
remain in their chosen frontend order; marshaling stores the resulting SSA values at the call
position. The invoker loads their exact LLVM types, performs the original target call with its
calling convention and parameter/result attributes, and stores its exact result. No `freeze`,
reinterpretation of user object fields or source-level evaluation reorder is introduced.
An ordinary tail hint may be lowered to a returning framed call; musttail is unsupported.
Frames alone retain that marshaling shape; the separate `call-preparation` component below
deliberately splits preparation and invocation into protected states.

Admitted targets are direct emitted definitions with an exact nonvariadic AS0 function type
and matching calling convention. Fixed scalar/vector/aggregate storage is supported. Varargs,
musttail, bundles, convergence/returns-twice/duplication-sensitive controls, special inalloca/
preallocated/Swift/nest parameters, un-emitted bodies and unsized/scalable/unsupported storage
are explicit unsupported sites. Intrinsics, declarations, unknown dynamic targets, generated
archive gates and archive-wrapper protocol calls are outside this internal-call scope and
counted in `preparation.excluded_calls`; a required scope with no admitted site fails. The
archive gate keeps its own ABI and source/key coverage rather than being credited as framed.
Frames conflict with legacy `internal-calls` in one scope; they compose with `reference-routes`.

A registered `module_prepare` hook creates all invokers before any function's definition/CFG
seal, while leaving source calls intact for original coverage discovery. Each helper is an
internal `noinline` function, automatically selected with a baseline CFG recipe. It does not
recursively inherit its owner's required frame/normalizer components. Reports expose
`generated=true`, `generation_component=call-frames`, `generated_owner`, `generated_site`,
`selected=true` and `requested=false`. Original requests/aliases and physical frame invocations
stay separate; `applied_types` distinguishes `void`/`value` and preparation reports frame count
and declared frame bytes. Straight-line invokers are honestly shape-only. Strict decision-flow
selection also rejects such helpers rather than silently exempting them.

Normalization relocates original call obligations to real invocations and direct function
reference uses to their frame stores. The reference component can then protect target/argument
addresses and the helper call. Frame allocas move to the final entry before SSA demotion when
padding adds an entry. A private original-owner inventory persists through final verification.
The verifier checks unique storage/invoker ownership, actual fields/targets/ABI attributes and
closure through supported address spills on both caller storage and the helper parameter;
unmarked overwrites, escaped/shared frames and
missing/inconsistent inventory fail. Private input artifacts are rejected and successful
final output strips the inventory/layout/ABI metadata. This is bounded compiler structural
evidence, not a proof of every runtime initialization path or trusted process integrity.

`pyobf_native_cff_frame_contract` exercises nineteen storage/ABI/target/inventory mutations
per internal/external profile, plus four external profile/control mutations.
`pyobf_native_demo_cff_frames` compares plain/protected calling conventions, byval/sret,
signed zero, fixed aggregates/vectors, void/zero-argument calls, effects, loops, recursive/
reentrant and four-thread execution; it checks seed behavior, original O2 retention/loss,
budgets/private-input/collision/storage failures, actual C++ frontend ABI and exception
type/message propagation. The latter has no selected invoke/cleanup scope: those remain D1b.
The real archive fixture also combines original-call frames with protected acquisitions.

The x86 COFF final gate requires the exact generated helper inventory, selected helper CFGs,
owned helper references in each caller and indirect target invocation inside each invoker.
Bypassing only that inner target field while retaining CFG fails the frame-specific check.
This is scoped component presence; `individual_sites_verified` remains false. Last-call ABI
arguments and public frame layouts remain observable, and this component supplies no device
authorization or encrypted release material. Eligible external/backend adapters are still
required for D4.

## Imported function-address routes

`import-routes` is separate from defined-target `reference-routes` and typed `external-calls`.
It routes admitted scalar instruction operands referencing strong external non-intrinsic AS0
function declarations through an invocation-owned pointer table. Direct calls, callback
arguments, returns/stores, selects/comparisons, PHI inputs and ptr-to-integer identity uses
retain their actual function addresses. Direct callees need an exact nonvariadic type/calling
convention. Weak declarations, nested aggregates/non-scalar casts, special call-control/parameter
ABI and unsupported layouts/operations receive explicit unsupported outcomes; required scopes
with no admitted site fail. Global initializers, arbitrary aliases and unknown dynamic targets
are outside this direct instruction-operand scope.

```json
{
  "schema_version": 1,
  "functions": {
    "selected_caller": {
      "components": {"import-routes": "required", "external-calls": "optional", "call-preparation": "optional"},
      "budgets": {"max_import_slots": 256, "max_import_sites": 4096}
    }
  }
}
```

The import slot limit permits powers of two from 2 through 4096 and must leave a null slot.
Import/reference limits, seed domains, mask coefficients, physical tables and source counts
are separate. Reports include actual source uses, table slots/bytes and call-target versus
function-address roles. Pointer bytes use the target layout, not the build host. A table stays
private to the containing invocation; recursion/reentrancy/threads use separate stack storage.
Wrong-state lookup stays within its table, but a selected null/incompatible target can crash.
This is neither authorization nor a universal wrong-state mismatch guarantee.

The explicit imported table profile admits declarations; old internal profiles still require
definitions. Reserve imported storage/slot inventory and pending loads during normalization.
Generate complete volatile initialization in the final entry after structural splitting/first
SSA. Create the actual indexed GEP with final state arithmetic only during binding, keeping
its pointer load beside it. This avoids moving spilled initialization/address dependencies.
The shared normalizer drops pure/speculatable attributes invalidated by volatile work. An
optimizer regression demonstrates that an unused formerly pure call keeps its new observation;
that probe does not claim arbitrary post-CFF O2 preserves CFF shape.

The imported resolver proves complete immutable actual initialization against its planned
slots, closed table storage and exact bounded mask/decoded-slot arithmetic. It validates the
real state slot and the final dispatcher path to the consuming body. State cancellation that
happens to calculate the correct normal index, fake state slots and coherently changed
expected-state/correction metadata cannot substitute for that path proof. Atomic/misaligned
reads, escaping/mutable storage, unused consumers, orphan initializers and missing/invalid
profiles fail. Private instruction/function/named input artifacts are rejected; successful
output strips the private reference/import metadata after combined proofs.

Frame target/argument stores and common-exit result stores preserve original imported-use
aliases. A typed external frame's target proof consumes the actual imported resolver, rather
than trusting the intended symbol in metadata. Frame helpers retain their separate ownership
and original/generated accounting. No runtime resolver, OS query, allocation API, new export
or loader operation is introduced. Import names and the final system/library ABI remain
visible; this does not implement PE import-table hiding, dependency collection/memory mapping
or protection against OS loader/IAT replacement.

`pyobf_native_cff_import_contract` exercises twenty-three table/profile/graph/state/closure
mutations. `pyobf_native_demo_cff_imports` executes actual provider-DLL target/callback/PHI/
select/escape/address identity and ABI/effect/thread behavior, seed layouts, mixed internal
references/external frames/preparation/locals, original O2 retention/loss, required/optional
controls, budgets, private metadata, target-32 IR/layout, erased-domain and wrong-state cases.
It also uses real frontend C++ aggregate ABI and exception propagation through selected
callers without local cleanup, plus the explicit supported hybrid cleanup profile. The actual Windows
backend test combines imports with external frames/preparation under its admitted
no-exceptions profile and pins default invoke/cleanup rejection. Seven scalar mask domains
execute at every width 1..128 at O0/O2. Runtime/final-code evidence is Windows x64 CLANG64;
target-32 proves IR/layout only.

The x86 COFF gate requires imported-domain coefficient presence per actual physical route
and indirect transfers for direct routed-call roles. Erasing that feature while retaining CFG
fails its gate. This is scoped final presence; `individual_sites_verified` remains false.
Use `pyobf_native_demo_measure_cff_imports` for paired plain/CFG/import/imported-frame/prepared
comparisons with one unchanged provider DLL. Each component's storage counts exclude unrelated
stack costs, and main/provider size/build costs remain separate.

One isolated current CLANG64 run observed none/O2 main `.text` bytes of
4822/4950/5078/5718/9222 and 4822/4982/5126/5750/9254 for plain/CFG/import/imported-frame/
prepared combinations; the unchanged provider adds 4758 text bytes separately. Two imported
uses allocate a 32-byte table. Frame composition adds 40 frame bytes and 32 internal-reference
table bytes; preparation uses 64 frame bytes instead, excluding other stack overhead. Imported
hot times were 7.078/7.4972 ns versus paired plain 3.54/3.472 ns, transform+codegen/link
0.2792/0.2884 s, startup 463.9/476.1 us versus 455/477 us. Frame composition measured
15.8738/17.7444 ns and prepared composition 93.5996/94.9522 ns. The existing internal-reference
cost target also passed eight variants with the same current plugin. These are small-fixture
warm medians and include ordinary timer/cache/loader variation; no strength/performance bound
or full-bootstrap startup claim follows.

## Typed external-call adapters

Enable `"external-calls": "required"` on the selected caller to move admitted external-call
arguments and results through invocation-owned typed frames. Add `"call-preparation": "required"`
for distinct state-bound field/invocation steps. `call-frames` remains a separate selection for
defined targets; enabling both does not merge their logical source obligations, helper owners,
public seed domains or applied counts. `max_frame_sites`, `max_frame_bytes` and
`max_frame_total_bytes` are shared limits: the total counts both enabled target classes,
including already normalized frames, and excludes unrelated stack overhead. Like internal
frames, external frames conflict with legacy `internal-calls`; set it to `off` when extending
the deep compatibility recipe. The state-bound `reference-routes` component composes with
external frames and can protect their internal helper-call references.

Source targets must be direct non-intrinsic strong external declarations with exact
nonvariadic AS0 function types and calling conventions. Ordinary Windows `dllimport` functions
are admitted. Fixed scalar/vector/aggregate arguments and results, byval/sret and parameter/
result attributes retain their original lowered ABI. Weak declarations, varargs, musttail,
bundles, returns-twice/convergent/duplication-sensitive calls, special parameter ABI and
unsupported storage fail required obligations; unknown dynamic targets are not direct
external sites. Optional unsupported sites receive no adapter credit; function-level
nonlocal-control rejection still applies. Original computations
and effects keep their frontend order; callback addresses keep their actual identity.

The strategy adds a private `noinline void(frame*)` invoker per original call before definition
sealing, with `generation_component=external-calls`, explicit owner/site and `requested=false`.
Baseline helper CFF and owner-approved preparation use the existing modular implementation.
It adds no heap/TLS service, OS operation or runtime resolver. The native backend's semantic
macros still mediate OS operations. Target addresses retain ordinary linker/OS import ownership;
DLL loading, delay resolution and initialization policy are not replaced or hardened here.
The final target ABI, import names and target pointers remain visible. Imported-address table
routing is available through the separate `import-routes` component above. Dependency
collection and memory mapping retain separate follow-up scope.

The shared verifier accepts declarations only under an explicit external descriptor profile;
internal descriptors still require definitions. It checks actual typed fields, target, inner
calling convention/attributes, closed storage and unique original owner/invoker inventory.
Weak/profile/control changes, escaped/shared storage or missing/duplicated accesses/inventory
are rejected. Compiler-private construction records are rejected in input and stripped only
after combined proofs. This is scoped structural evidence, not runtime authenticity.

Like internal frames, an external adapter adds a physical call frame. Opaque library stack
inspection, return-address identity, nonlocal resume and asynchronous retention of a frame
are outside its target contract. Calls that can throw may propagate through an admitted
caller without local cleanup. Supported landingpad invoke/cleanup scopes require explicit hybrid coverage.
In particular, the default C++ frontend emits terminate cleanup around the current Windows
memory backend's noexcept wrappers. The backend test preserves that rejection and separately
executes its `-fno-exceptions` adapter profile. Separate hybrid profiles execute the
default-exceptions backend with cfg, adapters/preparation and imported-address routes.

`pyobf_native_demo_cff_external` compares plain/protected code against a real separately linked
provider DLL, including calling conventions/sign extension, sret/byval, aggregates/vectors,
void/zero-argument calls, effects, loop visits, recursive callbacks, reentrancy and four threads.
It checks deterministic/varied seeds, mixed components, original O2 retention/loss, required/
optional ABI exclusions, combined frame/preparation budgets and target-32 IR storage. Real
frontend C++ aggregate ABI and exception type/message propagation also cross a provider DLL.
`pyobf_native_demo_cff_external_backend` compiles actual backend/user source units, routes
allocation/erasure/release through semantic macros and executes the admitted backend profile.

The x86 COFF final gate requires complete selected helper ownership, actual caller routes and
indirect target invocation in each external adapter. Erasing just its inner indirection while
retaining CFF fails this component gate. `final_presence_verified` is scoped presence evidence;
`individual_sites_verified` stays false. Windows x64 CLANG64 is the runtime/final-code scope;
target-32 checks prove IR/layout only. No kernel, Linux/macOS runtime or real detector support
is inferred. Use `pyobf_native_demo_measure_cff_external` for isolated same-source/seed
plain/CFG/external-frame/prepared-frame comparisons with one fixed provider DLL. Its provider
build/size/hash is recorded separately; main `.text`, transformation/codegen/link and paired
startup/hot costs have the shared driver's stated fixture/noise boundaries.

One isolated current CLANG64 run observed none/O2 main `.text` bytes of
4822/4950/5414/9062 and 4822/4982/5462/9078 for plain/CFG/external-frame/prepared-frame.
The unchanged provider adds 4758 `.text` bytes separately. Two call sites declare 40 frame
bytes, or 64 with preparation, excluding other CFF/SSA stack work. Frame-only hot times were
15.3424/14.5822 ns versus paired plain 3.3248/3.435 ns; prepared plus reference routing was
93.0816/94.9864 ns versus 3.4722/3.4064 ns. Frame transform+codegen/link took 0.2592/0.2564 s.
Frame startup was 462.2/485.5 us versus 447.1/466.7 us; prepared startup was 522.6/441.7 us
versus 510.1/451.6 us. Startup includes the fixed provider load and ordinary loader noise;
these tiny-fixture observations are not performance bounds or protection-strength measures.
The existing internal-frame cost target also passed eight variants with the updated shared
driver and its default no-provider path.

## Indexed local objects

`indexed-locals` is an independent opt-in component for whole functions and the admitted
Windows GNU hybrid EH profile. Python's `slot_vars`
maps local bindings into a list of object references. Native slots instead refer to original
typed stack objects, preserving their exact types, alignment, allocation counts, address
identity, subobject layouts and aliases. Values remain in those objects; this is address/binding
obfuscation, not value encryption or a rewrite of C++ object layout. Generated SSA spills are
not relabeled as protected locals. There is no heap allocation, new runtime API or global/TLS
table. Nested/recursive/reentrant invocations and concurrent callers own independent tables.

```json
{
  "schema_version": 1,
  "functions": {
    "selected_owner": {
      "components": {"indexed-locals": "required"},
      "budgets": {"max_local_slots": 256, "max_local_routes": 4096, "max_local_bytes": 65536}
    }
  },
  "markers": {
    "pyobf.native.sdk": {"components": {"indexed-locals": "optional"}}
  }
}
```

Select original fixed, nonempty, sized entry allocas with an explicit 32/64-bit AS0 stack
layout. Fixed scalars, arrays, aggregates and vectors are supported, including over-alignment,
constant allocation counts, atomic/volatile operations and pointer-containing objects. Existing
GEP, PHI/select, pointer comparison, call and escaped-address relationships retain the original
objects. A route protects a direct original-object address use or the start of a derived alias
chain; it does not separately instrument every later dereference of an already acquired alias.
Lifetime/debug control operands continue to designate original allocations and are reported
as retained controls rather than protected address routes.

Dynamic/nonentry, inalloca/swifterror, naked/foreign-stack, empty/unsized/scalable storage and
ABI/control-sensitive intrinsic, bundle, assembly or musttail uses have explicit unsupported
reasons. Ordinary memory intrinsics are admitted. Required unsupported/zero/lost requests fail;
optional unsupported objects stay outside this component. Frontend parameter stack slots may
qualify, but original SSA values and allocations introduced later by CFF/archive/frame support
do not become source-local coverage. If ordinary O2 removes an original object, a required
source request is reported as lost; selecting this component does not recreate that object.
Regions cannot enable it.

A public seed shuffles original object references and null entries in a power-of-two table.
`max_local_slots` permits powers of two from 2 through 4096 and reserves a null slot. The other
two budgets limit physical address routes and the table's own target-sized bytes. They do not
bound retained source storage, SSA/CFF scratch space or the complete native stack frame.
Reports count original objects in `applied`/`applied_types`; preparation separately records
`objects`, `address_routes`, `retained_control_uses`, `table_slots`, `per_invocation_bytes` and
`initializer_instructions`.

Normalization reserves storage and pending volatile pointer loads at original use points.
Initialization is generated in final entry during prepare, after structural splitting/first
SSA; moving previously split/spilled initializer GEPs is unsafe. Bind creates each bounded
table index from the actual address-producing body state, its site salt and a separate public
mask domain. No helper/CFG is created after state assignment. LLVM calling attributes and the
frontend's effect order remain unchanged. Exact mask/index/target graphs and real final
dispatcher routes are checked, together with complete immutable initialization, unique source
object/use inventories and the absence of unplanned direct object-address uses, table mutation/escape, dropped
consumers and orphan artifacts. Private tags survive combined checks and are then stripped;
source-supplied private artifacts are rejected.

The tests execute typed/aligned/atomic/volatile/alias/escape/lifetime/loop/recursive/reentrant/
four-thread cases, source O2 retention/loss and real C++ aggregate ABI/lifetime behavior with
frames/preparation/references. Thirty-two verifier mutations cover actual graph/table/object/
inventory/source/escape/unused-route failures. Separate cases cover budgets, unsupported
objects, private input and target-32 layout. Real SDK/user/backend source units are linked and
executed, and the real protected-archive fixture verifies its original local without crediting
generated key/frame/SSA storage. Runtime/final-code evidence is Windows x64 CLANG64; target-32
is IR/layout evidence only. EH cleanup scopes remain D1b.

The x86 COFF gate requires a retained local-domain coefficient for every reported physical
address route in its owner alongside existing CFG evidence. Erasing that feature while keeping
CFG fails. This is scoped component presence; `individual_sites_verified` remains false.
Public layouts/masks are not secrets. All states keep the table lookup bounded, but wrong
states may choose null, another incompatible object or the original slot. No authorization,
universal mismatch/crash, safe wrong-path dereference or runtime-dump protection is claimed.
Use `pyobf_native_demo_measure_cff_locals` for the same-source plain/CFG/locals/composed cost
comparison before selecting hot functions.

An isolated current-plugin run checked eight linked/executed variants with the same two
volatile source objects, both before/after ordinary O2. Plain/CFG/locals/locals-plus-call-
composition `.text` bytes were 4838/4966/5174/9542 and 4822/4998/5222/9574. Each local table
added 32 declared bytes for two objects/four address routes, excluding the retained objects
and general SSA/CFF stack costs. Locals transform plus O0 codegen/link took 0.556/0.307 s;
warm calls were 5.93/7.56 ns against paired plain 3.15/2.92 ns. CFG-only samples were 5.58/7.54 ns,
and the full call/preparation/reference composition took 99.89/99.66 ns. Local startup medians
were 239/278 us against 247/278 us. These Windows x64 CLANG64 fixture observations include
timing/cache/loader noise; they establish no general performance or protection-strength bound.

## Cross-state call preparation

Enable `"call-preparation": "required"` beside `"call-frames": "required"` or
`"external-calls": "required"`. The component is
off by default and uses the same admitted ABI/site set. `max_preparation_steps` defaults to
1024 per selected function; existing frame-byte/site/total and body-block budgets also apply.
One logical preparation site is the caller invocation or the generated invoker's target call.
Every nonempty typed field read/write and the invocation occupy distinct routing blocks/states,
prepared before final state assignment. Existing argument evaluation order and exact inner ABI
remain intact. Generated invokers receive explicit owner-approved preparation support; they do
not recursively frame calls or inherit every owner component. Strict original decision-flow
requirements still reject shape-only helpers.

Each nonempty field address uses its producer's actual local CFF state, a separate public mask
domain and a per-site salt. For field byte offset `o`, ABI alignment `A`, total allocation `F`
and field allocation size `S`, define `N = floor((F-S)/A)+1`. Decode a baked placement using
the state mask, reduce modulo `N`, then multiply by `A`. Correct execution addresses `o`;
all i32 states yield aligned in-allocation accesses. A reserved shuffled byte-array field of
`max_field_bytes + max_field_alignment` guarantees `N >= 2`, including target-only void calls.
This padding counts in frame storage budgets even if optional preparation cannot be applied.
Zero-byte fields keep constant addresses and receive no address-protection credit. Address
computations may precede their typed I/O step and cross it through closed SSA stack copies.

`applied`/`applied_types` count logical caller/invoker sites. Preparation metrics separately
count `logical_sites`, `field_addresses`, `empty_fields`, `state_steps` and `created_blocks`.
The verifier matches the actual finite-width mask/decode/modulo/alignment graph, exact field
layout, unique owned state slot and final dispatcher route. It checks caller/helper ownership,
complete fields and distinct steps/states through bounded unambiguous nonescaping SSA copies.
Canceled state arithmetic, missing/wrong fields, fake states, pointer escapes and incomplete
inventory fail. All preparation metadata remains private and is stripped only after combined
archive/frame/preparation checks; source-supplied private artifacts are rejected.

The full frame differential suite also runs with preparation: ABI/side effects, loops,
recursive/reentrant/thread use, source O2 and real C++ sret/by-value/exception propagation.
Seventeen structural mutation cases and a separate empty-field/budget/wrong-state/private-input
suite exercise the added proof. Original static entry allocas remain before initialization and
padding so later SSA demotion preserves LLVM lifetime operands. The real archive fixture composes
preparation with protected acquisitions and reference tables.

The x86 COFF gate requires a retained preparation-domain coefficient for each reported field
address in its owning function, alongside existing CFG and frame checks. Erasing this component
while retaining CFG fails. This is scoped presence evidence, not individual machine-site
equivalence (`individual_sites_verified=false`). Public masks/layouts are not secrets; wrong
states may collide or read other/uninitialized fields. This is static obfuscation, with no
authorization or universal crash/fault-safety guarantee. Measure the extra dispatcher/stack
cost using `pyobf_native_demo_measure_cff_preparation` before selecting hot paths.

An isolated current-plugin run of that target checked ten linked/executed variants across
plain/CFG/frame/preparation/preparation-plus-reference recipes and none/O2 source profiles.
Preparation `.text` was 8966/8982 bytes versus frame-only 5414/5462 and plain 4822/4822;
adding reference routes used 9286/9318 bytes. The two-call fixture's declared private frame
storage rose from 40 to 80 bytes (excluding SSA/CFF/backend stack overhead). Preparation
transform plus codegen/link took 0.288/0.270 seconds, warm calls 92.61/95.43 ns against paired
plain 3.01/2.80 ns; paired frame-only calls were 14.17/15.54 ns. Preparation startup medians
were 218/203 us against 215/204 us. These Windows x64 CLANG64 samples include timer/loader
noise and establish no general performance or protection-strength bound.

`pyobf_native_demo_measure_cff_frames` uses the shared same-source plain/CFG call workload for
frames alone and frames plus references, both before/after ordinary O2. It records separate
transform/codegen-link time, text/file size, declared frame storage and paired checked startup/hot
calls. Build/runtime scope and measurement-noise limitations match the reference benchmark.
The earlier typed-frame unit's isolated CLANG64 run observed plain/CFG/frame/frame-plus-reference `.text` bytes of
4822/4950/5414/5718 without source optimization and 4822/4982/5462/5766 after ordinary O2.
Frame-only transform plus codegen/link was 0.278/0.273 seconds, warm calls 14.01/14.75 ns
versus their plain 2.71/2.91 ns samples, and load/first-call/unload 240/258 us versus 258/242 us.
Frames plus references used 16.28/15.28 ns versus paired plain 2.81/2.69 ns samples. These
fixture observations include loader/timer noise and supply no general performance bound.

## Typed scalar literals and equality

`integer-literals` now keeps exact scalar widths from i1 through i128. APInt host calculations
and generated truncation/extension concatenate 32-bit state-mask lanes; no i64/i128 literal is
silently narrowed to the dispatcher's i32 width. Original operations, signed/unsigned predicates,
shift counts, stores, selects and their result types remain unchanged. On a valid path every
decoded operand has its original bit pattern. Wider integers and vector/pointer literals are
not coerced into this subset. Small-width wrong-state masks can collide; the feature never
promises that every possible wrong state changes every operand.

The separate `comparison-constants` component handles an integer eq/ne with one literal and
one live operand. Each site's fixed-width bijection combines a state-keyed XOR, addition,
right-xor shifts and two odd multipliers. These operations are bijective modulo that width;
there is no signed overflow or out-of-range shift. The target constant is encoded at build
time under the expected state, while only the live operand uses the observed state. Encoding
both operands under one observed key would cancel this dependency and is not the design.
This is local white-box concealment, not an issuer secret or cryptographic authorization.

Binding runs before scalar literal hiding. A literal originally on the left relocates its
scalar obligation to the encoded right operand of the original comparison. Its own site ID
uses a registered semantic target role, so ordinary optimization
may swap constant sides or invert eq/ne without falsely losing the request. Private maps
still retain the discovered physical operand index; final location maps deduplicate role
aliases. A required comparison actually folded away by optimization still rejects.
Comparisons retain their original identity, metadata/debug location and eq/ne result but clear a same-sign
assumption, because a non-monotonic bijection does not preserve operand signs. Original defined
inputs remain equivalent; no new poison-generating arithmetic flags are added. Ordered
comparisons are untouched by this component, and a required request with only ordered compares
fails as zero eligible work. Boolean i1, pointer/vector and oversized equality sites are
explicitly unsupported. Optional unsupported sites remain visible while eligible work applies.

The effective recipe reports each component's `applied_types`. The distinct comparison-key
domain permits the x86 COFF inspector to require retained mask lanes for all counted widths;
an existing scalar decoder cannot satisfy that check. It remains scoped component-presence
evidence, not a proof of every individual instruction. Public mixing coefficients remain
outside subsequent scalar hiding; protected user operands and encoded targets remain eligible.

The scalar contract runs actual production expressions at all widths, exhaustive small inputs,
O0/O2 codegen and an altered-coefficient negative. Full-pass tests cover wrapping, both signed
and unsigned ordering, shifts, volatile storage, PHIs, left/right eq/ne, 128-bit wrappers,
combined D1/D2 components, unsupported types, wrong state and removed comparison dependence.
A selected distinctive wide constant must also be absent from the final fixture image bytes;
this is not a claim that every incidental short byte sequence disappears from machine code.
`pyobf_native_demo_measure_cff_typed_data` records paired scalar/equality/both costs against
CFG-only from the same IR and writes `payload.cff.typed.measurements.json`.

One isolated Windows run of the i64 equality fixture measured 4934 `.text` baseline bytes;
scalar-only/equality-only/combined used 5126/5078/5926 bytes. Paired hot calls were
3.4390/4.2776 ns, 3.6242/4.1892 ns and 3.7192/13.9928 ns, respectively. Combined binding also
hides eligible constants introduced by the comparison expression, so its work can exceed the
sum of each isolated feature's cost. Startup pairs were 206.7/203.6, 218.0/229.0 and 197.9/187.8
microseconds; these are noisy machine/workload observations, not security-strength measures.

The scalar/comparison cost evidence above covers that subunit only. The separate
[typed archive pipeline](NATIVE_ARCHIVE.md) now covers admitted integer/FP/code-unit arrays
and binary assets with stable storage and state-keyed acquisition; its separate size/build/
first-use/warm-call measurements are recorded there. A module with no archive records uses
an empty compiler handoff. Optional empty scopes continue, required empty/lost requests fail,
and reports never credit nonexistent acquisitions. This does not enable the unfinished full
`parity` recipe.

## Build integration and provenance

The demo's outer glue is a separate `outer-bootstrap` domain with its own recipe, request
manifest, native object and linked report. `PYOBF_NATIVE_DEMO_OUTER_CFF` defaults ON;
`PYOBF_NATIVE_OUTER_CFF_CONFIG` and `PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT` are independent of the
payload recipe/optimization. `PYOBF_NATIVE_CFF_BOOTSTRAP` marks ordinary functions and
`PYOBF_NATIVE_CFF_BOOTSTRAP_EH` marks explicitly configured hybrid functions. The default
recipe selects21 ordinary and two Windows GNU hybrid glue definitions in both default
and triggered variants. A forced whole-scope override still rejects the actual EH bodies.
The final gate also rejects a runnable unprotected DLL compiled from the same combined IR.

The build order is payload final verification -> private per-build event input -> ciphertext
and masked-key record -> outer IR/requests -> optional source O2 -> outer CFF -> O0/no-LTO
object -> raw outer link -> data-only finalization -> exact final report. Parent IPO does not
optimize the sealed outer object or see the native record initializer. The OFF profile compiles
ordinary markers and has no outer-coverage claim; local reconstruction remains a weaker
static hurdle. Owned context/handoff and local path-fold release are integrated; measured
L2 readiness and D6 transition binding remain unimplemented. Owned derived-source acquisition
now exists separately, as described in the [contribution guide](NATIVE_CONTRIBUTIONS.md). See the
[release guide](NATIVE_RELEASE_RECORDS.md) for final artifact properties and private build inputs.
An optional [decoy build domain](NATIVE_DECOY.md) uses independent source/configuration/seed
and `decoy-payload` report identity. Its source ABI/initialization gate precedes requests,
and its exact final-image report precedes private event preparation and packaging. Named
outer-decoy variants add independent runtime preparation/release with their own recipe and
four further required fold owners. Their role-specific stages7-10 follow real admission
retirement; ordinary outer variants retain the original failure results. A compiler site
role of `real` here means actual semantic work in that failure domain, not extra protected
real-application edges or D6 gate density. Systematic decoy fault/erasure/OOM acceptance
remains required before full Unit4 completion.

The demo exposes `PYOBF_NATIVE_CFF_CONFIG` and optional `PYOBF_NATIVE_CFF_PRIVATE_MAP` CMake
file paths. Both request collection and transformation read the same configuration; changing
the configuration reruns them. The request pass writes a manifest and stamped LLVM IR before
ordinary optimization. Retain that IR through optimization to identify disappeared original
sites. Enabled components may register a `retain_source` callback at this boundary; it cannot
change the sealed function-definition set or CFG. `call-frames` uses it only for eligible local
targets of required frames, or enabled optional frames with required `call-preparation`.
Compiler-used roots prevent dead-argument/return ABI rewriting without exporting symbols or
requiring linker retention. Existing roots are preserved and repeated collection adds no
duplicates. This is not general provenance preservation: inlined, unreachable or otherwise
removed source sites still use the normal required/optional coverage policy.
`pyobf_native_demo_cff_frame_abi_retention` exercises the actual O2 rewrite, retention and
normal/exceptional results. A standalone invocation follows this order:

```text
opt -load-pass-plugin=<plugin> -passes=pyobf-native-cff-requests
    -pyobf-cff-config=recipe.json -pyobf-cff-requests-output=requests.json
    -S input.ll -o requested.ll
opt -passes=<supported ordinary optimization> -S requested.ll -o optimized.ll
opt -load-pass-plugin=<plugin> -passes=pyobf-native-cff
    -pyobf-cff-config=recipe.json -pyobf-cff-requests-input=requests.json
    -pyobf-cff-report=coverage.json -S optimized.ll -o protected.ll
```

Do not run ordinary optimization after state-bound obfuscation. Legacy manifests without
site inventories remain accepted. A manifest paired with unstamped IR cannot prove exact
original-site survival: missing provenance is `unverified`, never falsely `optimized-away`.
Explicit required site obligations reject that uncertainty.

Coverage schema 2 retains the existing function fields and adds effective recipes, component
stage/scope/analysis/runtime contracts and derived public seeds. Each component separately
reports requested, eligible, applied, unsupported, optimized-away and unverified sites, with
opaque IDs, input/generated/request origin, replacement links and retained/applied instance counts. Site totals
separate original blocks/edges/decisions, shape padding, real rewritten transitions, decoy
bodies, normalized returns, deduplicated blocks and oracle gates. A return-only padded function is still `shape-only`.
Separate `normalized_blocks`, `normalized_edges` and `normalized_decisions` describe the scope
after structural normalization and before padding/switch expansion/dispatch generation. Edges
there count distinct successor destinations; a condition whose two arms now reach the same
block is not a decision. `input_coverage_kind` retains the original category, while collapsed
decision flow becomes `normalized-straight-line` and is not credited as decision-flow verified.
Strict decision-flow selection rejects that outcome.

`-pyobf-cff-private-map=private.json` explicitly writes source/block/instruction provenance
and corresponding transformed-IR consumption locations.
Keep that file and request/IR diagnostics in the private build tree. No source map is emitted
as a runtime global. Reports do not contain literal values, content keys or observation data.
The linked Windows demo inspector checks CFG shape and the presence of applied component
features, binding its result to the exact image/report hashes. It does **not** prove each
individual reported site survived code generation; `individual_sites_verified` remains false.

## Declared dependency validation

Optional `build_domains` and `runtime_services` arrays describe prerequisites:

```json
{
  "schema_version": 1,
  "domain": "outer",
  "build_domains": [
    {"id": "outer", "requires": ["inner"]},
    {"id": "inner"}
  ],
  "runtime_services": [
    {"id": "root", "ready_at": "L0", "first_use": "L0"},
    {"id": "support", "ready_at": "L1", "first_use": "L2", "requires": ["root"],
     "protects_first_release": true}
  ]
}
```

Unknown prerequisites, duplicates, cycles, use before readiness and later-ready initialization
dependencies fail. A service marked `application_domain: true` cannot also protect its own
first release; a first-release protector must be ready by L2. Domain order is child-first;
each domain follows instrument/link, freeze, hash/fixed-layout-data finalization, exact
verification, pack, then parent consumption. Hash references cannot modify their measured
instructions. Component registration rejects unregistered late structural mutation or hooks
declared in the wrong stage. These are consistency checks on declarations and registered
hooks. A CFG seal also checks actual block, terminator and successor identities around
nonstructural route/bind/transition hooks, rejecting an undeclared structural change before
code emission. It also rejects late changes to the module's function-definition set, so a
state-bound hook cannot silently introduce an unselected helper. `runtime_readiness_proven`
is false. These checks do not repair the prototype's known loader
replacement window or establish an owned authorization context.

## Adding a component

The [path-fold contract](NATIVE_PATH_FOLD.md) provides a modular binding example:
`path_fold_sites.cpp` discovers and validates the private source ABI,
`path_fold_retain.cpp` preserves original calls before optimization, and
`path_fold_bind.cpp` emits state-dependent arithmetic after final state assignment.
`path_fold_seal.cpp` freezes the original storage/event/body-state relationship separately
from `path_fold_proof.cpp`, which checks the emitted reads, expressions and eight stores.
These checks do not infer cryptographic integrity or that bootstrap release consumes the fold.
The component is off by default, supports whole functions and normal-body hybrid-EH sites,
and rejects explicit regions and EH pad headers. Its per-function `max_path_fold_sites`
budget accepts 1 through 1048576. Required mode rejects zero, unsupported or lost original
sites; optional leaves unsupported ordinary calls requiring a separately linked provider.
The final checker records function-scoped presence, with `individual_sites_verified: false`.

1. Put the implementation and candidate discovery in its own strategy source. Add the source
   to `native/llvm/CMakeLists.txt`.
2. Register its `Component` entry in `component_registry.cpp`, including scope, analyses,
   mutation stage, runtime dependency and typed retain_source/module_prepare/normalize/prepare/route/bind/transition hooks.
   Source retention runs before original requests are collected and ordinary optimization;
   use it only for declared compiler metadata/ABI retention, never late CFG or helper generation.
   Module preparation runs at A2 before per-scope seals. Return every new internal helper as
   a `GeneratedDefinition` with owner/site/component; unregistered/removed definitions and
   selection/name collisions fail. Helpers receive explicit baseline CFF recipes and generated
   coverage rows, not invented original requests. Preserve source instructions for later
   discovery, then relocate uses in normalization. The orchestrator normalizes, routes call slots, freezes pre-state anchors, prepares final
   structure, re-lowers ordinary SSA, assigns states, binds and emits transitions. A component
   may explicitly register preparation plus a later binding hook. Classify every generated
   block through `CfgOrigins`; do not hide block creation in a state-bound callback.
   A pure encoded-transition wrapper also registers its production emitter in
   `transition_registry.cpp` and sets `Component::transition_model` to that capability.
   `transition_model_identity.cpp` must reduce it to an arbitrary unchanged normal input at
   the frozen entry state. `transition_model_match.cpp` then proves the actual graph, before
   source/normal-flow consumers use the core and exact owned reads. Keep strategy emission,
   reference reduction, matching, selection and typed descriptors in their existing modules.
   New runtime dependencies or structural effects need their own admission/proof rather
   than an identity registration or a retained metadata exemption.
   A non-CFG initializer keeps `changes_cfg=false`; automatic contribution composition then
   still requires the full hook seal and post-prepare source/normal-flow proof. Preserve
   closed compiler markers through `source_marker_name`. Add new state-bound data tags to
   the shared state/root proof and retain the component's independent operation verifier.
3. Discover actual candidates and precise unsupported reasons. Call `SiteCoverage::applied`
   only where a rewrite actually occurs. Keep original provenance and account for generated
   sites; do not claim a wrapper around one observation as multiple independent checks.
   A proved instruction merge calls `coalesce_instruction`; moving a protected use calls
   `relocate_use` with the old/new operand indices. These APIs preserve obligations and maps,
   rather than treating deletion as applied protection. The component must prove the semantic
   correspondence; the alias graph only validates the target and coverage relationship.
   If a component's protected role survives operand permutation, register `identity_operand`
   to derive a stable semantic identity. Physical operand indices remain map data. Default
   operand-index identities stay unchanged for components without such a contract.
4. Add differential and negative fixtures, final-image inspection and cost evidence appropriate
   to the component. Extend required recipes only when the promised coverage exists.

`contribution_contract.hpp` freezes compiler-facing source/owner/site responsibilities for
later D5-D7 integration. It is not a runtime provider, cache, detector or metadata encoder.
