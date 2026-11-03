# Compiler-generated function subjects

This D7 producer composes an exact function contribution with registered generated helper
bodies. It reuses the [physical COFF proof](NATIVE_FUNCTION_SUBJECTS.md), canonical native
capture and [reserved reference records](NATIVE_REFERENCE_SLOTS.md). Production post-role
helper-policy/manifest CMake wiring is implemented in the scoped Windows CLANG64 profiles;
its host composer/CLI and existing consumer argument seam accept exact ownership inputs.
Existing root-only profiles remain separate. This does not complete generated reader/cache
independence or D7.

## Early policy and late artifacts

A kind3 selector may add `"generated_helpers":true` alongside its exact `symbol`, `aliases`
and `fragments`. The Boolean participates in canonical plan identity before code generation.
It does not name helpers discovered after transformation. Old selectors keep their prior
identity and physical-root meaning. A helper policy without exact ownership inputs refuses;
it cannot silently revert to the root alone.

After normal transformation checks, the compiler report adds verified `generated_ownership`
edges. Call-frame and external-call edges come from actual `GeneratedDefinition` owner/site/
component records. Archive acquisitions name their actual materialized wrapper and original
source. A shared archive wrapper may belong to multiple source owners. Existing source/call
obligations and helper rows must agree with the edge set. Unknown generators, duplicates,
missing definitions and dependency cycles refuse. Ordinary calls, symbol prefixes and nearby
addresses do not confer ownership. Registered generator kinds have an explicit host registry.

`pyobf_native_emit_object(... FUNCTION_SECTIONS OWNERSHIP_REPORT report.json)` emits its
existing non-LTO native object plus `<object>.ownership.json`. The sidecar records object,
final input IR and compiler-report SHA-256 values and the exact normalized edge set. It
does not alter executable IR or introduce an ownership table into the distributed DLL.
The consumer receives both sidecar and independent compiler report, checks their exact
correspondence and actual object hash, then reads complete root/helper COFF contributions
against the linked image. The IR hash records emission provenance; it is not an independent
proof that an arbitrary compiler translated that IR correctly.

The compiler, source/emission policy and private build inputs remain trusted. These hashes
detect mixed epochs and inconsistent artifacts; they do not authenticate a malicious build
environment that coherently forges every input. Runtime consumers receive authenticated
range records, not caller-created ownership graphs.

## Closure and data finalization

The producer takes the generated-dependency closure, deduplicates shared helpers and combines
their actual ranges with the declared root. Each helper must pass the existing exact typed
function, relocation, alias/folding and final-byte checks. This initial helper emitter admits
no implicit helper aliases or unassociated outlining; unexpected fragments fail explicitly.
The union must satisfy the existing disjoint-range, count and byte budgets. No ordinary
callee graph is inferred, and this is not a whole-callgraph measurement.

`finalize_references.py` accepts `--ownership INDEX=manifest` and
`--ownership-report INDEX=compiler-report` for all and only helper-selected records. The
existing data-only fill seals the complete subject and records both provenance hashes.
Changed helper instructions, missing ownership, root-policy substitution and stale object/
report pairs refuse. Repeated completion preserves bytes. No measured digest or late helper
name regenerates code, so checking an instrumented function does not create a hash cycle.

The CLI rejects missing or unmatched ownership/report bindings, duplicate/noncanonical
record indices, stale reports and outputs aliasing either ownership input. Refusal preserves
existing input/output bytes. Fresh seals may use different nonces; tests authenticate their
contents rather than requiring equality across independent sealing invocations. The emission
test also deletes its private sidecar and requires the real build rule to recreate it.

The post composer accepts the same `--ownership`/`--ownership-report` bindings. Existing
runtime/fault/cost consumer parsers expose `--post-ownership`/`--post-ownership-report`, with
target-qualified pairs where they already select multiple targets. Both maps must exactly
cover the frozen helper records of that target; sibling targets cannot supply an omitted
binding. An object rebuilt for a fault/cost counterpart cannot reuse another object's
sidecar. Fresh variants use their own actual object/IR/report provenance. The host test
exercises both post-only and pre+post record
versions, including explicit zero-helper evidence when the actual compiler generated none.

`recipes/post_generated_functions.json` selects complete generated subjects for both roles.
CMake requests ownership sidecars only for helper-selected roles and tracks both compiler
report and sidecar as finalization inputs. The ordinary outer-OFF and plain fault/cost
counterparts use `pyobf-native-untransformed-ownership` on their actual pre-CFF IR. This
read-only compiler pass records defined ordinary functions with no generated edges; it
claims no CFF protection and rejects prepared archive, bound/generated and transformed
inputs. The existing emitter then binds that receipt to the actual source IR and emitted
object. A fresh replacement parent proof is required when replacing a helper-selected
parent object; child proofs remain independently bound to their unchanged child. These
build artifacts remain inside the same trusted build boundary described above.

The existing paired bootstrap cost report records each variant's object hashes, ownership
manifest/compiler-report hashes and actual helper counts. Ordinary and protected parent
receipts can differ; fixed child provenance must remain identical across that pair. This
records the measured input scope, not a strength score or a claim of independent runtime
readers/caches merely from ownership metadata.

## Modules and checks

| File under `native/` | Responsibility |
| --- | --- |
| `llvm/cff/generated_ownership.{hpp,cpp}` | Read-only compiler edge export after existing transformation checks |
| `llvm/cff/untransformed_inventory.cpp` | Read-only compiler receipt for ordinary pre-CFF emission, refusing transformed/prepared inputs |
| `llvm/archive/source_report.cpp` | Actual per-source archive wrapper acquisitions |
| `tools/generated_ownership.py` | Typed graph, source/call obligations, bounded cycle check and closure traversal |
| `tools/function_inventory.py` | Private emission sidecar and exact independent-report/object correspondence |
| `tools/generated_function_subject.py` | Complete physical root/helper ranges and disjoint union |
| `cmake/LLVMCompile.cmake`, `cmake/ReferenceSlots.cmake` | Optional emission and existing finalization integration |
| `tests/measurement/generated_fixture.ll`, `generated_support.cpp` | Actual internal/external helper generation and execution |
| `tests/measurement/generated_archive.ll`, `generated_archive.py` | Real shared global archive wrapper, per-owner CNG captures and unsupported nested-adapter refusal |
| `tests/measurement/generated_slots.py` | Production emitter, IPO boundary, no-work and actual early-policy/data-only records |
| `tests/measurement/check_generated.py` | Native captures, execution, helper mutations, mixed epochs and ownership omissions |
| `tests/measurement/untransformed_cases.py` | Unchanged ordinary IR, actual zero-helper emission/CNG and transformed-input refusal |
| `demo/recipes/post_generated_functions.json` | Early parent/child complete-generated-function selection example |

The tests retain a root-only counterpart: damaging a generated helper leaves that root's
digest unchanged but changes the complete subject. Real native CNG captures must match the
changed canonical digest, and the original object/final-image proof must reject the damage.
Source none/O2 internal/external cases and a real archive shared by two source functions
exercise actual compiler outputs. Source execution is checked as well as hashing. Saved old
and new plugins can additionally prove byte-identical final IR on the same prepared inputs.
Current archive runtime boundaries exclude required nested call-frame adapters; their partial
failure report must contain no verified ownership or executable output. The graph traversal
supports transitive dependencies, while future producers still need their own actual tests.

Current integration covers POST-only source none, PRE+POST/source O2/archive/parent IPO/decoy
and outer-CFF-OFF with ordinary receipts. The actual O2 parent has 14 call-frame helpers
and 15 measured ranges; the actual archived child has six helpers and seven ranges.
Runtime fault checks damage every measured range and require the correct owner denial;
pre-key, phase/origin, normal/EH/reentry, cleanup/OOM, decoy and ordinary-source refusal
controls retain their existing contracts. Exact zero-helper receipts are also tested.

The actual six-pair complete-release measurement includes the following real scenario:

| Source | Plain/protected `.text` bytes | Plain/protected startup ms | Plain/protected retained-outer complete release ms |
| --- | --- | --- | --- |
| none | 57014 / 185590 | 36.617 / 37.438 | 35.929 / 39.512 |
| O2 | 54646 / 137766 | 35.550 / 35.264 | 37.006 / 38.279 |

The independently rebuilt protected parents own 13/14 helpers for these none/O2 inputs;
ordinary parents own zero. All twelve parent receipts differ appropriately, while every
pair retains the exact fixed six-helper child provenance. These machine/fixture-specific
warm medians include CNG, disk I/O, loading, observation, entry and cleanup. Noise/order
reversals do not establish speedup, a bound, an isolated body cost or protection strength.

Generated per-owner reader code/storage/cache independence, compiler/linker anti-merge,
remaining policy/source combinations, metadata freshness and full D5-D8 acceptance remain
open. This integration does not prove an arbitrary post-CFF optimizer or target backend.
