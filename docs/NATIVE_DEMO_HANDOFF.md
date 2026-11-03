# Demo owned handoff and cleanup

The constrained Windows demo creates an owned context before release, prepares its lifecycle
support and uses a version3 internal entry handoff. The exported outer
`pyobf_native_demo_run` signature stays unchanged. The demo-only inner entry no longer accepts
a legacy BootstrapApi table. This is not a stable ABI for arbitrary third-party DLLs.

## Ownership and execution

RuntimeSession owns heap RuntimeContext, owner/expected lease, the loaded-image handle and
the publication token produced by the inner runtime. The handoff borrows its expected lease,
generation, public routing tag, publication output and separate observer callback through one
synchronous entry. Routing tags are neither secrets nor exact build identities.
Version3 appends an optional borrowed post-observation view. The opt-in
[post-release profile](NATIVE_PAYLOAD_BINDING.md#opt-in-post-release-code-observations)
owns its two observers in RuntimeSession and its two invocation scopes in the child.

The inner publishes into the outer-owned token before notifying observers or running compute.
It has no local RAII token alive across observer calls. Actual Clang IR retains an ordinary
whole-CFF inner entry. The outer run and transient release function need exception cleanup
and use explicit Windows GNU hybrid-EH CFF. Exception edges keep partial-coverage accounting;
this is not full EH flattening.

Teardown closes context admission, waits for admitted frames, withdraws inner publication
while its image is retained, unloads the image, then releases/erases adopted state. Stage6
is emitted after unload while outer state still exists. Transient plaintext is erased on
every exit, including observer exceptions; success erases it immediately after loading and
before stage3. The currently executing SDK image must still be kept mapped by its caller
through method return. Context quiescence does not join arbitrary threads entering code
outside the declared entry contract.

## Lifecycle protocol and limits

Bounded POD requests carry the generation and public routing tag. Per-session atomic phases
allow created -> environment accepted -> support prepared -> payload entered -> retired.
Private accepting/preparing phases claim each update before publishing its completed fold.
Final publication uses CAS so a concurrent retirement cannot be overwritten. RuntimeContext
owns eight fold words; initialization, environment acceptance, owned preparation and release
update them through required CFF sites. See the [fold contract](NATIVE_PATH_FOLD.md).
Wrong version, malformed requests, wrong generation/tag, duplicate or out-of-order operations
and closed contexts fail. Release rechecks live prepared support before decrypting. Inner
entry uses strict expected-context publication with no legacy fallback. A clear environment
and an explicitly allowed unavailable result are admitted separately.

| Planned readiness claim | What this unit establishes |
| --- | --- |
| L0/L1 initialization | Static support and owned state before release; executable initialization/generation pairing |
| L2 back-validation/contribution | Opt-in startup parent-code observation; lifecycle/fold-only default does not measure code or authenticate device evidence |
| L3 application release | Live lifecycle gate, state-bound fold and masked-key reconstruction before real AES-GCM; local obfuscation only |
| L4 entry preparation | Version/generation/identity and strict publication; optional per-use parent/child code observations bind two later CFF roles |
| L5 teardown | Declared synchronous entry and admitted-frame cleanup; caller image lifetime stays separate |

Observer stages1-6 are notifications, not trusted readiness values. Host observer exceptions
now propagate at every stage through cleanup, rather than terminating implicitly through a
noexcept wrapper. Context dispatch stays noexcept and does not invoke observers. Tests use
host-owned exception types; arbitrary exception objects, exported objects or background
threads implemented by an unloading DLL need a separate loader ownership contract.
User TLS/global initialization and arbitrary export behavior remain excluded. The temporary
file replacement window and runtime key/plaintext extraction remain open. These mechanisms do not implement
machine authorization or the complete D6/D7 configured provider and independent-owner model.
Named outer-decoy variants retire real admission before constructing their separate fold and
image guard. The child receives only the distinct DecoyHandoff POD. Stages7-10 describe decoy
authentication/load/entry/unload; they do not replace real-payload stages1-6. See the
[decoy contract](NATIVE_DECOY.md). The [composition and cost guide](NATIVE_BOOTSTRAP_ACCEPTANCE.md)
lists the startup order, remaining measured-readiness requirements and release benchmark scope.

## Build and file map

The demo creates the context source target even when its standalone option is off. Inner
and outer compile context sources through their respective IR/request/CFF/native-object/final
pipelines. Shared backend sources compile once per image. Source O2 precedes CFF; transformed
code stays outside parent ThinLTO.

| Files | Responsibility |
| --- | --- |
| `native/demo/bootstrap/handoff.hpp` | Internal version3 ABI and bounded lifecycle message |
| `native/demo/bootstrap/flow.hpp`, `session.cpp` | Session state, adoption, close/drain/withdraw/unload/destruction |
| `native/demo/bootstrap/lifecycle.cpp`, `support.cpp` | Phase dispatcher and live preparation/verification |
| `native/demo/bootstrap/path_events.hpp` | Wrapper for private generated startup descriptors; local events are not device evidence |
| `native/demo/bootstrap/key_material.cpp` | Selected record validation, expansion from the actual fold, serialization erasure and key unmasking |
| `native/demo/bootstrap/buffer.{hpp,cpp}` | Macro-mediated allocation and erasure on all exits |
| `native/demo/bootstrap/{entry,config,environment,release,bridge}.cpp` | Main flow, settings, policy, decrypt/load and observer/handoff channel |
| `native/demo/payload.cpp` | Strict inner publication/admission and sample compute |
| `native/demo/cmake/{IrPipeline,Packaging,OuterPipeline,SessionChecks}.cmake` | Source collection, private plan/pack/raw/fill/final domains and regression wiring |
| `native/demo/session_{fixture.hpp,backend.cpp,crypto.cpp,common.cpp,protocol.cpp,smoke.cpp,fold.cpp}`, `session_fold_reference.py` | Observed allocation/loader shim, separately compiled production CNG, cleanup/protocol failures and private-plan fold checkpoints |
| `native/demo/{session_build.py,release_flow_mutations.py,release_fault_smoke.cpp,check_session_cff.py}` | Actual73-definition source/request/CFF/final-image and post-emission runtime fault execution |
| `native/demo/lifetime_smoke.cpp` | Real DLL exceptions/recovery, nested/four-thread sessions and mapped-image cleanup |

The ordinary inner reports49 selected definitions:2 user entries,5 base SDK and42 context
definitions; assets/archive helpers add separately accounted rows. Ordinary outer reports66:21
ordinary bootstrap,2 explicit hybrid,42 context definitions and1 source derivation. OS backend implementations
and compiler-generated helpers are not credited by those counts. The73-definition fault
suite uses production CNG with observed allocation and loader shims; it checks serialization
and transient key erasure before observer callbacks. Real encrypted DLL smoke/lifetime tests
exercise the production loader separately. See the [release evidence](NATIVE_RELEASE_RECORDS.md)
for the bounded altered-flow cases and the remaining authorization/loader limits.
