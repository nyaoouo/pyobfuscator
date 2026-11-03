# Native typed archive runtime

This D3 data-protection implementation includes the opt-in source runtime target
`pyobf_native_archive_runtime`. It provides a typed AES-256-GCM pool, strict packaging,
stable caller-owned storage and per-record publication. An LLVM planning pass now collects
admitted user constants into a private plan and pending intermediate IR. A materialization
pass verifies generated wrappers and binds the pool to the registered `constant-archive`
component, which reconstructs access keys from actual CFF states. The opt-in demo CMake
pipeline orchestrates these stages, including deterministic binary assets and ordinary O2
before archive planning. The paired cost target below quantifies the scoped implementation;
later bootstrap/oracle coupling and additional backends remain separate work.
The CMake helper accepts `INPUT_BACKEND_SOURCES` for backend operation sources already compiled
into its input IR. It omits only those shared backend sources from the archive runtime phase;
archive core and generated wrappers remain compiled there. Demo and mixed SDK/archive builds
pass the actual SDK backend source list, so shared atomic definitions are linked once.
When no records are collected, optional or disabled scopes use a no-pool compiler handoff.
Required scopes with no eligible data or lost required requests still fail. Empty runtime
pools remain invalid; the handoff generates no dummy records or claimed acquisitions.

## Build and packaging

The Windows user-mode backend supplies the current implementation. Both MSVC and MSYS2
CLANG64 can compile the C++17 runtime; the LLVM/CFF integration check additionally requires
the CLANG64 plugin toolchain. The base SDK does not enable this target or add a cryptography
dependency. With smoke tests enabled, fixtures require `cryptography` in the selected Python
interpreter. No package is installed by configuration.

```powershell
$python = (Resolve-Path '.venv/Scripts/python.exe').Path
cmake -S native -B build/native-archive `
  -DPYOBF_NATIVE_BUILD_ARCHIVE_RUNTIME=ON `
  "-DPython3_EXECUTABLE=$python"
cmake --build build/native-archive --config Debug
ctest --test-dir build/native-archive -C Debug --output-on-failure
```

As a subproject, enable the same option before `add_subdirectory` and link the source target
into the consuming target. It compiles the runtime and backend sources in that target; no
prebuilt archive library or public C adapter is distributed. A backend without
`PYOBF_NATIVE_BACKEND_CAN_ARCHIVE` and its source list fails configuration when requested.

### Demo CMake pipeline and binary assets

For the existing Windows CLANG64 demo configuration, enable the archive pipeline separately
from the source-runtime smoke target:

```powershell
$python = (Resolve-Path '.venv/Scripts/python.exe').Path
$asset = (Resolve-Path 'native/demo/recipes/archive.json').Path
cmake -S native -B build/native-clang64 `
  -DPYOBF_NATIVE_BUILD_LLVM_PASS=ON -DPYOBF_NATIVE_BUILD_DEMO=ON `
  -DPYOBF_NATIVE_DEMO_ARCHIVE=ON -DPYOBF_NATIVE_CFF_SOURCE_OPT=O2 `
  "-DPYOBF_NATIVE_DEMO_ASSET=$asset" `
  "-DPython3_EXECUTABLE=$python"
cmake --build build/native-clang64
ctest --test-dir build/native-clang64 --output-on-failure
```

Keep the matching compiler/LLVM/Ninja configuration described in [Native setup](../native/README.md).
The bundled recipe file is used only as a portable sample asset; replace `$asset` with any
binary file whose bytes the demo should embed.
`PYOBF_NATIVE_BUILD_ARCHIVE_RUNTIME=ON` additionally enables standalone runtime and compiler
regressions. It is not necessary for the demo's private helper compilation. The pipeline
requires backend archive capability and marked SDK selection. An asset without the pipeline,
an absent input, an invalid optimization mode or disabled SDK markers fails configuration.

When no user recipe is supplied, `demo/recipes/archive.json` explicitly selects the baseline
recipe plus optional `constant-archive` for user-marked functions. This replaces the demo's
legacy deep default for those functions. SDK support receives baseline CFF without archiving
its own constants, avoiding a recursive decoder dependency. Supply a versioned configuration
for finer function/marker policies. Optional mode reports original sites removed by ordinary
O2; required sites removed by O2 reject the build. The pipeline does not downgrade required
policies to accommodate optimization.

`cmake/LLVMCompile.cmake` preserves common compiler flags, target/sysroot/toolchain arguments
and header depfiles. `demo/cmake/IrPipeline.cmake` collects original source requests before
`none` or `default<O2>` ordinary optimization. `cmake/ArchivePipeline.cmake` owns plan, pack,
helper compilation and request collection, strict request merging, linking and materialization.
The final CFF module becomes a native object with `-O0 -fno-lto`, so parent IPO does not
reoptimize the sealed module. Final-image verification still precedes outer payload packing.
This is the scoped Windows demo integration, not a validated arbitrary post-CFF LTO pipeline.

The demo asset option generates private `assets/asset_sample.{hpp,cpp}`. Consumers use:

```cpp
#include "assets/asset_sample.hpp"
const auto bytes = pyobfuscator::native::assets::get_sample();
// bytes.data / bytes.size describe immutable module-owned storage.
```

`cmake/Assets.cmake` also exposes `pyobf_native_embed_asset(source header ID sample FILE ...
DIRECTORY ...)` for a consuming build. Compile the generated marked source with the user
module, add the generated directory to its includes, and link `src/archive/asset_identity.cpp`
through `EXTRA_RUNTIME_SOURCES` in the archive helper. During ordinary optimization its
identity declaration must remain opaque. Linking the implementation afterward prevents IPA
from exposing the original initializer through a constant-return accessor; `noinline` alone
would not establish this property. All helper definitions exist before final CFF states.

Asset generation is deterministic for the same ID and bytes; encryption still uses fresh
entropy. IDs use 1-64 lowercase identifier characters and each input is limited to 16 MiB.
Empty assets have logical size zero and one private sentinel byte for portable C++ storage.
Views keep module lifetime and do not read the original file at runtime. Generation alone
provides no protection: the marked source must traverse archive planning, materialization
and final CFF. Generated plaintext C++/IR, private plans, bindings and source maps stay in the
private build tree. Only protected final images are distributable artifacts.

The shared-helper CMake regression uses Ninja with the existing plugin and matching compiler,
ordinary O2 and parent IPO. It checks binary reads before/after caching, source removal,
changed-input generation/package/image rebuilds, unchanged-input stability, empty files and
missing-input errors. It also checks source/helper request coverage, raw key/selected-byte
absence and lost-source required rejection in the actual linked DLL. The demo asset test
checks its own exported reader against the configured input. It does not delete that input.

The standalone build tool accepts a private schema-1 plan:

```json
{
  "schema_version": 1,
  "records": [
    {"id": "message", "kind": "code_units8", "bit_width": 8,
     "alignment": 1, "byte_order": 0, "data_hex": "41424300"}
  ]
}
```

```powershell
.venv/Scripts/python.exe native/tools/pack_archive.py `
  build/plan.json build/archive.bin build/archive.cpp build/archive.bindings.json
```

The output pool and generated C++ contain ciphertext, authenticated metadata and a distinct
cache/wrapper per record. The bindings file contains raw keys and plan/package hashes; it
and the plaintext plan are private build inputs, never distribution artifacts. Test headers
also contain known keys and expected plaintext solely for verification. Calling generated
wrappers without compiler materialization requires supplying their record keys;
compiler materialization plus final CFF supplies protected
per-site key frames. Generated C-linkage wrapper names are private compiler handoff symbols,
without explicit DLL exports, and are internalized after verification.

## Compiler planning handoff

The LLVM plugin also registers `pyobf-native-archive-plan`. Run it after ordinary source
optimization and before final CFF, using the same explicit function/marker/config selection
options as CFF. Select whole functions or the explicit x64 Windows GNU `hybrid-eh` profile;
regions remain unsupported. A concrete target data layout with 32-bit or 64-bit pointers
is required. Hybrid planning retains landingpad/resume, exception type-ID and declared GNU
exception-runtime type-info operands as ABI control data. Such operands create no archive
requests; sharing a constant object's address between ordinary data and EH control uses
rejects the data plan. Normal and post-landingpad consumers retain the existing state-key
and source/context restrictions. Example, using a previously built plugin:

```powershell
opt.exe -load-pass-plugin=build/native-e2e-clean/llvm/pyobf_native_cff.dll `
  -passes=pyobf-native-archive-plan -pyobf-cff-functions=f -pyobf-cff-markers=false `
  -pyobf-archive-plan-output=build/constants.plan.json `
  -verify-each -S build/source.ll -o build/payload.pending.ll
```

`constants.plan.json` uses the packer's existing private schema; it contains plaintext raw
bits. The intermediate IR records its exact SHA-256 and per-record storage/pending-symbol
mapping. Both are private build artifacts. Do not optimize or distribute this intermediate
as a finished program. It deliberately references unresolved acquisition gates and contains
zero-initialized key-frame slots. Final CFF, request collection and repeated planning reject
pending output, including a no-record plan. Materialization is required; manually supplying
a pending symbol is not a supported replacement for that stage.

The collector discovers immutable global references through constant expressions/aggregates
and follows every address-use path to selected executable instructions. A global requires
local defined storage, default address space and no TLS, explicit section, COMDAT or external
initialization. An unselected use, global-initializer escape or alias rejects the plan.
Inline/module assembly also prevents the closed-use proof. Mutable program globals are
outside this constant collector. Known constructors/destructors and Windows loader entries,
including statically visible direct-call descendants, cannot initiate acquisition. Opaque
early callbacks remain outside the accepted integration profile; this is not a loader
readiness certificate. Existing CFF source restrictions, including EH/coroutines, still apply.

Admitted scalar integers/floats and fixed arrays are serialized using target store size,
allocation stride and byte order. Unrepresented allocation padding becomes zero; it is not
invented source data. Structures, vectors, pointer-valued storage, double-double, undef/poison
and zero-stride arrays are rejected. Immediate data operands become loads from private typed
zero storage; fixed GEP/alloca/switch-case/intrinsic-immediate operands, inline-assembly
arguments and constant-reflection intrinsic operands are not collected as data. Local globals
retain their exact object/type/alignment and receive writable zero
initializers. Equal records are not merged. Empty objects stay distinct plan records.

Each source exposure gets a pending gate and an entry-allocated private 32-byte key frame,
with eight tagged volatile word slots and subsequent volatile clearing. PHI operands prepare
on their predecessor before the existing terminator; no control-flow edges are added.
The source ID, record ID and lane index survive as planning metadata, without raw keys.
Because decoding adds writes, crypto and synchronization, the pass conservatively removes
inferred purity promises from module definitions/non-intrinsic call sites and removes
invariant-load/group metadata. Ordinary optimization must precede this handoff.

The plan test checks these properties with `opt -verify-each`, exact raw integer/FP/code-unit
bits and actual packer consumption, including 32-bit gate sizes and big-endian padded
integers. Those layout checks do not establish execution on another target. The additional
protected-DLL test exercises materialization, user lifetime/recursion/concurrency, state-key
tampering and scoped static-data absence. Separate CMake/O2 and paired cost evidence below
extend that fixture. The separate empty-plan regression covers the no-pool phase path below.

### Empty compiler plans

Planning may produce schema-1 `records: []` when selected scopes have no admitted data, all
archive policies are off, or ordinary O2 removes the archive candidates. Planning then adds
only its private phase/inventory metadata; it preserves original purity attributes and does
not create storage, key frames or acquisition gates. An empty byte asset is different: its
existing logical-size-zero/sentinel-backed storage still becomes a real protected record.

The standalone packer and `seal()` retain their default nonempty-pool contract. Compiler
orchestration explicitly uses `pack_archive.py --allow-empty-plan`: for zero records it
writes a zero-byte bookkeeping `.bin`, a comment-only C++ source, and private bindings with
zero records, an all-zero archive identity and SHA-256 of the empty byte string. This is no
runtime pool, contains no keys/caches/wrappers, and is never passed to runtime acquisition.
Nonempty plans use exactly the existing v1 pool format and fresh entropy.

`llvm/archive/empty_plan.cpp` validates the original plan hash through the normal handoff, exact
zero record count/canonical no-pool identity, empty source inventory and absence of reserved
archive objects, function attributes or key/acquisition metadata. A zero-record bindings file
cannot materialize a nonempty pending plan. The empty result retains paired prepared/empty
phase flags: recollecting requests or replanning it is rejected, preserving original request
history until final CFF. Preflight and completion revalidate its contents; successful final
CFF removes the flags and inventory. The fixed CMake DAG still compiles its backend support
units, but it generates/acquires no pool or per-record objects for this path.

An original identity/void function with optional archive policy therefore executes normally
and reports zero eligible/applied archive sites. An archive scope with all data optimized
away keeps its original source rows as `optimized-away`, with zero acquisitions. Required
no-data scopes fail the zero-eligible gate; required lost requests fail original-source
coverage. Disabling every archive scope is an explicit no-op, not credited protection.

The executable and actual CMake/O2/parent-IPO regression verifies those cases, default packer
empty rejection, forged empty bindings against nonempty IR, stray archive objects/key tags,
bad inventories/phase flags, request/replan boundaries and final private-metadata removal.

## Materialization, state binding and source coverage

Enable `constant-archive` per source function in the versioned recipe configuration. With a
configuration file, planning collects only archive-enabled scopes. When `integer-literals`
is also enabled, direct integer operands stay with that component; integer-valued globals
can still use archive storage. A required component with no eligible data fails, so use
per-function overrides or optional mode for functions with only scalar literals.

The explicit build order is:

```text
source request collection -> ordinary source optimization -> archive plan -> Python packer
  -> compile runtime/generated C++ to matching target IR -> helper request collection
  -> merge source/helper requests + llvm-link with pending user IR
  -> archive materialize -> final CFF -> native object -> link -> final gate
```

All linked modules must use the same target triple, data layout and C++ ABI. Compile helpers
with source markers and without `optnone`; do not optimize the pending user module after its
data rewrite. Collect source CFF requests before planning using the same effective recipe.
Collect helper requests on their separate module before materialization, then merge them
with the original source requests. Collection after materialization is rejected. For example,
after generating the pool and compiling/linking helpers:

```powershell
opt.exe -load-pass-plugin=build/native-e2e-clean/llvm/pyobf_native_cff.dll `
  -passes=pyobf-native-archive-materialize -pyobf-archive-bindings=build/archive.bindings.json `
  -verify-each -S build/linked.pending.ll -o build/prepared.ll
opt.exe -load-pass-plugin=build/native-e2e-clean/llvm/pyobf_native_cff.dll `
  -passes=pyobf-native-cff -pyobf-cff-config=build/recipe.json `
  -pyobf-cff-requests-input=build/requests.json -pyobf-cff-report=build/coverage.json `
  -verify-each -S build/prepared.ll -o build/protected.ll
```

Materialization validates bounded private JSON, exact plan/package identity, canonical
descriptors, target storage/type/size/alignment, wrapper ABI and its actual require-call
arguments. It promotes only wrapper parameter slots to inspect their data flow. Each record
must use its own zero-initialized private cache and original destination. Verification follows
actual package bytes and call operands, rather than trusting wrapper names alone. The linked
require implementation must carry its SDK marker. All marked SDK support and archive owners
must be selected for final CFF. No C++ cache layout is guessed from LLVM.

Prepared IR temporarily holds raw key words in private metadata and is not distributable.
The independent `archive` mask domain binds eight volatile word stores per acquisition to
their actual body states and site/lane salts. Splitting can place these stores in different
bodies; each then uses its own expected state. Volatile clearing remains unconditional zero,
outside literal hiding. Final CFF rejects incomplete source/gate/frame/lane/clear bindings
and removes raw key metadata and private source inventory before emitting the result.

Physical component coverage counts eight key lanes plus one acquisition per prepared gate.
The separate per-function `archive_sources` report counts original operand requests and
acquisitions; it credits a source only when every associated acquisition is complete. A
private map links each original source location to all nine physical site IDs and their
normal transformed-IR entries. This keeps pre-optimization requests distinct from generated
work. Required lost source requests fail instead of being credited by unrelated key lanes.
The x86 final gate checks retained archive-mask multiplicity and source/lane consistency,
not individual-site machine-code equivalence.

The DLL fixture compares plain/protected exports, races cold acquisition on 12 threads,
checks recursion and pointer/storage stability, and reruns with splitting, common exits,
deduplication, indirect calls and scalar hiding. It rejects malformed manifests, pool
tampering, cache reuse, missing lanes and unselected support. Wrong keys and corrupted
state-dependent decoding stop before a consumer sentinel, including after a valid path
has warmed the same record's cache. Selected original data and full raw AES keys are absent
from that protected DLL. These are scoped Windows CLANG64 checks, not a general static-data
proof for arbitrary programs or trusted host attestation.

## Paired size, build and access costs

Run the opt-in measurement target on the matching Windows CLANG64 demo toolchain:

```powershell
cmake --build build/native-e2e-clean --target pyobf_native_demo_measure_archive
```

It writes `demo/payload.archive.measurements.json` in that build directory. The report binds
the workload and LLVM plugin hashes, records the compiler version, and compares plain,
CFF/scalar-only and CFF/scalar/archive inner DLLs with one public CFF seed. Ordinary source
optimization is separately `none` or O2. Helpers are freshly compiled for each archive
variant; build time includes request collection, ordinary optimization, plan/pack, helpers,
materialization, CFF, native link and final-image gates, excluding the user-source frontend,
LLVM plugin build and outer bootstrap/packing. Phase times identify the fixed helper cost.

The harness checks all 64 source bytes, stable pointer identity and typed results for inputs
-64 through 64 against an independent host reference. First use measures one compute call
after load, before cache warmup. Startup includes load, that first call and unload. Full
validation is outside timed intervals. Cold samples alternate image order 21 times; hot
medians use seven alternating batches of 3000 calls after validation/warmup. Warm hits still
authenticate each acquisition. A zero plain first-call median is reported as below observed
clock resolution, never interpreted as a zero-cost guarantee. Different images must resolve
to distinct module instances.

One isolated run on this machine recorded:

| Ordinary optimization | Plain / CFF / archive `.text` bytes | CFF / archive build seconds | Archive records / acquisitions |
| --- | --- | --- | --- |
| none | 4822 / 5302 / 35494 | 0.498 / 3.886 | 5 / 6 |
| O2 | 4774 / 5238 / 31286 | 0.547 / 3.795 | 1 / 2 |

| Ordinary optimization | CFF / archive startup microseconds | CFF / archive first-call microseconds | CFF / archive warm nanoseconds per call |
| --- | --- | --- | --- |
| none | 230.3 / 259.3 | 0.1 / 31.3 | 6.63 / 7298.4 |
| O2 | 212.8 / 250.1 | 0.1 / 15.8 | 6.00 / 1471.57 |

Archive file sizes were 101888 and 96768 bytes, against the CFF-only 64000-byte images.
Helper compilation consumed about 2.34 seconds in both archive profiles. O2 folded the wide,
integer and raw-FP globals into scalar literals, leaving the 64-byte blob in the archive;
the common scalar component protects those folded integers. The reports expose the changed
record/acquisition denominator rather than imply equal runtime archive work.
Those static acquisition counts include the pointer getter; the timed compute call executes
five acquisitions without ordinary optimization and one with O2.

These are tiny-workload Windows observations with warm OS/dependency caches. The high hot
ratios against a few-nanosecond CFF-only function show why archive acquisition remains opt-in;
they do not predict application throughput or security strength. Fresh random keys and
ordinary codegen can also change exact image sizes across runs. Large-record compiler scaling
is not established by this workload; repeated marker/source-inventory scans remain a known
follow-up. No runtime authentication is skipped to improve these numbers.

## Types and format

Metadata is canonical little endian; typed payload bytes retain their declared target memory
order. The runtime copies storage bits without floating-point conversion or Unicode decoding.

| Kind | Admitted storage |
| --- | --- |
| `integer` | i1-i128, at least the required bytes and at most 16, including explicit padding |
| `binary16`, `bfloat16`, `binary32`, `binary64`, `binary128` | Exact 2/2/4/8/16-byte representations, preserving NaN payloads and signed zero |
| `x87_80` | 10-16 bytes, preserving explicitly supplied storage padding |
| `bytes` | Arbitrary bytes, including empty records |
| `code_units8`, `code_units16`, `code_units32` | Complete units including a trailing zero unit; embedded zeros and unpaired code units are preserved |

Use byte-order 0 for raw bytes and 8-bit code units, 1 for little-endian typed storage and 2
for big-endian typed storage. A typed record with a different native order is rejected;
there is no implicit byte swap. Alignment is a power of two from 1 through 4096. The format
limits are 65536 records, 16 MiB per record and 64 MiB per pool; a pool cannot be empty.

Version 1 has a 40-byte header (magic `PYOBFAR1`, version, count, random archive identity,
total size), followed by 96-byte descriptors and contiguous ciphertext. Each descriptor has
a 40-byte core (index, kind, width, alignment, size, offset, byte order, reserved zero), a
12-byte body nonce, 16-byte body tag, 12-byte access nonce and 16-byte access tag.
Every record has an independent random 32-byte key; its two nonces differ. Public CFF seeds
do not generate these cryptographic keys.

The body authenticates `pyobf-native-archive-body-v1 || header || core`. An empty-message
access tag authenticates `pyobf-native-archive-access-v1 || header || core || body_nonce ||
body_tag`, under the same record key and its other nonce. Header/type/index/size substitutions
therefore fail the accessed record's verification. Empty neighbors sharing an offset still
have different identities, keys and caches. The parser bounds-checks before accessing a
descriptor or body. It validates the requested record, rather than scanning every other
record on each acquisition.

## Storage, lifetime and failure

`archive::acquire_record` is an internal source interface. Supply live, adequately aligned
destination storage, a live noncopyable `Cache`, a live immutable package and a 32-byte key.
Destination storage must not overlap the package or cache. The first successful acquisition
binds package pointer/size, record index, destination pointer/capacity for the cache lifetime.
Keep all these objects alive for the module instance; use exactly one cache per destination.
Do not supply ephemeral stack storage to a module-lifetime cache or reuse it after unload.

The winning thread transitions sealed -> decoding -> ready with backend acquire/release
atomics. Other threads wait for complete publication; ordinary user recursion after
acquisition can reuse the same object. Decoder callbacks and recursive decoder dependencies
are unsupported. Loading under loader lock or early initialization is not validated. The
runtime neither allocates replacement data storage nor changes its address or capacity.
The planning pass preserves original LLVM globals and checks their use closure; verified
materialization and state-keyed CFF gates prepare them before user consumption.

Every acquisition verifies the access tag, including ready-cache hits. A wrong key before
first use leaves the cache sealed; a wrong later key cannot bypass verification through the
ready state. Body authentication/termination failure wipes output and leaves a terminal
failed cache. There is no reset or automatic rebasing. `acquire_record` returns a specific
status; `require_record` and generated wrappers invoke the backend's terminal failure path
before the caller may consume data. On Windows this terminates the process.

Published plaintext and package bytes must remain immutable. A hit verifies its access tag
but does not re-decrypt or re-observe ciphertext body bytes, nor scan the ready plaintext for
modification. This cache is not an ongoing code/data integrity monitor. Local key concealment,
hostile runtime replacement, dumping and device authorization remain separate boundaries.

## Module and backend extension points

`tools/archive_format.py` owns types and strict plan validation; `tools/pack_archive.py` owns
entropy, AEAD sealing and source/private-binding generation. `src/archive/format.{hpp,cpp}`
owns bounded parsing and typed plaintext validation, `runtime.hpp` owns storage/status types,
`acquire.cpp` owns verification/publication, and `require.cpp` owns the fail-before-use wrapper.
`archive/CMakeLists.txt` defines their source target.

All runtime system operations use `system_ops.hpp` semantic macros. A backend supplies
explicit-AAD AEAD decrypt, lock-free 32-bit atomic load/CAS/store, pause, byte-order, memory
erase/allocation/release and terminal failure. Windows implementations live separately in
`operations/{crypto,atomic,archive_support,memory}.cpp`; the existing payload decrypt wrapper
retains its original AAD. The portable stub and template declare archive capability false.
No kernel, TPM, detector or executable-memory loader is added here.

Runtime/tool tests cover bit-exact data, empty records, alignment/order/bounds, type and tag
tampering, wrong keys before/after ready, cache ownership, concurrent first use and recursive
user access. The require-failure child must exit before a data-consumer sentinel. On CLANG64,
the CFF fixture compiles the actual runtime and generated wrappers to IR, checks their marker
coverage, transforms and links them, then reruns both functional and failure checks and the
scoped linked-code gate. Additional compiler/CMake tests prove selected automatic collection
and selected-byte absence for their fixtures. They do not establish absence of all plaintext
in arbitrary final distributions or confidentiality after runtime acquisition.

## Selected O2 PE publication check

The optional `PYOBF_NATIVE_DEMO_G3_O2_PREDECESSOR` gate first freezes the
requested IR, optimized IR and optimizer executable after the O2 output is
built. Finalization replays the exact `default<O2>` optimizer command from a
snapshot, normalizes only LLVM's temporary first-line ModuleID, and joins
both optimized IR and tool paths and bytes to the fixed archive-origin
record. A main seed-692 joint product and dedicated CTest pass; changed
input/tool/command and same-byte wrong-path/hardlink negatives refuse. This
record does not prove C++ source-to-IR provenance, optimizer DLLs or a
publisher signature.

The demo's optional `PYOBF_NATIVE_DEMO_G3_ARCHIVE_PUBLICATION` gate runs after
the fixed child replay and archive-origin record. For one supported Windows
x64 PRE+POST/O2 emitted layout, it checks the exact COFF-to-PE archive wrapper
calls, six writable and separate output/cache regions, the two published
predicate reads, compare inputs and control-flow entrances. All six wrapper
frames and 21 owner call targets are part of this selected static proof.
The full finalizer validates mixed POST helper routes before this gate; its
standalone checker assumes those helpers return normally. Both observed
seed-248 and seed-692 predicate orders pass; other layouts fail closed.
The seed-692 layout also passes with binding-status and context-availability
effects enabled. The check does not prove `require_record`/`acquire_record`
decoder effects, the ready-cache plaintext after modification, complete original
predicate equivalence or the bytes actually loaded at runtime.

The further optional `PYOBF_NATIVE_DEMO_G3_O2_ORIGINAL_PREDICATES` gate joins
the selected wrapper's requested `ne` condition to its O2 `eq` inversion,
archive-prepared IR, exact PE comparison operands and encoded allow/deny
successors. It combines that route with the two already proven compute
conditions, for three selected original predicates in the seed-692 product.
Actual paired COFF/PE register, CFF state-slot and frame changes pass the
preceding publication proof but fail this gate. The main joint finalizer and
focused CTest pass. It does not prove observation/callback/decoder effects,
general O2 equivalence or runtime loaded bytes.

The further optional `PYOBF_NATIVE_DEMO_G3_ARCHIVE_DECODER_LINKAGE` gate
checks the selected `require_record -> acquire_record` target and acquire's
three parse, access-check and decode call sites against COFF relocations,
raw PE calls, local Win64 arguments and frame/return routes. The actual
seed-692 O2/archive worktree product passed archive-origin, publication and
decoder-linkage CTests 3/3. Paired wrong-target/argument, stack restoration,
captured-slot alias and protected-instruction-interior edits refuse. The
report keeps acquire inter-state reachability, decoder/cache effects and
platform cryptography false; those still need separate proofs.

The further optional `PYOBF_NATIVE_DEMO_G3_ARCHIVE_FIRST_USE_ARM` gate proves
only the selected conditional state-zero/CAS/decode-result/failure-erase/
state-publication route in the linked seed-692 Windows x64 DLL. Its exact
COFF call relocations and PE targets, body transitions and return route
reject paired old-decoder-admitted machine changes. The worktree finalizer
and four affected CTests passed; main reran the focused actual-product test.
Normal reachability from `acquire_record` entry, cache contents after a
ready hit, platform crypto/atomic effects and destination integrity remain
unverified.
