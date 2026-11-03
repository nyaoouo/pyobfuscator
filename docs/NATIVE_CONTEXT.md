# Owned bootstrap context runtime

The optional `pyobf_native_bootstrap_context` CMake INTERFACE target compiles context sources
inside the consumer. Enable `PYOBF_NATIVE_BUILD_CONTEXT_RUNTIME=ON` before adding `native/`.
This additive C++17 API keeps the `BootstrapApi` v1 source interface. That legacy endpoint
now copies its descriptor while userdata/code remain borrowed. The optional strict endpoint
uses owned context leases and a scoped token. The demo now uses the owned handoff for
lifecycle pairing and cleanup. Path-bound key release and measured readiness remain separate
work. A live context provides resource lifetime, not authorization.

```cpp
#include "pyobfuscator_native/bootstrap_context.hpp"
using namespace pyobfuscator::native;

BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *) noexcept {
    return {BootstrapContextStatus::ok, request.operation_id};
}

// Stateless callbacks may omit userdata and destroy. Non-null userdata requires destroy.
auto created = create_bootstrap_context({bootstrap_context_abi_version, dispatch});
if (created.status == BootstrapContextStatus::ok) {
    auto lease = created.owner.lease();
    auto result = lease.invoke({17});
    created.owner.close();
    // New calls on this lease now return closed; reset releases its cleanup ownership.
    lease.reset();
}
```

## Ownership and threading

Creation adopts userdata only on success. The caller retains it after any validation,
allocation, code-provider or generation failure. Callbacks and destruction are `noexcept`;
throwing, nonlocal escape and retaining a request's borrowed input are unsupported. Inputs
are bounded to 65536 bytes and a nonzero size requires a non-null pointer. The caller keeps
the actual input bytes valid for the synchronous call. Results expose a status and numeric
word; this API does not automatically expose keys or establish trust in callback results.

The move-only owner and copyable leases share a private control block. Each admitted call
holds a separate frame reference, so the callback may close/reset its owner and invoking
lease without destroying its own state. Close is irreversible and never waits: `busy` means
an admitted call remains, `ok` means it was quiescent at observation. Both close admission.
`quiescent()` is an observation; it does not replace the loader's synchronization contract.
Old leases may retain closed state for cleanup but cannot reopen it. Final destruction and
provider releases occur exactly once after all handles and frames are released, outside
context locks. Counter exhaustion fails explicitly rather than wrapping.

Distinct handles may be used concurrently. Concurrent mutation/destruction of the **same**
owner or lease needs caller synchronization, as with ordinary C++ objects. Userdata access
inside simultaneous callbacks also needs the application's synchronization. Generation is
scoped to the live factory/runtime instance; it is not a cryptographic or process-global
identity and is not a standalone serialized handle. Handles may only cross modules built
with the same runtime ABI, backend and compatible allocation domain.

## Backend and code lifetime

The first implementation is `windows_user`. The capability is explicit:
`PYOBF_NATIVE_BACKEND_CAN_CONTEXT` plus `PYOBF_NATIVE_BACKEND_CONTEXT_SOURCES`. The stub and
backend template reject this optional runtime until they supply the operations. Legacy
SDK-only builds gain no new context dependencies. Memory, atomic/pause, failure and code
reference operations pass through `system_ops.hpp` macros. Context and archive source
targets can be consumed together without duplicate backend definitions.

The Windows backend retains ordinary loader references by the actual dispatch/destructor
addresses with `GetModuleHandleExW(FROM_ADDRESS)` and balances them after destruction returns.
It does not permanently pin modules. Unsupported/JIT/unregistered code returns
`code_unavailable`. These references protect callback lifetime, not authenticity or arbitrary
transitive dependencies. See Microsoft's [GetModuleHandleExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)
and [FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary)
contracts.

The caller/loader must separately keep the currently executing SDK implementation image
mapped until its method returns, including a destructor's final releases. Do not use context
creation, publication, destruction or unloading under `DllMain`. This API does not make releasing one's
own final executing-code reference safe and does not own arbitrary memory supplied by code
that was never registered.

## Scoped publication and expected identity

Include `bootstrap_binding.hpp` and call `bind_bootstrap_context(lease)`. A successful result
owns a move-only `binding` token; its destruction or `reset()` withdraws that publication.
There is one endpoint per consuming runtime/module. Other contexts still have independent
direct leases. A second bind returns `busy` until the token resets, including when the
published context has closed. Failed retain or serial exhaustion leaves the endpoint empty.
The token also records its actual origin registry. When moved across compatible modules,
reset withdraws that origin even if another endpoint has the same serial. Publication owns
an ordinary code-provider reference to the registry's module until withdrawal and state
cleanup finish. A registry holding callbacks from another module still owns its own lifetime.
This idle module reference does not replace the executing-SDK-image lifetime rule above.

```cpp
#include "pyobfuscator_native/bootstrap_binding.hpp"
auto scope = bind_bootstrap_context(lease);
if (scope.status == BootstrapContextStatus::ok) {
    auto result = call_bound_bootstrap(lease, {17});
    scope.binding.reset();
}
```

Each strict call supplies an expected lease, and the endpoint compares the actual context
identity. Numeric generations can collide across source-built runtime instances and cannot
replace this identity. A live expected lease prevents reuse of its storage. Missing,
closed, mismatched or reference-exhausted contexts return explicit failure; the endpoint
never reads or falls back to the legacy slot. Binding/unbinding a legacy table does not
replace or remove a strict publication.

Calls capture a retained lease under the publication lock, then invoke and release outside
it. A call captured before reset may finish. Reset prevents later captures; `owner.close()`
separately stops context admission, including direct `lease.invoke()` calls. A token clears
its own old fields before cleanup, so a destruction callback may publish another context
without stale reset removing it. No callback or final destruction runs under a publication
lock. Loader/caller synchronization still keeps executing SDK code mapped through return.
Publication status is lifecycle state, not measured readiness or key authorization.

## Files and validation

| Files | Responsibility |
| --- | --- |
| `native/include/pyobfuscator_native/bootstrap_context.hpp` | Public descriptor, status, owner and lease API |
| `native/include/pyobfuscator_native/bootstrap_binding.hpp` | Scoped publication token and strict endpoint declarations |
| `native/src/context/runtime.hpp` | Private immutable callbacks/providers and synchronized lifecycle state |
| `native/src/context/synchronization.cpp` | Backend-mediated locks and bounded generation allocation |
| `native/src/context/factory.cpp` | Validation, partial acquisition cleanup and adoption on success |
| `native/src/context/owner.cpp` | Move-only ownership, admission close and quiescence |
| `native/src/context/lease.cpp` | Copy/move/reset and retained closed-state lifetime |
| `native/src/context/call.cpp` | Request bounds, active frame admission and callback completion |
| `native/src/context/lifetime.cpp` | Reference bounds, final state destruction and provider release |
| `native/src/context/publication.{hpp,cpp}` | Private endpoint, bounded publication serial, retained publication and withdrawal |
| `native/src/context/binding.cpp`, `native/src/context/bound_call.cpp` | Move-only scope lifecycle and expected-identity call capture |
| `native/backends/windows_user/operations/code_lifetime.cpp` | Address-based Windows loader references |
| `native/context/CMakeLists.txt`, `native/context/Checks.cmake` | Optional source target/capability and scoped CFF checks |
| `native/tests/context/{lifecycle,concurrency,module,provider,failures}.cpp` | Adoption/close/reentrancy/thread/actual DLL unload and isolated failure-backend tests |
| `native/tests/context/binding_{smoke,reentrancy,concurrency}.cpp` | Actual equal cross-DLL generations/serials, origin registry/provider lifetime, no fallback/replacement, callback/destructor rebind and in-flight withdrawal |
| `native/tests/context/{check_cff,cff_build}.py` | Actual source/request/CFF/object flow, runtime contracts and exact final-image evidence |
| `native/tests/sdk_snapshot.cpp` | Legacy descriptor mutation/expiry, complete concurrent snapshots, reentrancy and caller-owned in-flight lifetime |

All 42 authored core definitions carry SDK CFF markers. The scoped CLANG64 tests combine
them with the actual five SDK definitions, collect requests before optional source O2,
emit an O0 non-LTO object and execute lifecycle, publication/provider and legacy snapshot
contracts. A separate core-only CFF object runs the isolated failure backend, including
reference/publication serial exhaustion and exact cleanup. Each executable has its own
linked image/report digest check. A same-source unprotected image fails the linked gate.
Shape-only helpers retain that accounting;
backend OS operations and unmarked support are not credited as protected. Arbitrary later
optimization, other platforms and demo readiness integration are not covered by these tests.
Clang constructor/destructor aliases resolve to their underlying function definition for
source-marker selection. Duplicate aliases do not count as additional protected functions;
marked data objects still fail selection.
When the parent enables CMake IPO, the test compiles/links its ordinary harness and backend
with ThinLTO while the transformed core remains a native non-LTO object.

```powershell
$clang = Join-Path (Join-Path $env:MSYS2_ROOT 'clang64') 'bin/clang++.exe'
cmake -S native -B build/native-context -G Ninja `
  "-DCMAKE_CXX_COMPILER=$clang" `
  -DPYOBF_NATIVE_BUILD_CONTEXT_RUNTIME=ON
cmake --build build/native-context
ctest --test-dir build/native-context -R pyobf_native_context_ --output-on-failure
```

Set `MSYS2_ROOT` to your MSYS2 installation directory before running this example from
the repository root.
Enable `PYOBF_NATIVE_BUILD_LLVM_PASS=ON` and supply a matching LLVM installation to include
the two CFF profiles. Failure tests use an isolated fake backend to force allocation and
first/second-provider acquisition failures and inspect erasure/balanced release; production
Windows DLL lifetime is tested separately against the actual loader.
