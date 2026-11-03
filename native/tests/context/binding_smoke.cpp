#include "checks.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/bootstrap_api.hpp"

#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {
using namespace context_test;
struct State { unsigned calls = 0, destroyed = 0; };
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *data) noexcept {
    ++static_cast<State *>(data)->calls;
    return {Status::ok, request.operation_id + 20};
}
void destroy(void *data) noexcept { ++static_cast<State *>(data)->destroyed; }
int legacy_dispatch(std::uint32_t, void *data) noexcept { ++*static_cast<unsigned *>(data); return 99; }
void legacy_stage(std::uint32_t, void *) {}

void check_identity_and_provider(const char *path) {
    // Run first: both independent source-built factory instances issue generation 1.
    State state;
    auto local = create_bootstrap_context({bootstrap_context_abi_version, dispatch, &state, destroy});
    require(local.status == Status::ok && local.owner.generation() == 1, "fresh host factory");
    auto expected = local.owner.lease();
    require(bind_bootstrap_context({}).status == Status::unavailable, "empty lease cannot publish");
    const auto module = LoadLibraryA(path);
    require(module != nullptr, "provider with separate runtime loaded");
    using Factory = void (*)(std::atomic<unsigned> *, BootstrapContextCreation *) noexcept;
    const auto factory = reinterpret_cast<Factory>(GetProcAddress(module, "context_provider_owned"));
    require(factory != nullptr, "separate runtime factory found");
    std::atomic<unsigned> provider_destroyed{0};
    BootstrapContextCreation foreign{Status::unavailable, {}};
    factory(&provider_destroyed, &foreign);
    require(foreign.status == Status::ok && foreign.owner.generation() == local.owner.generation(),
            "actual separate factory generation collision");
    auto wrong = foreign.owner.lease();
    unsigned legacy_calls = 0;
    const BootstrapApi api{bootstrap_abi_version, legacy_dispatch, legacy_stage, &legacy_calls};
    require(bind_bootstrap_api(&api), "legacy publication available independently");
    require(call_bound_bootstrap(expected, {1}).status == Status::unavailable && legacy_calls == 0,
            "missing strict binding never falls back to legacy");
    auto published = bind_bootstrap_context(expected);
    require(published.status == Status::ok && published.binding.generation() == expected.generation(), "owned publication");
    require(bind_bootstrap_context(wrong).status == Status::busy && bind_bootstrap_context(expected).status == Status::busy,
            "foreign and duplicate publication rejected");
    require(call_bound_bootstrap(wrong, {1}).status == Status::context_mismatch,
            "equal generations cannot substitute foreign identity");
    require(call_bound_bootstrap(expected, {2}).value == 22 && state.calls == 1, "paired strict call");
    require(call_bound_bootstrap(expected, {2, nullptr, 1}).status == Status::invalid_request && state.calls == 1,
            "strict captured call preserves input validation");
    using Publish = void (*)(const BootstrapContextLease *, BootstrapContextBindingCreation *) noexcept;
    using Call = void (*)(const BootstrapContextLease *, const BootstrapContextRequest *, BootstrapContextResult *) noexcept;
    const auto publish = reinterpret_cast<Publish>(GetProcAddress(module, "context_provider_bind"));
    const auto call = reinterpret_cast<Call>(GetProcAddress(module, "context_provider_call"));
    require(publish != nullptr && call != nullptr, "independent publication exports");
    BootstrapContextBindingCreation foreign_scope{Status::unavailable, {}};
    publish(&expected, &foreign_scope);
    require(foreign_scope.status == Status::ok, "same context may publish in a separate runtime endpoint");
    foreign_scope.binding.reset();
    const BootstrapContextRequest request{1};
    BootstrapContextResult provider_result;
    call(&expected, &request, &provider_result);
    require(provider_result.status == Status::unavailable && call_bound_bootstrap(expected, {2}).value == 22,
            "foreign token reset targets its origin even when both endpoint serials are one");
    require(bind_bootstrap_api(&api) && call_bound_bootstrap(expected, {3}).value == 23 && legacy_calls == 0,
            "legacy publication cannot replace strict state");
    unbind_bootstrap_api();
    require(call_bound_bootstrap(expected, {4}).value == 24, "legacy unbind cannot remove strict state");
    auto moved = std::move(published.binding);
    moved = std::move(moved);
    published.binding.reset();
    require(call_bound_bootstrap(expected, {5}).value == 25 && published.binding.generation() == 0,
            "moved/default token cannot unpublish live scope");
    moved.reset();
    require(call_bound_bootstrap(expected, {5}).status == Status::unavailable, "scope reset stops new acquisitions");
    auto rebound = bind_bootstrap_context(wrong);
    require(rebound.status == Status::ok, "new foreign scope can explicitly publish");
    require(FreeLibrary(module) != 0 && GetModuleHandleA(path) != nullptr, "provider remains mapped after caller release");
    require(call_bound_bootstrap(expected, {7}).status == Status::context_mismatch &&
            call_bound_bootstrap(wrong, {7}).value == 107, "new scope only admits paired context");
    foreign.owner = {};
    require(bind_bootstrap_context(expected).status == Status::busy &&
            call_bound_bootstrap(wrong, {7}).status == Status::closed, "closed publication remains reserved until reset");
    wrong.reset();
    require(provider_destroyed.load() == 0, "publication owns closed provider state");
    rebound.binding.reset();
    require(provider_destroyed.load() == 1 && GetModuleHandleA(path) == nullptr, "last publication releases state and provider");
    require(bind_bootstrap_api(&api) && call_bound_bootstrap(expected, {1}).status == Status::unavailable &&
            legacy_calls == 0, "retired strict slot has no legacy fallback");
    unbind_bootstrap_api();
    local.owner.close();
    require(bind_bootstrap_context(expected).status == Status::closed, "closed context cannot republish");
}

void check_registry_provider(const char *path) {
    State state;
    auto created = create_bootstrap_context({bootstrap_context_abi_version, dispatch, &state, destroy});
    auto expected = created.owner.lease();
    const auto module = LoadLibraryA(path);
    require(module != nullptr, "independent registry provider reloaded");
    using Publish = void (*)(const BootstrapContextLease *, BootstrapContextBindingCreation *) noexcept;
    using Call = void (*)(const BootstrapContextLease *, const BootstrapContextRequest *, BootstrapContextResult *) noexcept;
    const auto publish = reinterpret_cast<Publish>(GetProcAddress(module, "context_provider_bind"));
    const auto call = reinterpret_cast<Call>(GetProcAddress(module, "context_provider_call"));
    require(publish != nullptr && call != nullptr, "registry-only provider exports");
    BootstrapContextBindingCreation scope{Status::unavailable, {}};
    publish(&expected, &scope);
    require(scope.status == Status::ok, "provider registry captures host-only callbacks");
    auto moved = std::move(scope.binding);
    require(FreeLibrary(module) != 0 && GetModuleHandleA(path) != nullptr,
            "registry reference alone retains its module after caller unload");
    const BootstrapContextRequest request{2};
    BootstrapContextResult result;
    call(&expected, &request, &result);
    require(result.value == 22 && call_bound_bootstrap(expected, {2}).status == Status::unavailable,
            "endpoint lookup stays local while moved token retains its origin");
    moved.reset();
    require(GetModuleHandleA(path) == nullptr && state.destroyed == 0,
            "cross-module token releases registry provider after its call returned");
    created.owner = {};
    expected.reset();
    require(state.destroyed == 1, "registry provider lifetime is independent from adopted host state");
}
}

int main(int argc, char **argv) {
    context_test::require(argc == 2, "provider path required");
    check_identity_and_provider(argv[1]);
    check_registry_provider(argv[1]);
    context_test::check_binding_reentrancy();
    context_test::check_binding_concurrency();
    std::puts("owned context publication verified");
}
