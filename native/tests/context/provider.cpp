#include "pyobfuscator_native/bootstrap_context.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <atomic>
#include <new>

using namespace pyobfuscator::native;
namespace {
struct State { std::atomic<unsigned> *destroyed; };
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *) noexcept {
    return {BootstrapContextStatus::ok, request.operation_id + 100};
}
void destroy(void *data) noexcept {
    auto *state = static_cast<State *>(data);
    state->destroyed->fetch_add(1);
    delete state;
}
}

extern "C" __declspec(dllexport) void context_provider(std::atomic<unsigned> *destroyed,
                                                     BootstrapContextSpec *result) noexcept {
    auto *state = new (std::nothrow) State{destroyed};
    *result = state == nullptr ? BootstrapContextSpec{} :
        BootstrapContextSpec{bootstrap_context_abi_version, dispatch, state, destroy};
}

extern "C" __declspec(dllexport) void context_provider_owned(std::atomic<unsigned> *destroyed,
                                                           BootstrapContextCreation *result) noexcept {
    BootstrapContextSpec spec;
    context_provider(destroyed, &spec);
    *result = create_bootstrap_context(spec);
    if (result->status != BootstrapContextStatus::ok && spec.destroy != nullptr) spec.destroy(spec.user_data);
}

extern "C" __declspec(dllexport) void context_provider_bind(const BootstrapContextLease *lease,
                                                          BootstrapContextBindingCreation *result) noexcept {
    *result = bind_bootstrap_context(*lease);
}

extern "C" __declspec(dllexport) void context_provider_call(const BootstrapContextLease *lease,
    const BootstrapContextRequest *request, BootstrapContextResult *result) noexcept {
    *result = call_bound_bootstrap(*lease, *request);
}
