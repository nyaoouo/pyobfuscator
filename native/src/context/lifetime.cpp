#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <limits>

namespace pyobfuscator::native::detail {
namespace {

PYOBF_NATIVE_CFF_SDK void dispose_context(BootstrapContextState *context) noexcept {
    const auto spec = context->spec;
    const auto dispatch_provider = context->providers[0];
    const auto destroy_provider = context->providers[1];
    // Keep callback code mapped until destruction returns. No registry/state lock is held.
    if (spec.destroy != nullptr) spec.destroy(spec.user_data);
    context->~BootstrapContextState();
    PYOBF_NATIVE_ERASE(context, sizeof(BootstrapContextState));
    PYOBF_NATIVE_RELEASE(context);
    const bool destroy_released = PYOBF_NATIVE_RELEASE_CODE(destroy_provider);
    const bool dispatch_released = PYOBF_NATIVE_RELEASE_CODE(dispatch_provider);
    if (!destroy_released || !dispatch_released)
        PYOBF_NATIVE_PROTECTION_FAILURE(0x201);
}
}

PYOBF_NATIVE_CFF_SDK BootstrapContextStatus retain_context(BootstrapContextState *context, bool allow_closed) noexcept {
    context_lock(context->gate);
    auto status = BootstrapContextStatus::ok;
    if (!allow_closed && context->closing) status = BootstrapContextStatus::closed;
    else if (context->references == std::numeric_limits<std::uint32_t>::max())
        status = BootstrapContextStatus::reference_limit;
    else ++context->references;
    context_unlock(context->gate);
    return status;
}

PYOBF_NATIVE_CFF_SDK void release_context(BootstrapContextState *context) noexcept {
    if (context == nullptr) return;
    context_lock(context->gate);
    if (context->references == 0 || (context->references == 1 && context->active_calls != 0))
        PYOBF_NATIVE_PROTECTION_FAILURE(0x202);
    const bool dispose = --context->references == 0;
    context_unlock(context->gate);
    if (dispose) dispose_context(context);
}

PYOBF_NATIVE_CFF_SDK BootstrapContextStatus context_availability(BootstrapContextState *context) noexcept {
    context_lock(context->gate);
    const auto result = context->closing ? BootstrapContextStatus::closed : BootstrapContextStatus::ok;
    context_unlock(context->gate);
    return result;
}

}  // namespace pyobfuscator::native::detail
