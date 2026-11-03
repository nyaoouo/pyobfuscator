#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <limits>

namespace pyobfuscator::native::detail {

PYOBF_NATIVE_CFF_SDK BootstrapContextStatus admit_context_call(BootstrapContextState *context) noexcept {
    context_lock(context->gate);
    auto status = BootstrapContextStatus::ok;
    if (context->closing) status = BootstrapContextStatus::closed;
    else if (context->references == std::numeric_limits<std::uint32_t>::max() ||
             context->active_calls == std::numeric_limits<std::uint32_t>::max())
        status = BootstrapContextStatus::reference_limit;
    else {
        ++context->references;
        ++context->active_calls;
    }
    context_unlock(context->gate);
    return status;
}

PYOBF_NATIVE_CFF_SDK void complete_context_call(BootstrapContextState *context) noexcept {
    context_lock(context->gate);
    if (context->active_calls == 0) PYOBF_NATIVE_PROTECTION_FAILURE(0x204);
    --context->active_calls;
    context_unlock(context->gate);
    release_context(context);
}

}  // namespace pyobfuscator::native::detail

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextResult BootstrapContextLease::invoke(const BootstrapContextRequest &request) const noexcept {
    auto *context = context_;
    if (context == nullptr) return {error_, 0};
    if ((request.input_size != 0 && request.input == nullptr) || request.input_size > bootstrap_context_max_input)
        return {BootstrapContextStatus::invalid_request, 0};
    const auto status = detail::admit_context_call(context);
    if (status != BootstrapContextStatus::ok) return {status, 0};
    // A callback may reset the invoking lease/owner. Use only this retained frame afterward.
    const auto result = context->spec.dispatch(request, context->spec.user_data);
    detail::complete_context_call(context);
    return result;
}

}  // namespace pyobfuscator::native
