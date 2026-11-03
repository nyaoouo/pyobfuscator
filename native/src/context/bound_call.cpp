#include "publication.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextResult call_bound_bootstrap(
    const BootstrapContextLease &expected, const BootstrapContextRequest &request) noexcept {
    if (expected.context_ == nullptr) return {expected.error_, 0};
    auto &slot = detail::context_publication();
    detail::context_lock(slot.gate);
    auto status = BootstrapContextStatus::unavailable;
    auto *context = slot.context;
    if (context != nullptr) {
        status = context == expected.context_ ? detail::retain_context(context, false) :
            BootstrapContextStatus::context_mismatch;
    }
    detail::context_unlock(slot.gate);
    if (status != BootstrapContextStatus::ok) return {status, 0};
    // The captured lease survives reentrant unpublish. invoke adds its separate frame.
    BootstrapContextLease captured(context, status);
    return captured.invoke(request);
}

}  // namespace pyobfuscator::native
