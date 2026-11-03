#include "publication.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::detail {
namespace {
ContextPublication publication;
}

PYOBF_NATIVE_CFF_SDK ContextPublication &context_publication() noexcept { return publication; }

PYOBF_NATIVE_CFF_SDK void release_publication(ContextPublication *origin, std::uint64_t serial) noexcept {
    if (origin == nullptr) return;
    auto &slot = *origin;
    context_lock(slot.gate);
    auto *previous = slot.serial == serial ? slot.context : nullptr;
    platform::CodeLease provider{};
    if (previous != nullptr) {
        provider = slot.provider;
        slot.context = nullptr;
        slot.provider = {};
    }
    context_unlock(slot.gate);
    // Final destruction may reenter publication; no endpoint lock is held here.
    release_context(previous);
    if (!PYOBF_NATIVE_RELEASE_CODE(provider)) PYOBF_NATIVE_PROTECTION_FAILURE(0x205);
}
}  // namespace pyobfuscator::native::detail

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextBindingCreation bind_bootstrap_context(const BootstrapContextLease &lease) noexcept {
    if (lease.context_ == nullptr) return {lease.error_, {}};
    auto &slot = detail::context_publication();
    detail::context_lock(slot.gate);
    if (slot.context != nullptr) {
        detail::context_unlock(slot.gate);
        return {BootstrapContextStatus::busy, {}};
    }
    const auto retained = detail::retain_context(lease.context_, false);
    auto status = retained;
    platform::CodeLease provider{};
    std::uint64_t serial = 0;
    if (status == BootstrapContextStatus::ok) {
        provider = PYOBF_NATIVE_RETAIN_CODE(reinterpret_cast<platform::CodeAddress>(&detail::context_publication));
        if (provider.module == nullptr) status = BootstrapContextStatus::code_unavailable;
        else {
            serial = detail::advance_context_generation(slot.serial);
            if (serial == 0) status = BootstrapContextStatus::generation_exhausted;
            else {
                slot.context = lease.context_;
                slot.provider = provider;
            }
        }
    }
    detail::context_unlock(slot.gate);
    if (status != BootstrapContextStatus::ok) {
        if (retained == BootstrapContextStatus::ok) detail::release_context(lease.context_);
        if (!PYOBF_NATIVE_RELEASE_CODE(provider)) PYOBF_NATIVE_PROTECTION_FAILURE(0x206);
        return {status, {}};
    }
    return {status, BootstrapContextBinding(&slot, serial, lease.context_->generation)};
}

}  // namespace pyobfuscator::native
