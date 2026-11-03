#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextOwner::BootstrapContextOwner() noexcept = default;
PYOBF_NATIVE_CFF_SDK BootstrapContextOwner::BootstrapContextOwner(detail::BootstrapContextState *context) noexcept
    : context_(context) {}
PYOBF_NATIVE_CFF_SDK BootstrapContextOwner::BootstrapContextOwner(BootstrapContextOwner &&other) noexcept
    : context_(other.context_) { other.context_ = nullptr; }

PYOBF_NATIVE_CFF_SDK BootstrapContextOwner &BootstrapContextOwner::operator=(BootstrapContextOwner &&other) noexcept {
    if (this == &other) return *this;
    // Detach both handles before destruction can reenter either one.
    BootstrapContextOwner previous(context_);
    context_ = other.context_;
    other.context_ = nullptr;
    return *this;
}

PYOBF_NATIVE_CFF_SDK BootstrapContextOwner::~BootstrapContextOwner() {
    close();
    detail::release_context(context_);
}

PYOBF_NATIVE_CFF_SDK BootstrapContextLease BootstrapContextOwner::lease() const noexcept {
    if (context_ == nullptr) return {};
    const auto status = detail::retain_context(context_, false);
    return BootstrapContextLease(status == BootstrapContextStatus::ok ? context_ : nullptr, status);
}

PYOBF_NATIVE_CFF_SDK BootstrapContextStatus BootstrapContextOwner::close() noexcept {
    if (context_ == nullptr) return BootstrapContextStatus::unavailable;
    detail::context_lock(context_->gate);
    context_->closing = true;
    const auto status = context_->active_calls == 0 ? BootstrapContextStatus::ok : BootstrapContextStatus::busy;
    detail::context_unlock(context_->gate);
    return status;
}

PYOBF_NATIVE_CFF_SDK bool BootstrapContextOwner::quiescent() const noexcept {
    if (context_ == nullptr) return true;
    detail::context_lock(context_->gate);
    const bool result = context_->active_calls == 0;
    detail::context_unlock(context_->gate);
    return result;
}

PYOBF_NATIVE_CFF_SDK std::uint64_t BootstrapContextOwner::generation() const noexcept {
    return context_ == nullptr ? 0 : context_->generation;
}

}  // namespace pyobfuscator::native
