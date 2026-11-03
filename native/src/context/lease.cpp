#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native {

PYOBF_NATIVE_CFF_SDK BootstrapContextLease::BootstrapContextLease() noexcept = default;
PYOBF_NATIVE_CFF_SDK BootstrapContextLease::BootstrapContextLease(detail::BootstrapContextState *context,
                                                                 BootstrapContextStatus error) noexcept
    : context_(context), error_(error) {}
PYOBF_NATIVE_CFF_SDK BootstrapContextLease::BootstrapContextLease(const BootstrapContextLease &other) noexcept
    : error_(other.error_) {
    if (other.context_ != nullptr) {
        error_ = detail::retain_context(other.context_, true);
        if (error_ == BootstrapContextStatus::ok) context_ = other.context_;
    }
}
PYOBF_NATIVE_CFF_SDK BootstrapContextLease::BootstrapContextLease(BootstrapContextLease &&other) noexcept
    : context_(other.context_), error_(other.error_) {
    other.context_ = nullptr;
    other.error_ = BootstrapContextStatus::unavailable;
}

PYOBF_NATIVE_CFF_SDK BootstrapContextLease &BootstrapContextLease::operator=(const BootstrapContextLease &other) noexcept {
    if (this == &other) return *this;
    auto *replacement = other.context_;
    auto status = other.error_;
    if (replacement != nullptr) {
        status = detail::retain_context(replacement, true);
        if (status != BootstrapContextStatus::ok) replacement = nullptr;
    }
    auto *previous = context_;
    context_ = replacement;
    error_ = status;
    detail::release_context(previous);
    return *this;
}

PYOBF_NATIVE_CFF_SDK BootstrapContextLease &BootstrapContextLease::operator=(BootstrapContextLease &&other) noexcept {
    if (this == &other) return *this;
    auto *previous = context_;
    context_ = other.context_;
    error_ = other.error_;
    other.context_ = nullptr;
    other.error_ = BootstrapContextStatus::unavailable;
    detail::release_context(previous);
    return *this;
}

PYOBF_NATIVE_CFF_SDK BootstrapContextLease::~BootstrapContextLease() { detail::release_context(context_); }

PYOBF_NATIVE_CFF_SDK void BootstrapContextLease::reset() noexcept {
    auto *previous = context_;
    context_ = nullptr;
    error_ = BootstrapContextStatus::unavailable;
    detail::release_context(previous);
}

PYOBF_NATIVE_CFF_SDK BootstrapContextStatus BootstrapContextLease::availability() const noexcept {
    return context_ == nullptr ? error_ : detail::context_availability(context_);
}

PYOBF_NATIVE_CFF_SDK std::uint64_t BootstrapContextLease::generation() const noexcept {
    return context_ == nullptr ? 0 : context_->generation;
}

}  // namespace pyobfuscator::native
