#include "observer_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <utility>

namespace pyobfuscator::native::measurement::observer {
PYOBF_NATIVE_CFF_SDK Snapshot observe(const BootstrapContextLease &owner, bool force) noexcept {
    Snapshot result;
    result.owner_ = owner;
    detail::Response output;
    const detail::Request message{detail::version, sizeof(detail::Request), detail::Action::observe,
        force ? 1u : 0u, result.owner_.generation(), nullptr, &output};
    const auto received = result.owner_.invoke({detail::operation, &message, sizeof(message)});
    if (received.status != BootstrapContextStatus::ok || received.value != detail::reply) {
        result.data_.error = detail::context_error(received.status == BootstrapContextStatus::ok ?
            BootstrapContextStatus::invalid_request : received.status);
        return result;
    }
    result.data_ = output.data; result.reused_ = output.reused;
    for (unsigned index = 0; index != 32; ++index) result.expected_[index] = output.expected[index];
    return result;
}
PYOBF_NATIVE_CFF_SDK Validation Snapshot::check() const noexcept {
    if (data_.error.code != Status::ok) return {data_.error};
    // Immutable copied data and the retained origin stay paired across cache replacement.
    detail::Response output;
    const detail::Request message{detail::version, sizeof(detail::Request), detail::Action::validate,
        0, owner_.generation(), &data_, &output};
    const auto received = owner_.invoke({detail::operation, &message, sizeof(message)});
    if (received.status != BootstrapContextStatus::ok || received.value != detail::reply)
        return {detail::context_error(received.status == BootstrapContextStatus::ok ?
            BootstrapContextStatus::invalid_request : received.status)};
    return output.validation;
}
PYOBF_NATIVE_CFF_SDK Error invalidate(const BootstrapContextLease &owner) noexcept {
    detail::Response output;
    const detail::Request message{detail::version, sizeof(detail::Request), detail::Action::invalidate,
        0, owner.generation(), nullptr, &output};
    const auto received = owner.invoke({detail::operation, &message, sizeof(message)});
    return received.status == BootstrapContextStatus::ok && received.value == detail::reply ?
        output.validation.error : detail::context_error(received.status == BootstrapContextStatus::ok ?
            BootstrapContextStatus::invalid_request : received.status);
}
PYOBF_NATIVE_CFF_SDK void Snapshot::reset() noexcept {
    auto previous = std::move(owner_);
    data_ = {};
    PYOBF_NATIVE_ERASE(expected_, sizeof(expected_)); reused_ = false;
}
PYOBF_NATIVE_CFF_SDK Snapshot::Snapshot(Snapshot &&other) noexcept { *this = std::move(other); }
PYOBF_NATIVE_CFF_SDK Snapshot &Snapshot::operator=(Snapshot &&other) noexcept {
    if (this == &other) return *this;
    auto previous = std::move(owner_);
    data_ = other.data_; reused_ = other.reused_;
    for (unsigned index = 0; index != 32; ++index) expected_[index] = other.expected_[index];
    owner_ = std::move(other.owner_);
    other.data_ = {}; other.reused_ = false; PYOBF_NATIVE_ERASE(other.expected_, sizeof(other.expected_));
    return *this;
}
PYOBF_NATIVE_CFF_SDK Snapshot::~Snapshot() { reset(); }
PYOBF_NATIVE_CFF_SDK const Observation &Snapshot::data() const noexcept { return data_; }
PYOBF_NATIVE_CFF_SDK const std::uint8_t *Snapshot::reference_digest() const noexcept { return expected_; }
PYOBF_NATIVE_CFF_SDK bool Snapshot::reused() const noexcept { return reused_; }
}  // namespace pyobfuscator::native::measurement::observer
