#include "scope.hpp"
#include "context/runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <utility>
#include <cstring>

namespace pyobfuscator::native::contribution::scoped {
namespace {
PYOBF_NATIVE_CFF_SDK bool same_reference(const measurement::reference::Identity &left,
        const measurement::reference::Identity &right) noexcept {
    for (unsigned index = 0; index != 16; ++index)
        if (left.build[index] != right.build[index] || left.image[index] != right.image[index]) return false;
    return left.owner == right.owner && left.subject == right.subject && left.kind == right.kind &&
        left.stage == right.stage && left.capacity == right.capacity;
}
}
PYOBF_NATIVE_CFF_SDK Scope::Scope(const BootstrapContextLease &parent, const Spec &spec,
        const path_fold::Storage &fold, const std::uint8_t *material, std::size_t size, measurement::observer::Snapshot &&snapshot) noexcept
    : parent_(parent), spec_(spec), fold_(fold), snapshot_(std::move(snapshot)) {
    if (material == nullptr || size != sizeof(material_)) return;
    std::memcpy(material_, material, sizeof(material_));
    if (spec.routing == 0 || spec.domain == 0 || spec.function == 0 || spec.source == 0 ||
            spec.reference.owner != spec.function || spec.reference.stage != 2 ||
            !same_reference(spec.reference, snapshot_.data().identity) ||
            snapshot_.data().policy.mode != measurement::observer::Mode::per_use || snapshot_.reused()) return;
    initial_ = parent_.availability();
    if (initial_ == BootstrapContextStatus::ok && (parent_.generation() == 0 ||
            snapshot_.data().subject_instance != parent_.generation())) initial_ = BootstrapContextStatus::context_mismatch;
}
PYOBF_NATIVE_CFF_SDK Scope::~Scope() {
    if (PYOBF_NATIVE_ATOMIC_LOAD32(&busy_) != 0) PYOBF_NATIVE_PROTECTION_FAILURE(0x701);
    snapshot_.reset();
    PYOBF_NATIVE_ERASE(&fold_, sizeof(fold_));
    PYOBF_NATIVE_ERASE(material_, sizeof(material_));
    parent_.reset();
}
PYOBF_NATIVE_CFF_SDK const measurement::observer::Observation &Scope::observation() const noexcept {
    return snapshot_.data();
}
PYOBF_NATIVE_CFF_SDK BootstrapContextStatus Scope::binding_status(const BootstrapContextLease &lease) const noexcept {
    if (initial_ != BootstrapContextStatus::ok) return initial_;
    const auto *captured = ::pyobfuscator::native::detail::BootstrapContextAccess::state(parent_);
    const auto *provided = ::pyobfuscator::native::detail::BootstrapContextAccess::state(lease);
    if (captured == nullptr || provided == nullptr || captured != provided ||
            parent_.generation() == 0 || parent_.generation() != lease.generation())
        return BootstrapContextStatus::context_mismatch;
    const auto status = parent_.availability();
    return status == BootstrapContextStatus::ok ? lease.availability() : status;
}
}
