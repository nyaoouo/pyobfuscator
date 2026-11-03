#include "scope.hpp"
#include "context/runtime.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::contribution::scoped {
namespace {
PYOBF_NATIVE_CFF_SDK BootstrapContextStatus admit(const BootstrapContextLease &parent, const Spec &spec,
        const BootstrapContextLease &observation) noexcept {
    const auto generation = parent.generation();
    if (generation == 0) return parent.availability();
    const Admission message{admission_version, sizeof(Admission), spec.routing, spec.domain, spec.function,
        spec.source, generation, spec.reference.owner, 0, observation.generation(),
        reinterpret_cast<std::uintptr_t>(::pyobfuscator::native::detail::BootstrapContextAccess::state(observation))};
    const auto result = call_bound_bootstrap(parent, {spec.routing, &message, sizeof(message)});
    if (result.status != BootstrapContextStatus::ok) return result.status;
    if (result.value != generation) return BootstrapContextStatus::context_mismatch;
    return parent.availability();
}
}
PYOBF_NATIVE_CFF_SDK Result Scope::query(std::uint32_t routing, const Site &point) noexcept {
    if (PYOBF_NATIVE_ATOMIC_CAS32(&busy_, 0, 1) != 0) return {BootstrapContextStatus::busy};
    Result result;
    result.status = initial_;
    if (result.status == BootstrapContextStatus::ok && (routing != spec_.routing || point.domain != spec_.domain ||
            point.function != spec_.function || point.source != spec_.source || point.site == 0))
        result.status = BootstrapContextStatus::context_mismatch;
    if (result.status == BootstrapContextStatus::ok) result.status = admit(parent_, spec_, snapshot_.owner_);
    if (result.status == BootstrapContextStatus::ok) {
        result = detail::authenticated_material(fold_, material_, sizeof(material_), snapshot_, routing, point);
        if (result.status == BootstrapContextStatus::ok && result.material.status == measured::Status::ok) {
            result.status = admit(parent_, spec_, snapshot_.owner_);
            if (result.status == BootstrapContextStatus::ok) {
                result.observation = snapshot_.check().error;
                if (result.observation.code == measurement::observer::Status::ok) result.word = result.material.value.word;
                else result.status = BootstrapContextStatus::unavailable;
            }
        } else if (result.status == BootstrapContextStatus::ok) result.status = BootstrapContextStatus::unavailable;
    }
    if (result.status != BootstrapContextStatus::ok) {
        result.word = 0;
        result.material.value.word = 0;
    }
    PYOBF_NATIVE_ATOMIC_STORE32(&busy_, 0);
    return result;
}
}
extern "C" PYOBF_NATIVE_CFF_SDK std::uint32_t pyobf_native_measured_contribution_word_v1(
        pyobfuscator::native::contribution::scoped::Scope &scope, std::uint32_t routing,
        std::uint32_t domain, std::uint32_t function, std::uint32_t site, std::uint32_t source,
        std::uint32_t current) noexcept {
    const auto result = scope.query(routing, {domain, function, site, source, current});
    if (result.status != pyobfuscator::native::BootstrapContextStatus::ok) PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
    return result.word;
}
