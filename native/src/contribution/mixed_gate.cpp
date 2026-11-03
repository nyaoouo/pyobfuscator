#include "scope.hpp"
#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::contribution::scoped {
namespace {
PYOBF_NATIVE_CFF_SDK void require_binding(const Scope &scope, const BootstrapContextLease &lease) noexcept {
    if (scope.binding_status(lease) != BootstrapContextStatus::ok) PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
}
}
}

extern "C" PYOBF_NATIVE_CFF_SDK std::uint32_t pyobf_native_mixed_owned_contribution_word_v1(
        const pyobfuscator::native::BootstrapContextLease &lease, std::uint32_t routing,
        std::uint32_t domain, std::uint32_t function, std::uint32_t site,
        std::uint32_t source, std::uint32_t current,
        pyobfuscator::native::contribution::scoped::Scope &scope) noexcept {
    pyobfuscator::native::contribution::scoped::require_binding(scope, lease);
    const auto result = pyobfuscator::native::contribution::request(lease, routing,
        {domain, function, site, source, current});
    if (result.status != pyobfuscator::native::BootstrapContextStatus::ok || result.word == 0)
        PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
    return result.word;
}

extern "C" PYOBF_NATIVE_CFF_SDK std::uint32_t pyobf_native_mixed_measured_contribution_word_v1(
        pyobfuscator::native::contribution::scoped::Scope &scope, std::uint32_t routing,
        std::uint32_t domain, std::uint32_t function, std::uint32_t site,
        std::uint32_t source, std::uint32_t current,
        const pyobfuscator::native::BootstrapContextLease &lease) noexcept {
    pyobfuscator::native::contribution::scoped::require_binding(scope, lease);
    const auto result = scope.query(routing, {domain, function, site, source, current});
    if (result.status != pyobfuscator::native::BootstrapContextStatus::ok || result.word == 0)
        PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
    return result.word;
}
