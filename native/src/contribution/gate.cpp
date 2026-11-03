#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

// Private generated-call ABI. A scalar result avoids depending on C++ aggregate return
// lowering. A failed acquisition must stop before an unbound value enters the CFF state.
extern "C" PYOBF_NATIVE_CFF_SDK std::uint32_t pyobf_native_contribution_word_v1(
    const pyobfuscator::native::BootstrapContextLease &expected, std::uint32_t routing,
    std::uint32_t domain, std::uint32_t function, std::uint32_t site,
    std::uint32_t source, std::uint32_t current) noexcept {
    const auto result = pyobfuscator::native::contribution::request(expected, routing,
        {domain, function, site, source, current});
    if (result.status != pyobfuscator::native::BootstrapContextStatus::ok || result.word == 0)
        PYOBF_NATIVE_PROTECTION_FAILURE(0x702);
    return result.word;
}
