#include "pyobfuscator_native/contribution.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::contribution {

PYOBF_NATIVE_CFF_SDK Result derive(const std::uint32_t (&private_words)[8],
    std::uint32_t routing_tag, const Site &point) noexcept {
    if (routing_tag == 0 || point.domain == 0 || point.function == 0 || point.site == 0 || point.source == 0)
        return {BootstrapContextStatus::invalid_request, 0};
    auto *digest = static_cast<std::uint8_t *>(PYOBF_NATIVE_ALLOCATE(32));
    if (digest == nullptr) return {BootstrapContextStatus::allocation_failed, 0};
    constexpr char domain[] = "pyobf.native.contribution.context.v1";
    const std::uint32_t identity[]{routing_tag, point.domain, point.function, point.site, point.source, point.current};
    std::uint8_t material[sizeof(domain) + sizeof(identity) + sizeof(private_words)];
    for (unsigned index = 0; index != sizeof(domain); ++index) material[index] = domain[index];
    for (unsigned index = 0; index != 6; ++index)
        for (unsigned byte = 0; byte != 4; ++byte)
            material[sizeof(domain) + index * 4 + byte] = static_cast<std::uint8_t>(identity[index] >> (byte * 8));
    const volatile auto *words = private_words;
    for (unsigned index = 0; index != 8; ++index) {
        const auto value = words[index];
        for (unsigned byte = 0; byte != 4; ++byte)
            material[sizeof(domain) + sizeof(identity) + index * 4 + byte] = static_cast<std::uint8_t>(value >> (byte * 8));
    }
    const bool success = PYOBF_NATIVE_SHA256(material, sizeof(material), digest);
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    std::uint32_t word = 0;
    if (success) for (unsigned byte = 0; byte != 4; ++byte) word |= std::uint32_t(digest[byte]) << (byte * 8);
    PYOBF_NATIVE_ERASE(digest, 32);
    PYOBF_NATIVE_RELEASE(digest);
    if (!success) return {BootstrapContextStatus::unavailable, 0};
    return {BootstrapContextStatus::ok, word == 0 ? 1u : word};
}

}  // namespace pyobfuscator::native::contribution
