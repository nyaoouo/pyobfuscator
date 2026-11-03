#include "measured_internal.hpp"
#include "measurement/reference_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::release::measured::detail {
PYOBF_NATIVE_CFF_SDK Status expand(const std::uint32_t (&words)[8],
        const measurement::reference::Identity &identity, const std::uint8_t *digest, std::uint8_t *key) noexcept {
    if (key == nullptr) return Status::invalid_argument;
    if (digest == nullptr || !measurement::reference::detail::valid_identity(identity)) {
        PYOBF_NATIVE_ERASE(key, 32);
        return digest == nullptr ? Status::invalid_argument : Status::invalid_identity;
    }
    constexpr char domain[] = "pyobf.native.release.measured.v1";
    std::uint8_t material[sizeof(domain) + 32 + 52 + 32];
    for (unsigned index = 0; index != sizeof(domain); ++index) material[index] = domain[index];
    auto *output = material + sizeof(domain);
    const volatile auto *source = words;
    for (unsigned index = 0; index != 8; ++index) {
        const auto word = source[index];
        for (unsigned byte = 0; byte != 4; ++byte) output[index * 4 + byte] = static_cast<std::uint8_t>(word >> (byte * 8));
    }
    for (unsigned index = 0; index != 16; ++index) {
        output[32 + index] = identity.build[index]; output[48 + index] = identity.image[index];
    }
    const std::uint32_t fields[]{identity.owner, identity.subject, identity.kind, identity.stage, identity.capacity};
    for (unsigned index = 0; index != 5; ++index)
        for (unsigned byte = 0; byte != 4; ++byte) output[64 + index * 4 + byte] = static_cast<std::uint8_t>(fields[index] >> (byte * 8));
    for (unsigned index = 0; index != 32; ++index) output[84 + index] = digest[index];
    const bool success = PYOBF_NATIVE_SHA256(material, sizeof(material), key);
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    if (!success) PYOBF_NATIVE_ERASE(key, 32);
    return success ? Status::ok : Status::crypto_failed;
}
}
