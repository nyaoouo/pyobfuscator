#include "reference_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::reference::detail {

PYOBF_NATIVE_CFF_SDK bool valid_identity(const Identity &identity) noexcept {
    std::uint8_t build = 0, image = 0;
    for (unsigned index = 0; index != 16; ++index) { build |= identity.build[index]; image |= identity.image[index]; }
    return build && image && identity.owner && identity.subject && identity.kind >= 1 && identity.kind <= 3 &&
        identity.stage >= 1 && identity.stage <= 2 && identity.capacity >= min_slot && identity.capacity <= max_slot;
}

PYOBF_NATIVE_CFF_SDK bool derive_key(const Identity &identity, const std::uint32_t (&private_words)[8],
        std::uint8_t *key) noexcept {
    constexpr char domain[] = "pyobf.native.code.reference.key.v1";
    std::uint8_t material[sizeof(domain) + 52 + 32];
    for (unsigned index = 0; index != sizeof(domain); ++index) material[index] = domain[index];
    auto *encoded = material + sizeof(domain);
    for (unsigned index = 0; index != 16; ++index) { encoded[index] = identity.build[index]; encoded[index + 16] = identity.image[index]; }
    const std::uint32_t fields[]{identity.owner, identity.subject, identity.kind, identity.stage, identity.capacity};
    for (unsigned index = 0; index != 5; ++index)
        for (unsigned byte = 0; byte != 4; ++byte) encoded[32 + index * 4 + byte] = static_cast<std::uint8_t>(fields[index] >> (byte * 8));
    const volatile auto *words = private_words;
    for (unsigned index = 0; index != 8; ++index) {
        const auto word = words[index];
        for (unsigned byte = 0; byte != 4; ++byte) encoded[52 + index * 4 + byte] = static_cast<std::uint8_t>(word >> (byte * 8));
    }
    const bool success = PYOBF_NATIVE_SHA256(material, sizeof(material), key);
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    if (!success) PYOBF_NATIVE_ERASE(key, 32);
    return success;
}

}  // namespace pyobfuscator::native::measurement::reference::detail
