#include "key_expansion.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool expand_release_key(
    const path_fold::Storage &fold, const release::Record &record, std::uint8_t *key) noexcept {
    constexpr char magic[16] = "PYOBF-RELKEY-v1";
    if (record.version != 1 || record.size != sizeof(release::Record)) return false;
    for (unsigned index = 0; index != sizeof(magic); ++index)
        if (record.magic[index] != magic[index]) return false;
    for (auto byte : record.reserved) if (byte != 0) return false;
    constexpr char domain[] = "pyobf.native.release.fold.v1";
    std::uint8_t material[sizeof(domain) + 32];
    for (unsigned index = 0; index != sizeof(domain); ++index) material[index] = domain[index];
    const volatile auto *words = fold.words;
    for (unsigned lane = 0; lane != 8; ++lane) {
        const auto word = words[lane];
        for (unsigned byte = 0; byte != 4; ++byte)
            material[sizeof(domain) + lane * 4 + byte] = static_cast<std::uint8_t>(word >> (byte * 8));
    }
    const bool expanded = PYOBF_NATIVE_SHA256(material, sizeof(material), key);
    PYOBF_NATIVE_ERASE(material, sizeof(material));
    if (!expanded) return false;
    for (unsigned index = 0; index != 32; ++index) key[index] ^= record.mask[index];
    return true;
}

}  // namespace pyobfuscator::native::demo
