#include "pyobfuscator_native/cff_marker.hpp"

#include <cstdint>

// Link this implementation after ordinary source optimization. During that phase the
// declaration must remain opaque, so IPA cannot expose the asset through a constant return.
extern "C" PYOBF_NATIVE_CFF_SDK const std::uint8_t *__pyobf_native_asset_identity_v1(
    const std::uint8_t *value) noexcept {
    return value;
}
