#include "pyobfuscator_native/contribution_marker.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <cstdint>
#include <cstring>

extern "C" PYOBF_NATIVE_CFF int contribution_archive_value(
    const pyobfuscator::native::BootstrapContextLease &expected, int value) noexcept {
    pyobf_native_contribution_site_v1(expected, 501);
    static constexpr std::uint8_t bytes[]{0x41, 0, 0x42, 0xff, 0x43, 0x21, 0};
    static constexpr char16_t wide[]{0xd800, u'Z', 0};
    static constexpr std::uint64_t words[]{0x12345678abcdef01ull, 0x00000001ffffffffull};
    const unsigned index = static_cast<unsigned>(value) & 1;
    const double floating = index ? -0.0 : __builtin_nan("0x42");
    std::uint64_t bits;
    std::memcpy(&bits, &floating, sizeof(bits));
    int mixed = 0;
    for (unsigned n = 0; n != (static_cast<unsigned>(value) & 3) + 1; ++n) {
        pyobf_native_contribution_site_v1(expected, 502);
        mixed ^= bytes[(static_cast<unsigned>(value) + n) & 3];
    }
    return value + mixed + (wide[index] & 0x7f) + ((words[index] >> 32) & 0xff) +
        (bits & 0xff) + (bits >> 63);
}
