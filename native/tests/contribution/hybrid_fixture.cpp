#include "pyobfuscator_native/contribution_marker.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" int contribution_may_throw(int);
#ifdef PYOBF_CONTRIBUTION_INTERNAL_THROW_TEST
extern "C" int contribution_preparation_throwing(int);
#endif
extern "C" void contribution_cleanup(int) noexcept;
#ifdef PYOBF_CONTRIBUTION_PREPARATION_TEST
extern "C" int contribution_preparation_defined(int) noexcept;
#endif

namespace {
struct Cleanup {
    int &total;
    int value;
    ~Cleanup() noexcept { total += 5; contribution_cleanup(value); }
};
}

extern "C" PYOBF_NATIVE_CFF int contribution_hybrid(
    const pyobfuscator::native::BootstrapContextLease &expected, int value) {
    pyobf_native_contribution_site_v1(expected, 601);
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    const auto argument_mix = (static_cast<unsigned>(value) * 5u + 7u) & 63u;
#endif
#ifdef PYOBF_CONTRIBUTION_HYBRID_NORMALIZER_TEST
    unsigned duplicate;
    if (value & 1) duplicate = static_cast<unsigned>(value) + 7u;
    else duplicate = static_cast<unsigned>(value) + 7u;
    value = static_cast<int>(duplicate - 7u);
#endif
#ifdef PYOBF_CONTRIBUTION_PREPARATION_TEST
    value = contribution_preparation_defined(value);
#endif
    int cleanup = 0, result;
    try {
        Cleanup guard{cleanup, value};
#ifdef PYOBF_CONTRIBUTION_INTERNAL_THROW_TEST
        result = contribution_preparation_throwing(value);
#else
        result = contribution_may_throw(value);
#endif
        pyobf_native_contribution_site_v1(expected, 602);
        result += (value & 1) ? 3 : -7;
    } catch (int token) {
        pyobf_native_contribution_site_v1(expected, 603);
        result = value + token;
    }
    pyobf_native_contribution_site_v1(expected, 604);
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    static constexpr unsigned char bytes[]{0x48, 0x79, 0, 0xff, 0x62, 0x21, 0};
    return result + cleanup + 1 + bytes[static_cast<unsigned>(value) & 3] + static_cast<int>(argument_mix);
#else
    return result + cleanup + 1;
#endif
}
