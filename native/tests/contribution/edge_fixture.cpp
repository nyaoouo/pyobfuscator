#include "pyobfuscator_native/contribution_marker.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" PYOBF_NATIVE_CFF int contribution_switch(
    const pyobfuscator::native::BootstrapContextLease &expected, int value) noexcept {
    pyobf_native_contribution_site_v1(expected, 501);
    int result;
    switch (value) {
    case -9: case 3:
        pyobf_native_contribution_site_v1(expected, 502);
        result = value + 7; break;
    case -1:
        pyobf_native_contribution_site_v1(expected, 503);
        result = value * 2; break;
    case 2:
        pyobf_native_contribution_site_v1(expected, 504);
        result = 17; break;
    default:
        pyobf_native_contribution_site_v1(expected, 505);
        result = value - 5;
    }
    return result + ((value & 1) ? 3 : 0);
}
