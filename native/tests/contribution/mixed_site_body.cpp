#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/contribution_marker.hpp"

namespace native = pyobfuscator::native;
namespace scoped = native::contribution::scoped;
extern "C" int mixed_site_effect(native::BootstrapContextLease &, scoped::Scope &, int) noexcept(false);

extern "C" PYOBF_NATIVE_CFF int mixed_site_body(native::BootstrapContextLease &owned,
        scoped::Scope &measured, int value) noexcept(false) {
    pyobf_native_contribution_site_v1(owned, 701);
    volatile int input = value;
    const int selected = input < 0 ? -input + 11 : input == 0 ? 17 : input * 3 + 1;
    pyobf_native_measured_contribution_site_v1(measured, 702);
    return mixed_site_effect(owned, measured, selected);
}
