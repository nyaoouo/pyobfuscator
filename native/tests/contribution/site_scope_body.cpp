#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace scoped = pyobfuscator::native::contribution::scoped;
extern "C" int site_scope_effect(scoped::Scope &, scoped::Scope &, int) noexcept(false);

extern "C" PYOBF_NATIVE_CFF int site_scope_body(scoped::Scope &first, scoped::Scope &second,
        int value) noexcept(false) {
    pyobf_native_measured_contribution_site_v1(first, 701);
    volatile int input = value;
    const int selected = input < 0 ? -input + 11 : input == 0 ? 17 : input * 3 + 1;
    pyobf_native_measured_contribution_site_v1(second, 702);
    return site_scope_effect(first, second, selected);
}
