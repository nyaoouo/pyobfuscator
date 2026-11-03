#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace scoped = pyobfuscator::native::contribution::scoped;
extern "C" int site_scope_effect(scoped::Scope &, scoped::Scope &, int) noexcept(false);

extern "C" PYOBF_NATIVE_CFF int multi_scope_edge_body(scoped::Scope &first, scoped::Scope &second,
        int value) noexcept(false) {
    pyobf_native_measured_contribution_site_v1(first, 701);
    volatile int input = value;
    if (input < 0) {
        pyobf_native_measured_contribution_site_v1(second, 702);
        return site_scope_effect(first, second, -input + 11);
    }
    return site_scope_effect(first, second, input * 3 + 1);
}
