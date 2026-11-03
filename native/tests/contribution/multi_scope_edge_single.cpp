#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace scoped = pyobfuscator::native::contribution::scoped;

extern "C" PYOBF_NATIVE_CFF int multi_scope_edge_body(scoped::Scope &only, int value) noexcept {
    pyobf_native_measured_contribution_site_v1(only, 701);
    volatile int input = value;
    if (input < 0) return input - 1;
    return input + 1;
}
