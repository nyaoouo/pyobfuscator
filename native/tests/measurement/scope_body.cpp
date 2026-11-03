#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern "C" int measured_scope_effect(pyobfuscator::native::contribution::scoped::Scope &, int, int) noexcept(false);
extern "C" PYOBF_NATIVE_CFF int measured_scope_body(pyobfuscator::native::contribution::scoped::Scope &scope, int value) noexcept(false) {
    pyobf_native_measured_contribution_site_v1(scope, 701);
    volatile int input = value;
    int result;
    if (input < 0) result = -input + 11;
    else if (input == 0) result = 17;
    else result = input * 3 + 1;
    return measured_scope_effect(scope, value, result);
}
