#include "contribution/scope.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace scoped = pyobfuscator::native::contribution::scoped;
extern "C" scoped::Scope edge_scope_first_global;
extern "C" scoped::Scope edge_scope_second_global;
extern "C" int site_scope_effect(scoped::Scope &, scoped::Scope &, int) noexcept(false);
extern "C" int edge_scope_negative(int) noexcept;
extern "C" int edge_scope_zero(int) noexcept;
extern "C" int edge_scope_positive(int) noexcept;

extern "C" PYOBF_NATIVE_CFF int multi_scope_edge_body(int value) noexcept(false) {
    pyobf_native_measured_contribution_site_v1(edge_scope_first_global, 701);
    pyobf_native_measured_contribution_site_v1(edge_scope_second_global, 702);
    volatile int input = value;
    int selected;
    if (input < 0) selected = edge_scope_negative(input);
    else if (input == 0) selected = edge_scope_zero(input);
    else selected = edge_scope_positive(input);
    return site_scope_effect(edge_scope_first_global, edge_scope_second_global, selected);
}
