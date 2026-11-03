#include "pyobfuscator_native/contribution_marker.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

extern pyobfuscator::native::BootstrapContextLease contribution_fixture_expected;
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
extern "C" int contribution_archive_value(const pyobfuscator::native::BootstrapContextLease &, int) noexcept;
#endif
#ifdef PYOBF_CONTRIBUTION_PREPARATION_TEST
extern "C" int contribution_preparation_defined(int) noexcept;
extern "C" int contribution_preparation_imported(int) noexcept;
#endif

#ifndef PYOBF_CONTRIBUTION_NORMALIZER_TEST
extern "C" PYOBF_NATIVE_CFF int contribution_compute(
    const pyobfuscator::native::BootstrapContextLease &expected, int value) noexcept {
    pyobf_native_contribution_site_v1(expected, 101);
#ifdef PYOBF_CONTRIBUTION_PREPARATION_TEST
#ifdef PYOBF_CONTRIBUTION_SCALAR_DONOR_TEST
    const int argument_bit = value & 1;
#endif
    volatile int retained = value;
    value = contribution_preparation_imported(contribution_preparation_defined(retained));
#ifdef PYOBF_CONTRIBUTION_SCALAR_DONOR_TEST
    value += argument_bit;
#endif
#endif
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    value = contribution_archive_value(expected, value);
#endif
    int total = 0;
    for (int index = 0; index != (value & 3) + 1; ++index) {
        pyobf_native_contribution_site_v1(expected, 202);
        total += (value + index) & 1 ? value + 5 : value - 3;
    }
    pyobf_native_contribution_site_v1(expected, 303);
    return total + 11;
}
#else
extern "C" int contribution_compute(const pyobfuscator::native::BootstrapContextLease &, int) noexcept;
#endif

extern "C" PYOBF_NATIVE_CFF int contribution_compute_global(int value) noexcept {
    pyobf_native_contribution_site_v1(contribution_fixture_expected, 404);
    return contribution_compute(contribution_fixture_expected, value);
}
