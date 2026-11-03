#include "pyobfuscator_native/cff_marker.hpp"

extern "C" PYOBF_NATIVE_CFF int contribution_preparation_defined(int value) noexcept {
    volatile int retained = value;
    return retained;
}
#ifdef PYOBF_CONTRIBUTION_INTERNAL_THROW_TEST
extern "C" int contribution_may_throw(int);
extern "C" PYOBF_NATIVE_CFF int contribution_preparation_throwing(int value) {
    return contribution_may_throw(value);
}
#endif
