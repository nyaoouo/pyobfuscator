#if defined(PYOBF_MEASURE_MARKED)
#include "pyobfuscator_native/cff_marker.hpp"
#define PYOBF_MEASURE_ATTRIBUTE PYOBF_NATIVE_CFF
#else
#define PYOBF_MEASURE_ATTRIBUTE
#endif

extern "C" PYOBF_MEASURE_ATTRIBUTE int protected_value(int value) {
    return value * 3 + 5;
}

extern "C" __declspec(dllexport) int caller(int value) {
    return protected_value(value);
}
