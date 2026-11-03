#include "pyobfuscator_native/cff_marker.hpp"

extern "C" PYOBF_NATIVE_CFF int pyobf_demo_decoy_compute(int value) {
    if (value < 0) return 202;
    if (value == 0) return 303;
    return 101;
}
