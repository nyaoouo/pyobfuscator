#include "api.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace {
struct EffectGuard {
    int *effects;
    ~EffectGuard() { ++*effects; }
};

__attribute__((noinline)) int callback_leaf(int mode) {
    if (mode != 0) throw -mode;
    return 11;
}
}

extern "C" HYBRID_SUBJECT_API PYOBF_NATIVE_CFF int hybrid_callback(int depth, int mode, int *effects) {
    EffectGuard guard{effects};
    try {
        const auto value = depth > 0 ? callback_dispatch(hybrid_callback, depth - 1, mode, effects) : callback_leaf(mode);
        return whole_callback_result(value);
    } catch (int error) {
        *effects += 8;
        if (mode == 2) throw;
        return 100 + error;
    }
}
