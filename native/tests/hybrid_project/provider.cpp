#include "api.hpp"

namespace {
HybridCallback expected_callback = nullptr;
}

extern "C" HYBRID_PROVIDER_API void callback_register(HybridCallback callback) {
    expected_callback = callback;
}

extern "C" HYBRID_PROVIDER_API int callback_dispatch(HybridCallback callback, int depth, int mode, int *effects) {
    if (callback != expected_callback) throw -9000;
    *effects += 2;
    return callback(depth, mode, effects) + 3;
}
