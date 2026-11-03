#pragma once

#if defined(HYBRID_SUBJECT_BUILD)
#define HYBRID_SUBJECT_API __declspec(dllexport)
#else
#define HYBRID_SUBJECT_API __declspec(dllimport)
#endif

#if defined(HYBRID_PROVIDER_BUILD)
#define HYBRID_PROVIDER_API __declspec(dllexport)
#else
#define HYBRID_PROVIDER_API __declspec(dllimport)
#endif

using HybridCallback = int (*)(int depth, int mode, int *effects);

extern "C" {
HYBRID_SUBJECT_API int hybrid_callback(int depth, int mode, int *effects);
HYBRID_SUBJECT_API int whole_callback_result(int value);
HYBRID_PROVIDER_API void callback_register(HybridCallback callback);
HYBRID_PROVIDER_API int callback_dispatch(HybridCallback callback, int depth, int mode, int *effects);
}
