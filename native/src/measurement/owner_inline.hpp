#pragma once

#if defined(_MSC_VER)
#define PYOBF_NATIVE_OWNER_INLINE __forceinline
#else
#define PYOBF_NATIVE_OWNER_INLINE inline __attribute__((always_inline))
#endif
