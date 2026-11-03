#pragma once

#if defined(__clang__)
#define PYOBF_NATIVE_CFF __attribute__((annotate("pyobf.native.cff"), noinline, used))
#define PYOBF_NATIVE_CFF_SDK __attribute__((annotate("pyobf.native.sdk"), noinline, used))
#define PYOBF_NATIVE_CFF_BOOTSTRAP __attribute__((annotate("pyobf.native.bootstrap"), noinline, used))
#define PYOBF_NATIVE_CFF_BOOTSTRAP_EH __attribute__((annotate("pyobf.native.bootstrap.eh"), noinline, used))
#else
#define PYOBF_NATIVE_CFF
#define PYOBF_NATIVE_CFF_SDK
#define PYOBF_NATIVE_CFF_BOOTSTRAP
#define PYOBF_NATIVE_CFF_BOOTSTRAP_EH
#endif
