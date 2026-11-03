#include "release/record.hpp"

#if defined(_MSC_VER)
#pragma section(".pyobf", read)
#define PYOBF_RELEASE_DATA __declspec(allocate(".pyobf"))
#else
#define PYOBF_RELEASE_DATA __attribute__((section(".pyobf"), used))
#endif

namespace pyobfuscator::native::release {
PYOBF_RELEASE_DATA extern const Record record = {"PYOBF-RELKEY-v1", 1, 64, {}, {}};
}
