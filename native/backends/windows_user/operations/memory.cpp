#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace pyobfuscator::native::platform {

void *allocate(std::size_t size) noexcept {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void release(void *memory) noexcept {
    if (memory != nullptr) {
        HeapFree(GetProcessHeap(), 0, memory);
    }
}

void erase(void *memory, std::size_t size) noexcept {
    if (memory != nullptr) {
        SecureZeroMemory(memory, size);
    }
}

}  // namespace pyobfuscator::native::platform
