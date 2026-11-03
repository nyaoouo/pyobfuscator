#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdlib>

namespace pyobfuscator::native::platform {

std::uint32_t native_byte_order() noexcept { return 1; }

[[noreturn]] void protection_failure(std::uint32_t reason) noexcept {
    TerminateProcess(GetCurrentProcess(), 0xe04f0000u | (reason & 0xffffu));
    std::abort();
}

}  // namespace pyobfuscator::native::platform
