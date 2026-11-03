#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace pyobfuscator::native::platform {

CodeLease retain_code(CodeAddress address) noexcept {
    if (address == nullptr) return {};
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCWSTR>(address), &module)) return {};
    return {module};
}

bool release_code(CodeLease lease) noexcept {
    return lease.module == nullptr || FreeLibrary(static_cast<HMODULE>(lease.module)) != 0;
}

}  // namespace pyobfuscator::native::platform
