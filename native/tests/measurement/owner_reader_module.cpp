#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "owner_readers.hpp"

namespace { unsigned *detached = nullptr; }

extern "C" __declspec(dllexport) const pyobfuscator::native::measurement::observer::ReaderBinding *
pyobf_test_owner_readers(unsigned *counter) noexcept {
    detached = counter;
    return pyobfuscator::native::measurement::generated_readers::bindings;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH && detached != nullptr) ++*detached;
    return TRUE;
}
