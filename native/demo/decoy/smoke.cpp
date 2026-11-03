#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "handoff.hpp"

#include <climits>
#include <cstdlib>

int main(int argc, char **argv) {
    using namespace pyobfuscator::native::demo;
    if (argc != 2 && argc != 3) return 2;
    auto *module = LoadLibraryA(argv[1]);
    if (module == nullptr) return 3;
    auto *entry = reinterpret_cast<DecoyEntry>(GetProcAddress(module, "pyobf_native_inner_entry"));
    if (entry == nullptr) { FreeLibrary(module); return 4; }
    const int positive = argc == 3 ? std::atoi(argv[2]) : 101;
    DecoyHandoff handoff{decoy_handoff_version, sizeof(DecoyHandoff), decoy_role, -2};
    bool okay = entry(nullptr, 5) == -110;
    constexpr int failures[]{-2, -4, -7, -8};
    for (auto failure : failures) {
        handoff.failure = failure;
        okay = okay && entry(&handoff, 5) == positive && entry(&handoff, INT_MAX) == positive &&
            entry(&handoff, 0) == 303 && entry(&handoff, INT_MIN) == 202;
    }
    handoff.abi_version = 0; okay = okay && entry(&handoff, 5) == -110;
    handoff.abi_version = decoy_handoff_version;
    handoff.size = 0; okay = okay && entry(&handoff, 5) == -110;
    handoff.size = sizeof(DecoyHandoff);
    handoff.role = 0; okay = okay && entry(&handoff, 5) == -110;
    handoff.role = decoy_role;
    handoff.failure = 0; okay = okay && entry(&handoff, 5) == -111;
    FreeLibrary(module);
    return okay ? 0 : 5;
}
