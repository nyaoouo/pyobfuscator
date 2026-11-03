#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/capture.hpp"
#include "reference_slots.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace measurement = pyobfuscator::native::measurement;
namespace reference = measurement::reference;
namespace reserved = measurement::reserved;

extern "C" __declspec(dllexport) int slot_anchor(int value) { return value * 7 + 3; }

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    std::uint32_t words[8]{};
    auto *file = std::fopen(argv[1], "rb");
    if (!file) return 2;
    const auto count = std::fread(words, sizeof(words), 1, file);
    const auto extra = std::fgetc(file);
    if (std::fclose(file) || count != 1 || extra != EOF) return 3;
    auto module = LoadLibraryA(argv[2]);
    if (!module) return 4;
    auto target = reinterpret_cast<pyobfuscator::native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    if (!target) return 5;
    const auto self = reinterpret_cast<pyobfuscator::native::platform::CodeAddress>(&slot_anchor);
    const bool wanted = std::strtoul(argv[3], nullptr, 10) != 0;
    bool ok = true;
    // Independently compiled identities/offsets never come from the slot directory.
    for (std::size_t index = 0; index != reserved::count; ++index) {
        const auto &identity = reserved::identities[index];
        auto decoded = reference::open(reserved::data + reserved::offsets[index], identity.capacity, identity, words);
        if (decoded.status() != reference::Status::ok) {
            std::fprintf(stderr, "reference authentication/descriptor failure at %zu\n", index);
            ok = false; break;
        }
        auto observed = measurement::capture(decoded.descriptor(), index == 0 ? self : target);
        if (observed.data().status != measurement::Status::ok ||
                (std::memcmp(observed.data().digest, decoded.expected_digest(), 32) == 0) != wanted) {
            std::fprintf(stderr, "actual code mismatch at %zu\n", index);
            ok = false; break;
        }
    }
    if (!FreeLibrary(module)) return 6;
    if (!ok) return 7;
    std::puts("reserved references authenticate and match independently observed final code");
    return 0;
}
