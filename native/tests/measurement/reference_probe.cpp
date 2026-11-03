#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/reference.hpp"
#include "measurement/capture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <thread>
#include <utility>
#include <vector>

namespace {
namespace measurement = pyobfuscator::native::measurement;
namespace reference = measurement::reference;
namespace platform = pyobfuscator::native::platform;

void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "native code reference: %s\n", message); std::exit(1); }
}
std::vector<std::uint8_t> read(const char *path, std::size_t limit) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "open test input");
    std::vector<std::uint8_t> bytes;
    for (int byte; (byte = std::fgetc(file)) != EOF;) {
        require(bytes.size() < limit, "test input exceeds budget"); bytes.push_back(static_cast<std::uint8_t>(byte));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "read test input");
    return bytes;
}
bool blank(const reference::Reference &value) {
    const auto &descriptor = value.descriptor();
    if (descriptor.kind || descriptor.subject || descriptor.owner || descriptor.image_size || descriptor.preferred_base ||
            descriptor.ranges || descriptor.range_count || descriptor.fixups || descriptor.fixup_count) return false;
    for (unsigned index = 0; index != 32; ++index) if (value.expected_digest()[index]) return false;
    return true;
}
bool empty(const reference::Reference &value) { return value.status() == reference::Status::unavailable && blank(value); }
void measure(const std::vector<std::uint8_t> &package, const reference::Identity &identity,
        const std::uint32_t (&words)[8]) {
    LARGE_INTEGER frequency{};
    require(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0, "measurement clock");
    for (unsigned calls : {1u, 4u}) for (unsigned batch = 0; batch != 7; ++batch) {
        LARGE_INTEGER begin{}, end{};
        require(QueryPerformanceCounter(&begin) != 0, "measurement start");
        for (unsigned iteration = 0; iteration != 32; ++iteration) for (unsigned call = 0; call != calls; ++call) {
            auto value = reference::open(package.data(), package.size(), identity, words);
            require(value.status() == reference::Status::ok, "measured reference failed");
        }
        require(QueryPerformanceCounter(&end) && end.QuadPart >= begin.QuadPart, "measurement completion");
        std::printf("cost %u %.3f\n", calls, double(end.QuadPart - begin.QuadPart) * 1e9 / double(frequency.QuadPart) / 32.0);
    }
}
}

extern "C" __declspec(dllexport) int reference_anchor(int value) { return value * 3 + 7; }

int main(int argc, char **argv) {
    const bool cost = argc > 1 && std::strcmp(argv[argc - 1], "--cost") == 0;
    if (cost) --argc;
    require(argc == 5 || argc == 6, "metadata, package, expected status/match and optional module");
    auto metadata = read(argv[1], 84), package = read(argv[2], 512 * 1024 + 1);
    require(metadata.size() == 84, "test-only independent identity and private path words");
    static_assert(sizeof(reference::Identity) == 52);
    reference::Identity identity{};
    std::uint32_t words[8]{};
    std::memcpy(&identity, metadata.data(), sizeof(identity));
    std::memcpy(words, metadata.data() + sizeof(identity), sizeof(words));
    auto first = reference::open(package.data(), package.size(), identity, words);
    const auto wanted = static_cast<reference::Status>(std::strtoul(argv[3], nullptr, 10));
    require(first.status() == wanted, "reference failure source differs");
    if (wanted != reference::Status::ok) { require(blank(first), "failed reference retained metadata"); return 0; }
    auto second = reference::open(package.data(), package.size(), identity, words);
    auto assigned = reference::open(package.data(), package.size(), identity, words);
    require(second.status() == wanted && assigned.status() == wanted, "independent opens");
    auto moved = std::move(first); require(empty(first), "move retired original reference");
    assigned = std::move(moved); require(empty(moved), "replacement move retired source");
    require(assigned.descriptor().ranges != second.descriptor().ranges, "shared typed reference storage");
    reference::Reference concurrent[4]; std::thread workers[4];
    for (unsigned index = 0; index != 4; ++index) workers[index] = std::thread([&, index] {
        concurrent[index] = reference::open(package.data(), package.size(), identity, words);
    });
    for (auto &worker : workers) worker.join();
    for (unsigned index = 0; index != 4; ++index) {
        require(concurrent[index].status() == wanted && concurrent[index].descriptor().ranges != assigned.descriptor().ranges &&
            concurrent[index].descriptor().ranges != second.descriptor().ranges, "concurrent open shares storage or failed");
        for (unsigned other = 0; other != index; ++other)
            require(concurrent[index].descriptor().ranges != concurrent[other].descriptor().ranges, "concurrent owner storage alias");
    }
    if (cost) measure(package, identity, words);
    std::memset(package.data(), 0, package.size());
    auto member = reinterpret_cast<platform::CodeAddress>(&reference_anchor);
    HMODULE module = nullptr;
    if (argc == 6) {
        module = LoadLibraryA(argv[5]); require(module != nullptr, "load measured test module");
        member = reinterpret_cast<platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
        require(member != nullptr, "resolve measured test code");
    }
    auto observed = measurement::capture(assigned.descriptor(), member);
    require(observed.data().status == measurement::Status::ok, "actual native code observation");
    const bool matches = std::memcmp(observed.data().digest, assigned.expected_digest(), 32) == 0;
    require(matches == (std::strtoul(argv[4], nullptr, 10) != 0), "expected reference differs from actual code");
    require(std::memcmp(assigned.expected_digest(), second.expected_digest(), 32) == 0, "retired ciphertext changed owned reference");
    assigned.reset(); require(empty(assigned) && second.status() == wanted, "reset invalidated other owned snapshot");
    observed.reset();
    if (module != nullptr) require(FreeLibrary(module) != 0, "release measured test module");
    std::puts("actual CNG reference/observation, owned moves, independent concurrent decode and retired input pass");
}
