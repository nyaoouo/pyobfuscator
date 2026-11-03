#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const auto image = LoadLibraryA(argv[1]);
    if (image == nullptr) return 3;
    const auto pointer = reinterpret_cast<const std::uint8_t *(*)(bool)>(GetProcAddress(image, "pointer"));
    const auto data = reinterpret_cast<std::uint64_t (*)()>(GetProcAddress(image, "data"));
    const auto floating = reinterpret_cast<double (*)(bool)>(GetProcAddress(image, "floating"));
    const auto pure = reinterpret_cast<int (*)()>(GetProcAddress(image, "pure"));
    const auto caller = reinterpret_cast<int (*)()>(GetProcAddress(image, "caller"));
    const auto recurse = reinterpret_cast<int (*)(unsigned)>(GetProcAddress(image, "recurse"));
    const char *names[]{"get_wide", "get_zeros", "get_nested", "get_number", "get_nan"};
    const std::uint8_t wide[]{0, 0xd8, 0x5a, 0, 0, 0}, zeros[8]{}, nested[]{'A', 'B', 'C', 'D'};
    const std::uint8_t number[]{0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0};
    const std::uint8_t nan[]{0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0xf8, 0x7f};
    const std::uint8_t *expected[]{wide, zeros, nested, number, nan};
    const std::size_t sizes[]{6, 8, 4, 8, 8};
    const std::uint8_t *(*getters[5])();
    for (unsigned index = 0; index < 5; ++index) {
        getters[index] = reinterpret_cast<const std::uint8_t *(*)()>(GetProcAddress(image, names[index]));
        if (getters[index] == nullptr) return 4;
    }
    if (pointer == nullptr || data == nullptr || floating == nullptr || pure == nullptr || caller == nullptr || recurse == nullptr) return 5;
    if (argc > 2) {
        if (std::strcmp(argv[2], "warm-probe") == 0) data();
        pointer(true);
        std::puts("DATA-CONSUMED");
        return 0;
    }
    std::atomic<bool> start{false};
    std::atomic<unsigned> failures{0};
    std::atomic<const void *> stable[7]{};
    const auto identity = [&](unsigned index, const void *value) {
        const void *empty = nullptr;
        stable[index].compare_exchange_strong(empty, value);
        return stable[index].load() == value;
    };
    std::vector<std::thread> threads;
    for (unsigned thread = 0; thread < 12; ++thread) threads.emplace_back([&] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (unsigned repeat = 0; repeat < 8; ++repeat) {
            const auto *yes = pointer(true), *no = pointer(false);
            const std::uint8_t tail[]{'B', 0xff, 'C', '!', 0};
            if (yes == nullptr || no == nullptr || std::memcmp(yes, tail, 5) ||
                !identity(0, yes) || !identity(1, no) ||
                data() != (0x1ffffffffull ^ 0x7ff8123456789abcull) || pure() != 7 || caller() != 16 ||
                recurse(8) != 21) ++failures;
            for (unsigned index = 0; index < 5; ++index) {
                const auto *value = getters[index]();
                if (value == nullptr || std::memcmp(value, expected[index], sizes[index]) ||
                    !identity(index + 2, value)) ++failures;
            }
            const auto positive = floating(true), negative = floating(false);
            std::uint64_t positive_bits, negative_bits;
            std::memcpy(&positive_bits, &positive, 8);
            std::memcpy(&negative_bits, &negative, 8);
            if (positive_bits != 0x8000000000000000ull || negative_bits != 0x7ff8000000000011ull) ++failures;
        }
    });
    start.store(true, std::memory_order_release);
    for (auto &thread : threads) thread.join();
    if (recurse(32) != 45 || failures != 0) return 6;
    FreeLibrary(image);
    std::puts("protected archive verified");
    return 0;
}
