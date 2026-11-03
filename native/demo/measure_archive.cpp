// Measurement harness only; production system operations remain in target backends.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using Compute = std::uint32_t (*)(std::int32_t);
using Pointer = const std::uint8_t *(*)();
constexpr unsigned cold_samples = 21, hot_samples = 7, hot_iterations = 3000;
constexpr unsigned char prefix[] = "native-archive-measurement";
volatile std::uint64_t sink = 0;

[[noreturn]] void fail(const char *message) {
    std::cerr << message << '\n';
    std::exit(2);
}

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    return values[values.size() / 2];
}

std::uint8_t expected_byte(unsigned index) {
    if (index < sizeof(prefix)) return prefix[index];
    if (index == sizeof(prefix)) return 0xff;
    return static_cast<std::uint8_t>(index - sizeof(prefix) - 1);
}

std::uint32_t expected(std::int32_t input) {
    return (std::uint32_t{expected_byte(static_cast<std::uint32_t>(input) & 31)} + 90) ^
        0xffffffffu ^ 0x56789abcu ^ 0x80000000u;
}

struct Module {
    HMODULE module;
    Compute compute;
    Pointer pointer;
    explicit Module(const char *path) : module(LoadLibraryA(path)) {
        if (module == nullptr) fail("cannot load archive benchmark image");
        compute = reinterpret_cast<Compute>(GetProcAddress(module, "archive_compute"));
        pointer = reinterpret_cast<Pointer>(GetProcAddress(module, "archive_pointer"));
        if (compute == nullptr || pointer == nullptr) fail("archive benchmark exports are missing");
    }
    ~Module() { FreeLibrary(module); }
    Module(const Module &) = delete;
    Module &operator=(const Module &) = delete;
    void check() const {
        const auto *data = pointer();
        if (data == nullptr || data != pointer()) fail("archive pointer is unstable");
        for (unsigned index = 0; index < 64; ++index)
            if (data[index] != expected_byte(index)) fail("archive benchmark bytes differ");
        for (int input = -64; input <= 64; ++input)
            if (compute(input) != expected(input)) fail("archive benchmark changed typed-data results");
    }
};

std::pair<double, double> cold(const char *path) {
    const auto start = Clock::now();
    double first_call;
    {
        Module module(path);
        const auto call_start = Clock::now();
        const auto result = module.compute(7);
        const auto call_end = Clock::now();
        if (result != expected(7)) fail("archive cold result differs");
        first_call = std::chrono::duration<double, std::micro>(call_end - call_start).count();
    }
    return {std::chrono::duration<double, std::micro>(Clock::now() - start).count(), first_call};
}

double hot(const Module &module) {
    std::uint64_t checksum = 0;
    const auto start = Clock::now();
    for (unsigned index = 0; index < hot_iterations; ++index)
        checksum += module.compute(static_cast<std::int32_t>(index % 17) - 8);
    const auto end = Clock::now();
    std::uint64_t reference = 0;
    for (unsigned index = 0; index < hot_iterations; ++index)
        reference += expected(static_cast<std::int32_t>(index % 17) - 8);
    if (checksum != reference) fail("archive hot checksum differs");
    sink = checksum;
    return std::chrono::duration<double, std::nano>(end - start).count() / hot_iterations;
}
}  // namespace

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    std::vector<double> first_load, second_load, first_call, second_call, first_hot, second_hot;
    for (unsigned sample = 0; sample < cold_samples; ++sample) {
        std::pair<double, double> first, second;
        if (sample % 2 == 0) { first = cold(argv[1]); second = cold(argv[2]); }
        else { second = cold(argv[2]); first = cold(argv[1]); }
        first_load.push_back(first.first); second_load.push_back(second.first);
        first_call.push_back(first.second); second_call.push_back(second.second);
    }
    Module first(argv[1]), second(argv[2]);
    if (first.module == second.module) fail("archive benchmark paths resolved to the same module");
    first.check(); second.check();
    for (unsigned sample = 0; sample < hot_samples; ++sample) {
        if (sample % 2 == 0) { first_hot.push_back(hot(first)); second_hot.push_back(hot(second)); }
        else { second_hot.push_back(hot(second)); first_hot.push_back(hot(first)); }
    }
    std::cout << "baseline_startup_us=" << median(first_load) << '\n';
    std::cout << "protected_startup_us=" << median(second_load) << '\n';
    std::cout << "baseline_first_call_us=" << median(first_call) << '\n';
    std::cout << "protected_first_call_us=" << median(second_call) << '\n';
    std::cout << "baseline_hot_ns=" << median(first_hot) << '\n';
    std::cout << "protected_hot_ns=" << median(second_hot) << '\n';
    std::cout << "cold_samples=" << cold_samples << '\n';
    std::cout << "hot_samples=" << hot_samples << '\n';
    std::cout << "hot_iterations=" << hot_iterations << '\n';
}
