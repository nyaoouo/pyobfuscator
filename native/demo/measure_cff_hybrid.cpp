#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <utility>
#include <vector>
#include <windows.h>

// Host measurement operations are separate from the protected runtime/backend.
#define PYOBF_MEASURE_LOAD(path) LoadLibraryA(path)
#define PYOBF_MEASURE_SYMBOL(module, name) GetProcAddress(module, name)
#define PYOBF_MEASURE_CLOSE(module) FreeLibrary(module)

namespace {
using Clock = std::chrono::steady_clock;
using Compute = int (*)(int, int, int *);
constexpr unsigned startup_samples = 20, hot_samples = 7;
volatile std::uint64_t sink = 0;

[[noreturn]] void fail(const char *reason) {
    std::cerr << reason << '\n';
    std::exit(2);
}

std::pair<HMODULE, Compute> open(const char *path) {
    const auto module = PYOBF_MEASURE_LOAD(path);
    if (module == nullptr) fail("cannot load hybrid measurement module");
    const auto compute = reinterpret_cast<Compute>(PYOBF_MEASURE_SYMBOL(module, "hybrid_measure"));
    if (compute == nullptr) fail("missing hybrid measurement export");
    return {module, compute};
}

std::uint64_t checked(Compute compute, int input, int mode) {
    int effects = 0, value = 0;
    bool threw = false;
    try { value = compute(input, mode, &effects); }
    catch (int error) {
        if (mode != 2 || error != input + 23) fail("hybrid measurement changed thrown value");
        threw = true;
        value = 1000 + error;
    }
    const auto expected = mode == 0 ? input * 3 + 7 + (input < 0 ? -5 : 9) :
                          mode == 1 ? (input + 23) * 2 : input + 1023;
    if (threw != (mode == 2) || value != expected || effects != (mode == 0 ? 1 : 9))
        fail("hybrid measurement changed result, rethrow or guard effects");
    return static_cast<std::uint32_t>(value) + (static_cast<std::uint64_t>(effects) << 32);
}

double startup_once(const char *path, int mode) {
    const auto start = Clock::now();
    const auto [module, compute] = open(path);
    sink = checked(compute, 7, mode);
    if (!PYOBF_MEASURE_CLOSE(module)) fail("cannot unload hybrid measurement module");
    return std::chrono::duration<double, std::micro>(Clock::now() - start).count();
}

std::pair<double, std::uint64_t> hot_once(Compute compute, int mode, unsigned iterations) {
    std::uint64_t checksum = 0;
    const auto start = Clock::now();
    for (unsigned index = 0; index < iterations; ++index)
        checksum += checked(compute, static_cast<int>(index % 17) - 8, mode);
    const auto elapsed = Clock::now() - start;
    sink = checksum;
    return {std::chrono::duration<double, std::nano>(elapsed).count() / iterations, checksum};
}

void samples(const char *name, const std::vector<double> &values) {
    std::cout << '"' << name << "\":[";
    for (unsigned index = 0; index < values.size(); ++index) {
        if (index != 0) std::cout << ',';
        std::cout << values[index];
    }
    std::cout << ']';
}
}

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    const int mode = std::atoi(argv[3]);
    if (mode < 0 || mode > 2) return 1;
    const unsigned iterations = mode == 0 ? 500000 : 2000;
    std::vector<double> baseline_startup, protected_startup, baseline_hot, protected_hot;
    for (unsigned sample = 0; sample < startup_samples; ++sample) {
        if (sample % 2 == 0) {
            baseline_startup.push_back(startup_once(argv[1], mode));
            protected_startup.push_back(startup_once(argv[2], mode));
        } else {
            protected_startup.push_back(startup_once(argv[2], mode));
            baseline_startup.push_back(startup_once(argv[1], mode));
        }
    }
    const auto [baseline_module, baseline] = open(argv[1]);
    const auto [protected_module, protected_code] = open(argv[2]);
    for (unsigned index = 0; index < 64; ++index) {
        checked(baseline, static_cast<int>(index % 17) - 8, mode);
        checked(protected_code, static_cast<int>(index % 17) - 8, mode);
    }
    std::uint64_t checksum = 0;
    for (unsigned sample = 0; sample < hot_samples; ++sample) {
        std::pair<double, std::uint64_t> first, second;
        if (sample % 2 == 0) {
            first = hot_once(baseline, mode, iterations);
            second = hot_once(protected_code, mode, iterations);
        } else {
            second = hot_once(protected_code, mode, iterations);
            first = hot_once(baseline, mode, iterations);
        }
        if (first.second != second.second) fail("hybrid measurement checksum differs");
        checksum = first.second;
        baseline_hot.push_back(first.first);
        protected_hot.push_back(second.first);
    }
    if (!PYOBF_MEASURE_CLOSE(baseline_module) || !PYOBF_MEASURE_CLOSE(protected_module))
        fail("cannot close hybrid measurement modules");
    std::cout << std::setprecision(17) << '{';
    samples("baseline_startup_us", baseline_startup); std::cout << ',';
    samples("protected_startup_us", protected_startup); std::cout << ',';
    samples("baseline_hot_ns", baseline_hot); std::cout << ',';
    samples("protected_hot_ns", protected_hot);
    std::cout << ",\"startup_samples\":" << startup_samples << ",\"hot_samples\":" << hot_samples
              << ",\"hot_iterations\":" << iterations << ",\"warmup_calls_per_image\":64"
              << ",\"checksum\":" << checksum << "}\n";
}
