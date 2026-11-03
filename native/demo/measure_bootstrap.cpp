#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using Run = int (*)(int, int, void (*)(std::uint32_t, void *), void *);
constexpr unsigned startup_samples = 16, repeated_samples = 7, repeated_iterations = 24;
volatile std::uint64_t sink = 0;

void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "bootstrap measurement failed: %s (%lu)\n", message, GetLastError()); std::exit(1); }
}
Run symbol(HMODULE module) {
    require(module != nullptr, "load outer image");
    const auto result = reinterpret_cast<Run>(GetProcAddress(module, "pyobf_native_demo_run"));
    require(result != nullptr, "resolve outer entry");
    return result;
}
int expected(int value, bool decoy) {
    if (decoy) return value > 0 ? 101 : value < 0 ? 202 : 303;
    return value < 0 ? -value + 11 : value == 0 ? 17 : value * 3 + 1;
}
double startup(const char *path, int corrupt, bool decoy) {
    const auto begin = Clock::now();
    const auto module = LoadLibraryA(path);
    require(symbol(module)(7, corrupt, nullptr, nullptr) == expected(7, decoy), "startup full-release result");
    require(FreeLibrary(module) != 0, "release outer caller reference");
    return std::chrono::duration<double, std::micro>(Clock::now() - begin).count();
}
double repeated(Run run, int corrupt, bool decoy) {
    std::uint64_t checksum = 0;
    const auto begin = Clock::now();
    for (unsigned index = 0; index != repeated_iterations; ++index) {
        const int value = static_cast<int>(index % 17) - 8;
        const int result = run(value, corrupt, nullptr, nullptr);
        require(result == expected(value, decoy), "repeated full-release result");
        checksum += static_cast<std::uint32_t>(result);
    }
    sink = checksum;
    return std::chrono::duration<double, std::micro>(Clock::now() - begin).count() / repeated_iterations;
}
double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    return values[values.size() / 2];
}
}

int main(int argc, char **argv) {
    require(argc == 5, "plain/protected image, corrupt flag and expected role supplied");
    const int corrupt = std::atoi(argv[3]);
    const bool decoy = std::atoi(argv[4]) != 0;
    std::vector<double> plain_startup, protected_startup, plain_repeated, protected_repeated;
    for (unsigned sample = 0; sample != startup_samples; ++sample) {
        if (sample % 2 == 0) {
            plain_startup.push_back(startup(argv[1], corrupt, decoy));
            protected_startup.push_back(startup(argv[2], corrupt, decoy));
        } else {
            protected_startup.push_back(startup(argv[2], corrupt, decoy));
            plain_startup.push_back(startup(argv[1], corrupt, decoy));
        }
    }
    const auto plain_module = LoadLibraryA(argv[1]), protected_module = LoadLibraryA(argv[2]);
    const auto plain = symbol(plain_module), protected_run = symbol(protected_module);
    for (unsigned sample = 0; sample != repeated_samples; ++sample) {
        if (sample % 2 == 0) {
            plain_repeated.push_back(repeated(plain, corrupt, decoy));
            protected_repeated.push_back(repeated(protected_run, corrupt, decoy));
        } else {
            protected_repeated.push_back(repeated(protected_run, corrupt, decoy));
            plain_repeated.push_back(repeated(plain, corrupt, decoy));
        }
    }
    require(FreeLibrary(protected_module) != 0 && FreeLibrary(plain_module) != 0, "release retained outer images");
    std::printf("plain_startup_us=%.6f\nprotected_startup_us=%.6f\nplain_repeated_release_us=%.6f\nprotected_repeated_release_us=%.6f\n",
                median(plain_startup), median(protected_startup), median(plain_repeated), median(protected_repeated));
    std::printf("startup_samples=%u\nrepeated_samples=%u\nrepeated_iterations=%u\n",
                startup_samples, repeated_samples, repeated_iterations);
}
