#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
using Module = HMODULE;
Module open_module(const char *path) { return LoadLibraryA(path); }
void *find_symbol(Module module, const char *name) {
    return reinterpret_cast<void *>(GetProcAddress(module, name));
}
void close_module(Module module) { FreeLibrary(module); }
#else
#include <dlfcn.h>
using Module = void *;
Module open_module(const char *path) { return dlopen(path, RTLD_NOW); }
void *find_symbol(Module module, const char *name) { return dlsym(module, name); }
void close_module(Module module) { dlclose(module); }
#endif

namespace {

using Clock = std::chrono::steady_clock;
using Compute = int (*)(int);
constexpr int startup_samples = 40;
constexpr int hot_samples = 5;
constexpr int hot_iterations = 500000;
volatile std::uint64_t sink = 0;

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    return values[values.size() / 2];
}

Compute checked_symbol(Module module, const char *name) {
    auto *symbol = find_symbol(module, name);
    if (symbol == nullptr) {
        std::cerr << "benchmark DLL has no requested export\n";
        std::exit(2);
    }
    return reinterpret_cast<Compute>(symbol);
}

double startup_once(const char *path, const char *symbol, int expected) {
    const auto start = Clock::now();
    auto module = open_module(path);
    if (module == nullptr) {
        std::cerr << "cannot load benchmark DLL\n";
        std::exit(3);
    }
    auto compute = checked_symbol(module, symbol);
    if (compute(7) != expected) {
        std::cerr << "benchmark DLL changed function result\n";
        std::exit(4);
    }
    close_module(module);
    return std::chrono::duration<double, std::micro>(Clock::now() - start).count();
}

std::pair<double, std::uint64_t> hot_once(Compute compute) {
    std::uint64_t checksum = 0;
    const auto start = Clock::now();
    for (int index = 0; index < hot_iterations; ++index) {
        checksum += static_cast<std::uint32_t>(compute(index % 17 - 8));
    }
    const auto elapsed = Clock::now() - start;
    sink = checksum;
    return {std::chrono::duration<double, std::nano>(elapsed).count() /
                hot_iterations,
            checksum};
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 3 && argc != 5) {
        return 1;
    }
    const char *symbol = argc == 5 ? argv[3] : "pyobf_demo_compute";
    const int expected = argc == 5 ? std::atoi(argv[4]) : 22;
    std::vector<double> baseline_startup;
    std::vector<double> protected_startup;
    for (int sample = 0; sample < startup_samples; ++sample) {
        if (sample % 2 == 0) {
            baseline_startup.push_back(startup_once(argv[1], symbol, expected));
            protected_startup.push_back(startup_once(argv[2], symbol, expected));
        } else {
            protected_startup.push_back(startup_once(argv[2], symbol, expected));
            baseline_startup.push_back(startup_once(argv[1], symbol, expected));
        }
    }
    auto baseline_module = open_module(argv[1]);
    auto protected_module = open_module(argv[2]);
    if (baseline_module == nullptr || protected_module == nullptr) {
        std::cerr << "cannot load benchmark DLLs for hot calls\n";
        return 5;
    }
    auto baseline_compute = checked_symbol(baseline_module, symbol);
    auto protected_compute = checked_symbol(protected_module, symbol);
    std::vector<double> baseline_hot;
    std::vector<double> protected_hot;
    for (int sample = 0; sample < hot_samples; ++sample) {
        std::pair<double, std::uint64_t> baseline;
        std::pair<double, std::uint64_t> protected_code;
        if (sample % 2 == 0) {
            baseline = hot_once(baseline_compute);
            protected_code = hot_once(protected_compute);
        } else {
            protected_code = hot_once(protected_compute);
            baseline = hot_once(baseline_compute);
        }
        if (baseline.second != protected_code.second) {
            std::cerr << "benchmark DLLs disagree on hot-path results\n";
            return 6;
        }
        baseline_hot.push_back(baseline.first);
        protected_hot.push_back(protected_code.first);
    }
    close_module(baseline_module);
    close_module(protected_module);
    std::cout << "baseline_startup_us=" << median(baseline_startup) << '\n';
    std::cout << "protected_startup_us=" << median(protected_startup) << '\n';
    std::cout << "baseline_hot_ns=" << median(baseline_hot) << '\n';
    std::cout << "protected_hot_ns=" << median(protected_hot) << '\n';
    std::cout << "startup_samples=" << startup_samples << '\n';
    std::cout << "hot_samples=" << hot_samples << '\n';
    std::cout << "hot_iterations=" << hot_iterations << '\n';
    return 0;
}
