#include "api.hpp"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {
bool check(int depth, int mode, bool print) {
    int effects = 0, value;
    try { value = hybrid_callback(depth, mode, &effects); }
    catch (int error) { value = 500 + error; }
    const auto expected = mode == 2 ? 498 : (mode == 1 ? 99 : 23) + depth * 15;
    const auto expected_effects = depth * 3 + 1 + (mode == 2 ? (depth + 1) * 8 : mode == 1 ? 8 : 0);
    if (value != expected || effects != expected_effects) return false;
    if (print) std::printf("%d:%d:%d:%d\n", depth, mode, value, effects);
    return true;
}
}

int main() {
    callback_register(hybrid_callback);
    for (int depth = 0; depth < 5; ++depth) for (int mode = 0; mode < 3; ++mode)
        if (!check(depth, mode, true)) return 1;
    std::atomic<unsigned> failures{0};
    std::vector<std::thread> workers;
    for (unsigned worker = 0; worker < 4; ++worker) workers.emplace_back([&, worker] {
        for (unsigned iteration = 0; iteration < 64; ++iteration)
            if (!check((iteration + worker) % 5, (iteration + worker) % 3, false)) ++failures;
    });
    for (auto &worker : workers) worker.join();
    if (failures.load() != 0) return 2;
    std::puts("HYBRID_CALLBACK_THREADS_OK");
}
