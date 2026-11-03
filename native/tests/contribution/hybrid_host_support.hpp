#pragma once

#include <atomic>
#include <thread>
#include <vector>

extern "C" int contribution_hybrid(const pyobfuscator::native::BootstrapContextLease &, int);
extern pyobfuscator::native::BootstrapContextLease contribution_fixture_expected;
#ifdef PYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST
extern "C" int contribution_hybrid_literal(const pyobfuscator::native::BootstrapContextLease &, int);
#endif

namespace {
std::atomic<unsigned> hybrid_cleanups{0};
std::atomic<bool> hybrid_nested_failure{false};
int hybrid_reference(int value) {
    const auto normal = value == -3 || value == 3 ? 2 * value + 17 : 2 * value + 7 + ((value & 1) ? 3 : -7);
#ifdef PYOBF_CONTRIBUTION_ARCHIVE_TEST
    const auto index = static_cast<unsigned>(value) & 3;
    return normal + (index == 0 ? 72 : index == 1 ? 121 : index == 2 ? 0 : 255) +
        static_cast<int>((static_cast<unsigned>(value) * 5u + 7u) & 63u);
#else
    return normal;
#endif
}
}
extern "C" void contribution_cleanup(int) noexcept { hybrid_cleanups.fetch_add(1); }
extern "C" int contribution_may_throw(int value) {
    if (value == -13) throw 2.5;
    if (value == -3 || value == 3) throw value + 11;
    if (value == 9 && contribution_hybrid(contribution_fixture_expected, 8) != hybrid_reference(8))
        hybrid_nested_failure.store(true);
    return 2 * value + 1;
}

namespace {
bool hybrid_run(const pyobfuscator::native::BootstrapContextLease &lease) {
#ifdef PYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST
    const auto scalar_before = hybrid_cleanups.load();
    for (int value : {5, 6, 3, -13}) {
        try {
            if (contribution_hybrid_literal(lease, value) != 41 || value == 3 || value == -13) return false;
        } catch (int token) {
            if (value != 3 || token != 14) return false;
        } catch (double token) {
            if (value != -13 || token != 2.5) return false;
        }
    }
    if (hybrid_cleanups.load() != scalar_before + 4) return false;
#endif
    const auto before = hybrid_cleanups.load();
    unsigned expected = 0;
    for (int value = -13; value <= 13; ++value) {
        ++expected;
        if (value == 9) ++expected;
        try {
            const auto result = contribution_hybrid(lease, value);
            if (value == -13 || result != hybrid_reference(value)) return false;
        } catch (double token) {
            if (value != -13 || token != 2.5) return false;
        }
    }
    if (hybrid_cleanups.load() != before + expected || hybrid_nested_failure.load()) return false;
    const auto parallel_before = hybrid_cleanups.load();
    std::atomic<bool> failed{false};
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker != 4; ++worker)
        threads.emplace_back([&] {
            for (int value = -8; value <= 8; ++value)
                if (contribution_hybrid(lease, value) != hybrid_reference(value)) failed.store(true);
#ifdef PYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST
            for (int value : {5, 6}) {
                try { if (contribution_hybrid_literal(lease, value) != 41) failed.store(true); }
                catch (...) { failed.store(true); }
            }
#endif
        });
    for (auto &thread : threads) thread.join();
    return !failed.load() && hybrid_cleanups.load() == parallel_before + 68
#ifdef PYOBF_CONTRIBUTION_HYBRID_SCALAR_TEST
        + 8
#endif
        ;
}
}
