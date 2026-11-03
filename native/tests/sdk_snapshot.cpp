#include "pyobfuscator_native/bootstrap_api.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

namespace {
using namespace pyobfuscator::native;
void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "SDK snapshot check failed: %s\n", message); std::exit(1); }
}
struct State { int value; std::atomic<unsigned> calls{0}; };
int first(std::uint32_t operation, void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.calls;
    return state.value * 7 + static_cast<int>(operation);
}
int second(std::uint32_t operation, void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.calls;
    return state.value * 13 + static_cast<int>(operation);
}
void stage(std::uint32_t, void *) {}
bool install_local(State &state) {
    const BootstrapApi local{bootstrap_abi_version, first, stage, &state};
    return bind_bootstrap_api(&local);
}

void mutation() {
    State a{17}, b{31};
    BootstrapApi api{bootstrap_abi_version, first, stage, &a};
    require(bind_bootstrap_api(&api), "valid table bound");
    api = {bootstrap_abi_version, second, stage, &b};
    require(call_bootstrap(0) == 119 && a.calls.load() == 1 && b.calls.load() == 0,
            "later table mutation cannot alter the owned descriptor snapshot");
    unbind_bootstrap_api();
}

void lifetime() {
    State state{17};
    require(install_local(state) && call_bootstrap(2) == 121, "table object may expire after bind returns");
    const BootstrapApi invalid{0, second, stage, &state};
    require(!bind_bootstrap_api(&invalid) && !bind_bootstrap_api(nullptr) && call_bootstrap(3) == 122,
            "invalid bind leaves complete prior snapshot unchanged");
    unbind_bootstrap_api();
    require(call_bootstrap(1) == -1, "unbind clears snapshot");
}

void concurrent_snapshots() {
    State a{17}, b{31};
    const BootstrapApi api_a{bootstrap_abi_version, first, stage, &a};
    const BootstrapApi api_b{bootstrap_abi_version, second, stage, &b};
    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i != 4; ++i) workers.emplace_back([&] {
        while (!start.load()) std::this_thread::yield();
        for (unsigned n = 0; n != 5000; ++n) {
            const int result = call_bootstrap(0);
            require(result == -1 || result == 119 || result == 403, "concurrent snapshot cannot tear callback/context pairing");
        }
    });
    start.store(true);
    for (unsigned n = 0; n != 3000; ++n) {
        require(bind_bootstrap_api(n % 2 == 0 ? &api_a : &api_b), "concurrent bind");
        if (n % 8 == 0) unbind_bootstrap_api();
    }
    for (auto &worker : workers) worker.join();
    unbind_bootstrap_api();
}

int reenter(std::uint32_t, void *data) noexcept {
    unbind_bootstrap_api();
    require(bind_bootstrap_api(static_cast<const BootstrapApi *>(data)), "callback can replace legacy publication");
    return call_bootstrap(0);
}
void reentrancy() {
    State state{17};
    const BootstrapApi next{bootstrap_abi_version, first, stage, &state};
    const BootstrapApi initial{bootstrap_abi_version, reenter, stage, const_cast<BootstrapApi *>(&next)};
    require(bind_bootstrap_api(&initial) && call_bootstrap(0) == 119, "no publication lock is held over callback");
    unbind_bootstrap_api();
}

struct BlockingState { std::atomic<bool> entered{false}, proceed{false}; };
int blocked(std::uint32_t, void *data) noexcept {
    auto &state = *static_cast<BlockingState *>(data);
    state.entered.store(true);
    while (!state.proceed.load()) std::this_thread::yield();
    return 42;
}
void in_flight() {
    BlockingState state;
    const BootstrapApi api{bootstrap_abi_version, blocked, stage, &state};
    require(bind_bootstrap_api(&api), "blocking callback bound");
    std::thread worker([] { require(call_bootstrap(0) == 42, "captured legacy callback finishes after unbind"); });
    while (!state.entered.load()) std::this_thread::yield();
    unbind_bootstrap_api();
    require(call_bootstrap(0) == -1, "unbind stops later legacy capture");
    // Caller-owned userdata/code must remain alive until the already captured call returns.
    state.proceed.store(true);
    worker.join();
}
}

int main(int argc, char **) {
    mutation();
    if (argc == 1) {
        lifetime();
        concurrent_snapshots();
        reentrancy();
        in_flight();
    }
    std::puts("legacy SDK snapshot verified");
}
