#include "checks.hpp"

#include <thread>
#include <vector>

namespace context_test {
namespace {
struct ConcurrentState {
    std::atomic<unsigned> entered{0}, finished{0}, destroyed{0};
    std::atomic<bool> proceed{false};
};

BootstrapContextResult dispatch(const BootstrapContextRequest &, void *data) noexcept {
    auto &state = *static_cast<ConcurrentState *>(data);
    state.entered.fetch_add(1);
    while (!state.proceed.load()) std::this_thread::yield();
    require(state.destroyed.load() == 0, "active callback state alive");
    state.finished.fetch_add(1);
    return {Status::ok, 71};
}
void destroy(void *data) noexcept { static_cast<ConcurrentState *>(data)->destroyed.fetch_add(1); }
}

void check_concurrency() {
    ConcurrentState state;
    auto created = create_bootstrap_context({bootstrap_context_abi_version, dispatch, &state, destroy});
    require(created.status == Status::ok, "threaded context created");
    auto lease = created.owner.lease();
    std::vector<std::thread> workers;
    for (unsigned i = 0; i != 4; ++i) workers.emplace_back([copy = lease]() mutable {
        for (unsigned n = 0; n != 1000; ++n) {
            auto next = copy;
            copy = next;
        }
        require(copy.invoke({1}).value == 71, "admitted threaded callback completes");
        for (unsigned n = 0; n != 1000; ++n) {
            auto next = copy;
            require(next.invoke({1}).status == Status::closed, "closed copies reject new calls");
        }
    });
    while (state.entered.load() != 4) std::this_thread::yield();
    require(!created.owner.quiescent() && created.owner.close() == Status::busy, "close does not wait on four frames");
    created.owner = {};
    lease.reset();
    require(state.destroyed.load() == 0, "workers keep state alive without owner");
    state.proceed.store(true);
    for (auto &worker : workers) worker.join();
    require(state.finished.load() == 4 && state.destroyed.load() == 1, "last worker cleans once");
}
}  // namespace context_test
