#include "checks.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <thread>

namespace context_test {
namespace {
struct State { std::atomic<bool> entered{false}, proceed{false}; std::atomic<unsigned> destroyed{0}; };
BootstrapContextResult dispatch(const BootstrapContextRequest &, void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    state.entered.store(true);
    while (!state.proceed.load()) std::this_thread::yield();
    require(state.destroyed.load() == 0, "unpublished admitted callback remains alive");
    return {Status::ok, 83};
}
void destroy(void *data) noexcept { static_cast<State *>(data)->destroyed.fetch_add(1); }
}

void check_binding_concurrency() {
    State state;
    auto owned = create_bootstrap_context({bootstrap_context_abi_version, dispatch, &state, destroy});
    auto expected = owned.owner.lease();
    auto scope = bind_bootstrap_context(expected);
    require(scope.status == Status::ok, "concurrent publication");
    std::thread worker([copy = expected] { require(call_bound_bootstrap(copy, {1}).value == 83, "admitted strict call finishes"); });
    while (!state.entered.load()) std::this_thread::yield();
    scope.binding.reset();
    require(call_bound_bootstrap(expected, {1}).status == Status::unavailable, "unpublished endpoint rejects later call");
    require(owned.owner.close() == Status::busy, "admitted strict frame visible to owner close");
    owned.owner = {};
    expected.reset();
    require(state.destroyed.load() == 0, "unpublish and owner release cannot destroy worker state");
    state.proceed.store(true);
    worker.join();
    require(state.destroyed.load() == 1, "strict captured lease and frame clean once after worker");
}
}  // namespace context_test
