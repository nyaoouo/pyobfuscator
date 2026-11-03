#include "checks.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <utility>

namespace context_test {
namespace {
struct State {
    unsigned calls = 0, destroyed = 0;
    BootstrapContextBinding *binding = nullptr;
    BootstrapContextOwner *owner = nullptr;
    BootstrapContextLease *expected = nullptr, *replacement = nullptr;
    bool rebind_on_destroy = false;
};
void rebind(State &state) noexcept {
    auto next = bind_bootstrap_context(*state.replacement);
    require(next.status == Status::ok, "reentrant replacement can publish without lock recursion");
    *state.binding = std::move(next.binding);
}
BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.calls;
    if (request.operation_id == 9) {
        state.binding->reset();
        require(call_bound_bootstrap(*state.expected, {1}).status == Status::unavailable, "reentrant unpublish takes effect");
        rebind(state);
        *state.owner = {};
        state.expected->reset();
        require(state.destroyed == 0, "captured strict call and frame retain old state");
    }
    return {Status::ok, request.operation_id + 10};
}
void destroy(void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.destroyed;
    if (state.rebind_on_destroy) rebind(state);
}
BootstrapContextSpec spec(State &state) { return {bootstrap_context_abi_version, dispatch, &state, destroy}; }
}

void check_binding_reentrancy() {
    State first, second;
    auto a = create_bootstrap_context(spec(first)), b = create_bootstrap_context(spec(second));
    auto expected = a.owner.lease(), replacement = b.owner.lease();
    auto scope = bind_bootstrap_context(expected);
    first.binding = &scope.binding;
    first.owner = &a.owner;
    first.expected = &expected;
    first.replacement = &replacement;
    require(call_bound_bootstrap(expected, {9}).value == 19 && first.destroyed == 1,
            "reentrant unpublish/rebind/owner reset finishes old call");
    require(call_bound_bootstrap(replacement, {2}).value == 12, "new scope survives old captured cleanup");
    scope.binding.reset();

    State previous;
    auto old = create_bootstrap_context(spec(previous));
    auto old_expected = old.owner.lease();
    auto cleanup = bind_bootstrap_context(old_expected);
    previous.binding = &cleanup.binding;
    previous.replacement = &replacement;
    previous.rebind_on_destroy = true;
    old.owner = {};
    old_expected.reset();
    cleanup.binding.reset();
    require(previous.destroyed == 1 && cleanup.binding.generation() == replacement.generation() &&
            call_bound_bootstrap(replacement, {3}).value == 13,
            "final destructor rebind survives resetting token's old scope");
    cleanup.binding = {};
    require(call_bound_bootstrap(replacement, {1}).status == Status::unavailable, "move-reset releases replacement scope");
}
}  // namespace context_test
