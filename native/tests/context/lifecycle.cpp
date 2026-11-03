#include "checks.hpp"

#include <utility>

namespace context_test {
namespace {
struct State {
    unsigned calls = 0, destroyed = 0;
    BootstrapContextOwner *owner = nullptr;
    BootstrapContextLease *lease = nullptr;
    BootstrapContextOwner *release_on_destroy = nullptr;
};

BootstrapContextResult dispatch(const BootstrapContextRequest &request, void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.calls;
    if (request.operation_id == 9) {
        require(state.owner->close() == Status::busy, "reentrant close reports an active frame");
        *state.owner = {};
        state.lease->reset();
        require(state.destroyed == 0, "frame owns state after owner and invoking lease reset");
    }
    const auto input = request.input_size == sizeof(unsigned) ? *static_cast<const unsigned *>(request.input) : 0;
    return {Status::ok, request.operation_id + input};
}

void destroy(void *data) noexcept {
    auto &state = *static_cast<State *>(data);
    ++state.destroyed;
    if (state.release_on_destroy != nullptr) *state.release_on_destroy = {};
}
BootstrapContextSpec spec(State &state) { return {bootstrap_context_abi_version, dispatch, &state, destroy}; }
}

void check_lifecycle() {
    State state;
    auto invalid = spec(state);
    invalid.abi_version = 0;
    require(create_bootstrap_context(invalid).status == Status::invalid_specification, "version rejected");
    invalid = spec(state);
    invalid.dispatch = nullptr;
    require(create_bootstrap_context(invalid).status == Status::invalid_specification, "missing dispatch rejected");
    invalid = spec(state);
    invalid.destroy = nullptr;
    require(create_bootstrap_context(invalid).status == Status::invalid_specification, "borrowed state rejected");
    require(state.destroyed == 0, "failure did not adopt state");
    invalid = spec(state);
    invalid.dispatch = reinterpret_cast<decltype(invalid.dispatch)>(std::uintptr_t{1});
    require(create_bootstrap_context(invalid).status == Status::code_unavailable,
            "actual Windows backend rejects an unregistered callback address");
    require(state.destroyed == 0, "unregistered code failure leaves state with caller");
    auto first = create_bootstrap_context(spec(state));
    require(first.status == Status::ok && first.owner.generation() != 0, "owned creation");
    const auto generation = first.owner.generation();
    auto lease = first.owner.lease();
    require(lease.generation() == generation && lease.availability() == Status::ok, "paired lease");
    const unsigned input = 40;
    require(lease.invoke({2, &input, sizeof(input)}).value == 42, "call-borrowed request");
    require(lease.invoke({2, nullptr, 1}).status == Status::invalid_request, "null input rejected");
    require(lease.invoke({2, &input, bootstrap_context_max_input + 1}).status == Status::invalid_request,
            "oversized input rejected");
    require(state.calls == 1, "invalid requests never reach dispatch");
    auto copy = lease;
    copy = copy;
    copy = std::move(copy);
    auto moved = std::move(copy);
    require(copy.availability() == Status::unavailable && moved.generation() == generation, "lease transfer");
    BootstrapContextOwner owner = std::move(first.owner);
    owner = std::move(owner);
    require(first.owner.generation() == 0 && owner.generation() == generation, "owner transfer");
    require(owner.close() == Status::ok && owner.quiescent(), "idle irreversible close");
    require(owner.lease().availability() == Status::closed && lease.invoke({1}).status == Status::closed,
            "closed owner and old lease cannot admit calls");
    auto closed_copy = moved;
    require(closed_copy.availability() == Status::closed && closed_copy.generation() == generation,
            "closed copies keep cleanup ownership without admission");
    owner = {};
    moved.reset();
    lease.reset();
    require(state.destroyed == 0, "last closed lease still owns state");
    closed_copy.reset();
    require(state.destroyed == 1, "state destroyed exactly once after final lease");

    State next;
    auto second = create_bootstrap_context(spec(next));
    require(second.owner.generation() > generation, "live factory generations do not reuse");
    auto reentrant = second.owner.lease();
    next.owner = &second.owner;
    next.lease = &reentrant;
    require(reentrant.invoke({9}).status == Status::ok && next.destroyed == 1,
            "reentrant self-release completes then cleans up");
    require(reentrant.invoke({1}).status == Status::unavailable, "reset invoking handle stays empty");

    State old_state, replacement_state;
    auto replacement = create_bootstrap_context(spec(replacement_state));
    auto replaced = create_bootstrap_context(spec(old_state));
    const auto replacement_generation = replacement.owner.generation();
    old_state.release_on_destroy = &replacement.owner;
    replaced.owner = std::move(replacement.owner);
    require(replaced.owner.generation() == replacement_generation && old_state.destroyed == 1 &&
            replacement_state.destroyed == 0, "transfer precedes old-state reentrant destruction");
    replaced.owner = {};
    require(replacement_state.destroyed == 1, "replacement remains owned until reset");

    auto stateless = create_bootstrap_context({bootstrap_context_abi_version,
        [](const BootstrapContextRequest &, void *) noexcept { return BootstrapContextResult{Status::ok, 17}; }});
    require(stateless.status == Status::ok && stateless.owner.lease().invoke({0}).value == 17,
            "stateless callback needs no destructor");
}
}  // namespace context_test

int main(int argc, char **argv) {
    context_test::check_lifecycle();
    context_test::check_concurrency();
    if (argc == 2) context_test::check_provider(argv[1]);
    std::puts("owned context lifecycle verified");
}
