#include "observer_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <cstring>

namespace pyobfuscator::native::measurement::observer::detail {
PYOBF_NATIVE_CFF_SDK BootstrapContextResult dispatch(const BootstrapContextRequest &input, void *opaque) noexcept {
    if (input.operation_id != operation || input.input == nullptr || input.input_size != sizeof(Request))
        return {BootstrapContextStatus::invalid_request, 0};
    Request request; std::memcpy(&request, input.input, sizeof(request));
    auto &state = *static_cast<State *>(opaque);
    if (request.version != version || request.size != sizeof(Request) || request.output == nullptr || request.force > 1 ||
            (request.action != Action::observe && request.force != 0) ||
            ((request.action == Action::validate) != (request.snapshot != nullptr)))
        return {BootstrapContextStatus::invalid_request, 0};
    if (request.instance != state.context->generation) return {BootstrapContextStatus::context_mismatch, 0};
    if (request.action == Action::observe) acquire(state, request.force != 0, *request.output);
    else if (request.action == Action::validate) validate(state, *request.snapshot, request.output->validation);
    else if (request.action == Action::invalidate) {
        lock(state);
        auto error = live(state);
        if (error.code == Status::ok) { error.code = Status::revoked; revoke(state, error); error = state.failure; }
        request.output->validation.error = error;
        unlock(state);
    } else return {BootstrapContextStatus::invalid_request, 0};
    return {BootstrapContextStatus::ok, reply};
}
}  // namespace pyobfuscator::native::measurement::observer::detail
