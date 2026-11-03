#include "flow.hpp"
#include "path_events.hpp"
#include "contribution/protocol.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextResult dispatch_lifecycle(
    const BootstrapContextRequest &request, void *opaque) noexcept {
    auto *context = static_cast<RuntimeContext *>(opaque);
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    if (request.input_size == sizeof(contribution::scoped::Admission)) return dispatch_post(request, *context);
#endif
    if (request.input_size == sizeof(contribution::Message)) return dispatch_contribution(request, *context);
    if (request.operation_id != context->config.environment_operation_id || request.input == nullptr ||
            request.input_size != sizeof(LifecycleMessage)) return {BootstrapContextStatus::invalid_request, 0};
    LifecycleMessage message;
    std::memcpy(&message, request.input, sizeof(message));
    if (message.generation != context->generation || message.routing_tag != context->config.environment_operation_id)
        return {BootstrapContextStatus::context_mismatch, 0};
    const auto phase = PYOBF_NATIVE_ATOMIC_LOAD32(&context->phase);
    if (phase == static_cast<std::uint32_t>(LifecyclePhase::retired)) return {BootstrapContextStatus::closed, 0};
    if (message.operation == LifecycleOperation::verify_support) {
        return phase == static_cast<std::uint32_t>(LifecyclePhase::support_prepared) ?
            BootstrapContextResult{BootstrapContextStatus::ok, context->generation} :
            BootstrapContextResult{BootstrapContextStatus::unavailable, 0};
    }
    std::uint32_t before, after;
    if (message.operation == LifecycleOperation::prepare_support) {
        before = static_cast<std::uint32_t>(LifecyclePhase::environment_accepted);
        after = static_cast<std::uint32_t>(LifecyclePhase::support_preparing);
    } else if (message.operation == LifecycleOperation::enter_payload) {
        before = static_cast<std::uint32_t>(LifecyclePhase::support_prepared);
        after = static_cast<std::uint32_t>(LifecyclePhase::payload_entered);
    } else return {BootstrapContextStatus::invalid_request, 0};
    if (PYOBF_NATIVE_ATOMIC_CAS32(&context->phase, before, after) != before)
        return {BootstrapContextStatus::unavailable, 0};
    if (message.operation == LifecycleOperation::prepare_support) {
        pyobf_native_path_fold_step_v1(context->fold, path_events::support_tag, path_events::support_word);
        if (PYOBF_NATIVE_ATOMIC_CAS32(&context->phase,
                static_cast<std::uint32_t>(LifecyclePhase::support_preparing),
                static_cast<std::uint32_t>(LifecyclePhase::support_prepared)) !=
                static_cast<std::uint32_t>(LifecyclePhase::support_preparing))
            return {BootstrapContextStatus::closed, 0};
    }
    return {BootstrapContextStatus::ok, message.operation == LifecycleOperation::enter_payload ?
        static_cast<std::uint64_t>(context->environment.overall) : context->generation};
}

}  // namespace pyobfuscator::native::demo
