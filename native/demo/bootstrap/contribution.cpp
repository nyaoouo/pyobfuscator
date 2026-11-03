#include "flow.hpp"
#include "contribution/protocol.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextResult dispatch_contribution(
    const BootstrapContextRequest &request, RuntimeContext &context) noexcept {
#if defined(PYOBF_DEMO_POST_CODE_HASH)
#if defined(PYOBF_DEMO_POST_MIXED)
    return dispatch_post_owned(request, context);
#else
    (void)request; (void)context;
    return {BootstrapContextStatus::invalid_request, 0};
#endif
#else
    if (request.operation_id != context.config.environment_operation_id || request.input == nullptr ||
            request.input_size != sizeof(contribution::Message)) return {BootstrapContextStatus::invalid_request, 0};
    contribution::Message message;
    std::memcpy(&message, request.input, sizeof(message));
    if (message.version != contribution::context_protocol_version || message.size != sizeof(message) ||
            message.reserved != 0 || message.tail_reserved != 0)
        return {BootstrapContextStatus::invalid_request, 0};
    if (context.generation == 0 || message.generation != context.generation ||
            message.routing_tag != context.config.environment_operation_id)
        return {BootstrapContextStatus::context_mismatch, 0};
    const auto phase = PYOBF_NATIVE_ATOMIC_LOAD32(&context.phase);
    if (phase == static_cast<std::uint32_t>(LifecyclePhase::retired)) return {BootstrapContextStatus::closed, 0};
    if (phase != static_cast<std::uint32_t>(LifecyclePhase::payload_entered)) return {BootstrapContextStatus::unavailable, 0};
    if (PYOBF_NATIVE_ATOMIC_LOAD32(&context.contribution_state) != 2) return {BootstrapContextStatus::unavailable, 0};
    const auto result = contribution::derive(context.contribution_fold.words, message.routing_tag, message.point);
    return {result.status, result.status == BootstrapContextStatus::ok ?
        (std::uint64_t(contribution::context_reply_tag) << 32) | result.word : 0};
#endif
}

}  // namespace pyobfuscator::native::demo
