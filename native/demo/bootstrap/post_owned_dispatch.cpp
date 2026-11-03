#include "flow.hpp"
#include "post_profile.hpp"
#include "post_mixed_sites.hpp"
#include "contribution/protocol.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextResult dispatch_post_owned(
        const BootstrapContextRequest &request, RuntimeContext &context) noexcept {
    if (request.operation_id != post_profile::routing ||
            request.operation_id != context.config.environment_operation_id ||
            request.input == nullptr || request.input_size != sizeof(contribution::Message))
        return {BootstrapContextStatus::invalid_request, 0};
    contribution::Message message;
    std::memcpy(&message, request.input, sizeof(message));
    if (message.version != contribution::context_protocol_version || message.size != sizeof(message) ||
            message.reserved != 0 || message.tail_reserved != 0 ||
            message.routing_tag != post_profile::routing || message.generation == 0 ||
            message.generation != context.generation || message.point.domain != post_profile::domain)
        return {BootstrapContextStatus::context_mismatch, 0};
    const auto phase = PYOBF_NATIVE_ATOMIC_LOAD32(&context.phase);
    if (phase == static_cast<std::uint32_t>(LifecyclePhase::retired))
        return {BootstrapContextStatus::closed, 0};
    if (phase != static_cast<std::uint32_t>(LifecyclePhase::payload_entered) ||
            PYOBF_NATIVE_ATOMIC_LOAD32(&context.contribution_state) != 2 ||
            PYOBF_NATIVE_ATOMIC_LOAD32(&context.post_ready) != 2)
        return {BootstrapContextStatus::unavailable, 0};
    bool allowed = false;
    for (const auto &site : post_mixed_sites::sites)
        if (site.owner == message.point.function && site.label == message.point.site &&
                site.source == message.point.source) { allowed = true; break; }
    if (!allowed) return {BootstrapContextStatus::invalid_request, 0};
    const auto result = contribution::derive(context.contribution_fold.words,
        message.routing_tag, message.point);
    return {result.status, result.status == BootstrapContextStatus::ok ?
        (std::uint64_t(contribution::context_reply_tag) << 32) | result.word : 0};
}
}
