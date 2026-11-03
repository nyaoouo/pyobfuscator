#include "flow.hpp"
#include "post_profile.hpp"

#include <cstring>

namespace pyobfuscator::native::demo {
PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextResult dispatch_post(
        const BootstrapContextRequest &request, RuntimeContext &context) noexcept {
    using contribution::scoped::Admission;
    if (request.operation_id != context.config.environment_operation_id || request.input == nullptr ||
            request.input_size != sizeof(Admission)) return {BootstrapContextStatus::invalid_request, 0};
    Admission message; std::memcpy(&message, request.input, sizeof(message));
    if (message.version != contribution::scoped::admission_version || message.size != sizeof(message) || message.reserved != 0)
        return {BootstrapContextStatus::invalid_request, 0};
    if (context.generation == 0 || message.generation != context.generation || message.routing != post_profile::routing ||
            message.domain != post_profile::domain || message.source != post_profile::source ||
            message.observation_owner != message.function ||
            (message.function != post_profile::wrapper_owner && message.function != post_profile::compute_owner))
        return {BootstrapContextStatus::context_mismatch, 0};
    const auto phase = PYOBF_NATIVE_ATOMIC_LOAD32(&context.phase);
    if (phase == static_cast<std::uint32_t>(LifecyclePhase::retired)) return {BootstrapContextStatus::closed, 0};
    if (phase != static_cast<std::uint32_t>(LifecyclePhase::payload_entered) ||
            PYOBF_NATIVE_ATOMIC_LOAD32(&context.post_ready) != 2 ||
            PYOBF_NATIVE_ATOMIC_LOAD32(&context.contribution_state) != 2) return {BootstrapContextStatus::unavailable, 0};
    const unsigned role = message.function == post_profile::wrapper_owner ? 0u : 1u;
    if (message.observation_instance == 0 || message.observation_context == 0 ||
            message.observation_instance != context.post_observation_instances[role] ||
            message.observation_context != reinterpret_cast<std::uintptr_t>(context.post_observation_contexts[role]))
        return {BootstrapContextStatus::context_mismatch, 0};
    return {BootstrapContextStatus::ok, context.generation};
}
}
