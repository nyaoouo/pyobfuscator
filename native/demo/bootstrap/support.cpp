#include "flow.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP bool prepare_support(RuntimeSession &session) noexcept {
    if (session.context == nullptr || session.expected.generation() != session.context->generation) return false;
    const LifecycleMessage message{session.context->generation, session.context->config.environment_operation_id,
                                   LifecycleOperation::prepare_support};
    const auto result = session.expected.invoke({message.routing_tag, &message, sizeof(message)});
    return result.status == BootstrapContextStatus::ok && result.value == session.owner.generation();
}

PYOBF_NATIVE_CFF_BOOTSTRAP bool support_is_ready(const RuntimeSession &session) noexcept {
    if (session.context == nullptr || session.expected.generation() != session.context->generation ||
            session.owner.generation() != session.context->generation) return false;
    const LifecycleMessage message{session.context->generation, session.context->config.environment_operation_id,
                                   LifecycleOperation::verify_support};
    const auto result = session.expected.invoke({message.routing_tag, &message, sizeof(message)});
    return result.status == BootstrapContextStatus::ok && result.value == session.owner.generation();
}

}  // namespace pyobfuscator::native::demo
