#include "flow.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP void record_stage(std::uint32_t stage, void *opaque) {
    auto *context = static_cast<RuntimeContext *>(opaque);
    if (context->observer != nullptr) {
        context->observer(stage, context->user_data);
    }
}

PYOBF_NATIVE_CFF_BOOTSTRAP PayloadHandoff make_payload_handoff(RuntimeSession &session) noexcept {
    return {handoff_abi_version, session.context->config.environment_operation_id, session.context->generation,
            &session.expected, &session.publication, record_stage, session.context
#if defined(PYOBF_DEMO_POST_CODE_HASH)
            , &session.post.handoff
#endif
    };
}

}  // namespace pyobfuscator::native::demo
