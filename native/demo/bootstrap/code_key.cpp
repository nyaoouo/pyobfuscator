#include "flow.hpp"
#include "release/measured.hpp"
#include "reference_slots.hpp"
#include "owner_readers.hpp"
#include "context/runtime.hpp"

#include <utility>

namespace pyobfuscator::native::demo {
namespace {
PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextStatus stage_status(const RuntimeSession &session) noexcept {
    if (session.context == nullptr || session.context->generation == 0 ||
            session.expected.generation() != session.context->generation || session.owner.generation() != session.context->generation)
        return BootstrapContextStatus::context_mismatch;
    const auto origin = session.owner.lease();
    if (origin.availability() != BootstrapContextStatus::ok) return origin.availability();
    if (detail::BootstrapContextAccess::state(origin) != detail::BootstrapContextAccess::state(session.expected))
        return BootstrapContextStatus::context_mismatch;
    const LifecycleMessage message{session.context->generation, session.context->config.environment_operation_id,
        LifecycleOperation::verify_support};
    const auto result = session.expected.invoke({message.routing_tag, &message, sizeof(message)});
    return result.status == BootstrapContextStatus::ok && result.value != session.context->generation ?
        BootstrapContextStatus::context_mismatch : result.status;
}
}
PYOBF_NATIVE_CFF_BOOTSTRAP bool measured_release_is_ready(RuntimeSession &session) noexcept {
    const auto checked = session.code_snapshot.check();
    if (checked.error.code != measurement::observer::Status::ok) {
        session.code_key_result = {release::measured::Status::observation_failed, checked.error}; return false;
    }
    session.code_stage_status = stage_status(session);
    if (session.code_stage_status != BootstrapContextStatus::ok) {
        session.code_key_result = {release::measured::Status::observation_failed,
            {measurement::observer::Status::context_failed, session.code_stage_status}}; return false;
    }
    return true;
}
PYOBF_NATIVE_CFF_BOOTSTRAP bool reconstruct_measured_payload_key(RuntimeSession &session, std::uint8_t *key) noexcept {
    namespace reserved = measurement::reserved;
    namespace observer = measurement::observer;
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    constexpr unsigned reference_count = 3;
#else
    constexpr unsigned reference_count = 1;
#endif
    static_assert(measurement::generated_readers::count == reserved::count && reserved::count == reference_count &&
        reserved::identities[0].kind == 1 && reserved::identities[0].stage == 1);
    session.code_key_result = {}; session.code_stage_status = BootstrapContextStatus::unavailable;
    if (key == nullptr) return false;
    PYOBF_NATIVE_ERASE(key, 32);
    session.code_stage_status = stage_status(session);
    if (session.code_stage_status != BootstrapContextStatus::ok) {
        session.code_key_result = {release::measured::Status::observation_failed,
            {observer::Status::context_failed, session.code_stage_status}}; return false;
    }
    if (session.code_owner.generation() != 0) return false;
    auto made = measurement::generated_readers::create_0(reserved::data + reserved::offsets[0],
        reserved::identities[0].capacity, reserved::identities[0], session.context->fold.words,
        {observer::Mode::once_per_instance, 0, 10000000000ull},
        reinterpret_cast<platform::CodeAddress>(&reconstruct_measured_payload_key), session.context->generation);
    if (made.error.code != observer::Status::ok) {
        session.code_key_result = {release::measured::Status::observation_failed, made.error}; return false;
    }
    session.code_owner = std::move(made.owner);
    session.code_snapshot = observer::observe(session.code_owner.lease());
    if (!measured_release_is_ready(session)) return false;
    session.code_key_result = release::measured::reconstruct(session.context->fold, release::record, session.code_snapshot, key);
    if (session.code_key_result.status != release::measured::Status::ok || !measured_release_is_ready(session)) {
        PYOBF_NATIVE_ERASE(key, 32); observer::invalidate(session.code_owner.lease()); return false;
    }
    return true;
}
}
