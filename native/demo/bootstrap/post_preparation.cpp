#include "flow.hpp"
#include "post_profile.hpp"
#include "reference_slots.hpp"
#include "owner_readers.hpp"
#include "context/runtime.hpp"

#include <utility>

namespace pyobfuscator::native::demo {
namespace {
PYOBF_NATIVE_CFF_BOOTSTRAP BootstrapContextStatus post_stage(const RuntimeSession &session) noexcept {
    if (session.context == nullptr || session.image == nullptr) return BootstrapContextStatus::invalid_request;
    if (session.context->generation == 0 || session.expected.generation() != session.context->generation ||
            session.owner.generation() != session.context->generation) return BootstrapContextStatus::context_mismatch;
    const auto origin = session.owner.lease();
    if (origin.availability() != BootstrapContextStatus::ok) return origin.availability();
    if (detail::BootstrapContextAccess::state(origin) != detail::BootstrapContextAccess::state(session.expected))
        return BootstrapContextStatus::context_mismatch;
    const LifecycleMessage request{session.context->generation, session.context->config.environment_operation_id,
        LifecycleOperation::verify_support};
    const auto result = session.expected.invoke({request.routing_tag, &request, sizeof(request)});
    return result.status == BootstrapContextStatus::ok && result.value != session.context->generation ?
        BootstrapContextStatus::context_mismatch : result.status;
}

template <unsigned Role>
PYOBF_NATIVE_CFF_BOOTSTRAP bool prepare_post_role(RuntimeSession &session, platform::CodeAddress inner) noexcept {
    static_assert(Role < 2);
    namespace reserved = measurement::reserved;
    namespace observer = measurement::observer;
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    constexpr unsigned slot = Role + 1;
#else
    constexpr unsigned slot = Role;
#endif
    const auto &identity = reserved::identities[slot];
    const observer::Policy policy{observer::Mode::per_use, 1000000000, 1000000000};
    const auto member = Role == 0 ? reinterpret_cast<platform::CodeAddress>(&prepare_post) : inner;
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    observer::Creation made{};
    if constexpr (Role == 0) {
        made = measurement::generated_readers::create_1(
            reserved::data + reserved::offsets[slot], identity.capacity, identity, session.context->contribution_fold.words,
            policy, member, session.context->generation);
    } else {
        made = measurement::generated_readers::create_2(
            reserved::data + reserved::offsets[slot], identity.capacity, identity, session.context->contribution_fold.words,
            policy, member, session.context->generation);
    }
#else
    observer::Creation made{};
    if constexpr (Role == 0) {
        made = measurement::generated_readers::create_0(
            reserved::data + reserved::offsets[slot], identity.capacity, identity, session.context->contribution_fold.words,
            policy, member, session.context->generation);
    } else {
        made = measurement::generated_readers::create_1(
            reserved::data + reserved::offsets[slot], identity.capacity, identity, session.context->contribution_fold.words,
            policy, member, session.context->generation);
    }
#endif
    session.post.preparation[Role] = made.error;
    if (made.error.code != observer::Status::ok) return false;
    session.post.owners[Role] = std::move(made.owner);
    session.post.leases[Role] = session.post.owners[Role].lease();
    session.post.handoff.roles[Role] = {{post_profile::routing, post_profile::domain, identity.owner,
        post_profile::source, identity}, &session.post.leases[Role],
        reserved::data + reserved::material_offsets[slot], reserved::material_size};
    return true;
}
}
PYOBF_NATIVE_CFF_BOOTSTRAP void retire_post(RuntimeSession &session) noexcept {
    if (session.context != nullptr) PYOBF_NATIVE_ATOMIC_STORE32(&session.context->post_ready, 3);
    if (session.context != nullptr) {
        for (unsigned index = 0; index != 2; ++index) {
            session.context->post_observation_instances[index] = 0;
            session.context->post_observation_contexts[index] = nullptr;
        }
    }
    session.post.handoff = {};
    for (unsigned index = 0; index != 2; ++index) {
        session.post.owners[index].close();
        session.post.leases[index].reset();
        session.post.owners[index] = {};
    }
}
PYOBF_NATIVE_CFF_BOOTSTRAP bool prepare_post(RuntimeSession &session, platform::CodeAddress inner) noexcept {
    namespace reserved = measurement::reserved;
    namespace observer = measurement::observer;
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    constexpr unsigned first = 1;
#else
    constexpr unsigned first = 0;
#endif
    static_assert(measurement::generated_readers::count == reserved::count && reserved::count == first + 2 && reserved::identities[first].owner == post_profile::wrapper_owner &&
        reserved::identities[first + 1].owner == post_profile::compute_owner);
    session.post.stage_status = post_stage(session);
    if (session.post.stage_status != BootstrapContextStatus::ok) return false;
    if (inner == nullptr ||
            session.context->config.environment_operation_id != post_profile::routing ||
            PYOBF_NATIVE_ATOMIC_LOAD32(&session.context->contribution_state) != 2) {
        session.post.stage_status = BootstrapContextStatus::invalid_request; return false;
    }
    if (PYOBF_NATIVE_ATOMIC_CAS32(&session.context->post_ready, 0, 1) != 0) {
        session.post.stage_status = BootstrapContextStatus::unavailable; return false;
    }
    session.post.handoff.fold = &session.context->contribution_fold;
    if (!prepare_post_role<0>(session, inner) || !prepare_post_role<1>(session, inner)) {
        retire_post(session); return false;
    }
    session.post.stage_status = post_stage(session);
    if (session.post.stage_status != BootstrapContextStatus::ok) { retire_post(session); return false; }
    for (unsigned index = 0; index != 2; ++index) {
        session.context->post_observation_instances[index] = session.post.leases[index].generation();
        session.context->post_observation_contexts[index] = detail::BootstrapContextAccess::state(session.post.leases[index]);
    }
    PYOBF_NATIVE_ATOMIC_STORE32(&session.context->post_ready, 2);
    return true;
}
}
