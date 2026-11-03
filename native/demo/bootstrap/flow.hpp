#pragma once

#include "pyobfuscator_native/environment.hpp"
#include "handoff.hpp"
#include "pyobfuscator_native/cff_marker.hpp"
#include "pyobfuscator_native/system_ops.hpp"
#include "path_fold/marker.hpp"
#if defined(PYOBF_DEMO_POST_CODE_HASH)
#include "post_handoff.hpp"
#endif
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
#include "release/measured.hpp"
#endif

#include <cstdint>

namespace pyobfuscator::native::demo {

using Observer = void (*)(std::uint32_t stage, void *user_data);

struct RuntimeConfig {
    std::uint32_t environment_operation_id;
    bool allow_unavailable;
    const char *detector_selection;
};

struct RuntimeContext {
    RuntimeConfig config;
    environment::Report environment;
    Observer observer;
    void *user_data;
    std::uint64_t generation = 0;
    platform::AtomicWord32 phase{0};
    path_fold::Storage fold;
    platform::AtomicWord32 contribution_state{0};
    path_fold::Storage contribution_fold;
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    platform::AtomicWord32 post_ready{0};
    std::uint64_t post_observation_instances[2]{};
    const void *post_observation_contexts[2]{};
#endif
};

enum class LifecyclePhase : std::uint32_t {
    created, environment_accepted, support_prepared, payload_entered, retired,
    environment_accepting, support_preparing
};

struct RuntimeSession {
    RuntimeSession() noexcept;
    RuntimeSession(const RuntimeSession &) = delete;
    RuntimeSession &operator=(const RuntimeSession &) = delete;
    ~RuntimeSession();
    RuntimeContext *context = nullptr;
    BootstrapContextOwner owner;
    BootstrapContextLease expected;
    BootstrapContextBindingCreation publication{BootstrapContextStatus::unavailable, {}};
    void *image = nullptr;
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    PostSession post;
#endif
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    BootstrapContextOwner code_owner;
    measurement::observer::Snapshot code_snapshot;
    BootstrapContextStatus code_stage_status = BootstrapContextStatus::unavailable;
    release::measured::Result code_key_result{};
#endif
};

RuntimeConfig read_build_config() noexcept;
void record_stage(std::uint32_t stage, void *opaque);
bool initialize_session(RuntimeSession &, Observer, void *) noexcept;
void retire_payload(RuntimeSession &) noexcept;
void destroy_runtime_context(void *) noexcept;
BootstrapContextResult dispatch_lifecycle(const BootstrapContextRequest &, void *) noexcept;
BootstrapContextResult dispatch_contribution(const BootstrapContextRequest &, RuntimeContext &) noexcept;
bool freeze_contribution(RuntimeContext &) noexcept;
bool prepare_support(RuntimeSession &) noexcept;
bool support_is_ready(const RuntimeSession &) noexcept;
bool reconstruct_payload_key(const RuntimeContext &, std::uint8_t *) noexcept;
#if defined(PYOBF_DEMO_POST_CODE_HASH)
bool prepare_post(RuntimeSession &, platform::CodeAddress) noexcept;
void retire_post(RuntimeSession &) noexcept;
BootstrapContextResult dispatch_post(const BootstrapContextRequest &, RuntimeContext &) noexcept;
#if defined(PYOBF_DEMO_POST_MIXED)
BootstrapContextResult dispatch_post_owned(const BootstrapContextRequest &, RuntimeContext &) noexcept;
#endif
#endif
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
bool reconstruct_measured_payload_key(RuntimeSession &, std::uint8_t *) noexcept;
bool measured_release_is_ready(RuntimeSession &) noexcept;
#endif
PayloadHandoff make_payload_handoff(RuntimeSession &) noexcept;
bool pass_environment_gate(RuntimeContext *context);
int release_and_load_payload(bool corrupt, RuntimeSession &session);
int finish_failed_release(RuntimeSession &, int, int, bool);

}  // namespace pyobfuscator::native::demo
