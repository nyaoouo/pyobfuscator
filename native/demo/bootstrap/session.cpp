#include "flow.hpp"
#include "path_events.hpp"

#include <new>
#include <utility>

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP RuntimeSession::RuntimeSession() noexcept = default;

PYOBF_NATIVE_CFF_BOOTSTRAP RuntimeSession::~RuntimeSession() {
    retire_payload(*this);
    expected.reset();
    owner = {};
    context = nullptr;
}

PYOBF_NATIVE_CFF_BOOTSTRAP void retire_payload(RuntimeSession &session) noexcept {
    session.owner.close();
    if (session.context != nullptr)
        PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::retired));
    while (!session.owner.quiescent()) PYOBF_NATIVE_SPIN_PAUSE();
    session.publication.binding.reset();
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    retire_post(session);
#endif
#if defined(PYOBF_DEMO_PRE_CODE_HASH)
    session.code_owner.close();
    session.code_snapshot.reset();
    session.code_owner = {};
#endif
    if (session.image != nullptr) {
        PYOBF_NATIVE_UNLOAD(session.image);
        session.image = nullptr;
    }
}

PYOBF_NATIVE_CFF_BOOTSTRAP void destroy_runtime_context(void *opaque) noexcept {
    auto *context = static_cast<RuntimeContext *>(opaque);
    context->~RuntimeContext();
    PYOBF_NATIVE_ERASE(context, sizeof(RuntimeContext));
    PYOBF_NATIVE_RELEASE(context);
}

PYOBF_NATIVE_CFF_BOOTSTRAP bool initialize_session(RuntimeSession &session, Observer observer, void *user_data) noexcept {
    if (session.context != nullptr || session.owner.generation() != 0) return false;
    void *memory = PYOBF_NATIVE_ALLOCATE(sizeof(RuntimeContext));
    if (memory == nullptr) return false;
    auto *context = new (memory) RuntimeContext{read_build_config(), {}, observer, user_data};
    pyobf_native_path_fold_init_v1(context->fold, path_events::seed);
    auto created = create_bootstrap_context({bootstrap_context_abi_version, dispatch_lifecycle,
                                              context, destroy_runtime_context});
    if (created.status != BootstrapContextStatus::ok) {
        destroy_runtime_context(context);
        return false;
    }
    session.context = context;
    session.owner = std::move(created.owner);
    context->generation = session.owner.generation();
    session.expected = session.owner.lease();
    return session.expected.availability() == BootstrapContextStatus::ok;
}

}  // namespace pyobfuscator::native::demo
