#include "flow.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::demo {

namespace {

PYOBF_NATIVE_CFF_BOOTSTRAP_EH int run(int value, int corrupt, Observer observer, void *user_data) {
    RuntimeSession session;
    if (!initialize_session(session, observer, user_data)) return -3;
    if (!pass_environment_gate(session.context)) {
        return finish_failed_release(session, value, -2, (corrupt & 2) != 0);
    }

    if (!prepare_support(session)) return finish_failed_release(session, value, -7, (corrupt & 2) != 0);
    const int release_status = release_and_load_payload(corrupt != 0, session);
    if (release_status != 0) {
        return finish_failed_release(session, value, release_status, (corrupt & 2) != 0);
    }
    auto *entry = reinterpret_cast<InnerEntry>(PYOBF_NATIVE_RESOLVE(session.image));
    if (entry == nullptr) {
        return -6;
    }
#if defined(PYOBF_DEMO_POST_CODE_HASH)
    if (!prepare_post(session, reinterpret_cast<platform::CodeAddress>(entry)))
        return finish_failed_release(session, value, -9, (corrupt & 2) != 0);
#endif

    const auto handoff = make_payload_handoff(session);
    const int result = entry(&handoff, value);
    retire_payload(session);
    record_stage(6, session.context);
    return result;
}

}  // namespace

}  // namespace pyobfuscator::native::demo

extern "C" __declspec(dllexport) PYOBF_NATIVE_CFF_BOOTSTRAP int pyobf_native_demo_run(
    int value, int corrupt, void (*observer)(std::uint32_t, void *), void *user_data) {
    return pyobfuscator::native::demo::run(value, corrupt, observer, user_data);
}
