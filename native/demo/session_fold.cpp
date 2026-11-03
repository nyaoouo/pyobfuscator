#include "session_fixture.hpp"

#include <array>
#include <cstdio>

namespace session_fixture {
namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::demo;
using Words = std::array<std::uint32_t, 8>;

Words snapshot(const RuntimeSession &session) {
    Words words{};
    const volatile auto *source = session.context->fold.words;
    for (unsigned lane = 0; lane != words.size(); ++lane) words[lane] = source[lane];
    return words;
}
void output(const char *name, const Words &words) {
    std::printf("bootstrap-fold %s", name);
    for (auto word : words) std::printf(" %u", word);
    std::puts("");
}
}

void check_fold() {
    reset();
    {
        RuntimeSession session;
        require(initialize_session(session, nullptr, nullptr), "fold session initialization");
        const auto initial = snapshot(session);
        output("initialize", initial);
        fold_context = session.context;
        require(pass_environment_gate(session.context), "fold environment acceptance");
        const auto accepted = snapshot(session);
        output("environment", accepted);
        require(!pass_environment_gate(session.context) && snapshot(session) == accepted,
                "duplicate environment cannot advance fold");
        require(prepare_support(session), "fold owned support preparation");
        const auto supported = snapshot(session);
        output("support", supported);
        for (unsigned lane = 0; lane != supported.size(); ++lane) {
            require(counters.phase_fold[0][lane] == accepted[lane], "environment fold precedes ready publication");
            require(counters.phase_fold[1][lane] == supported[lane], "owned support fold precedes ready publication");
        }
        require(!prepare_support(session) && support_is_ready(session) && snapshot(session) == supported,
                "verification and duplicate requests cannot advance fold");
        require(release_and_load_payload(false, session) == 0, "fold reaches actual decrypt boundary");
        fold_context = nullptr;
        const auto released = snapshot(session);
        output("release", released);
        for (unsigned lane = 0; lane != released.size(); ++lane)
            require(counters.decrypt_fold[lane] == released[lane], "release fold precedes decrypt operation");
    }
    verify_clean();
    for (bool retire_environment : {true, false}) {
        reset();
        {
            RuntimeSession session;
            require(initialize_session(session, nullptr, nullptr), "retirement-race fold session");
            fold_context = session.context;
            if (!retire_environment) require(pass_environment_gate(session.context), "support retirement-race environment");
            counters.retire_on_phase = static_cast<std::uint32_t>(retire_environment ?
                LifecyclePhase::environment_accepted : LifecyclePhase::support_prepared);
            require(!(retire_environment ? pass_environment_gate(session.context) : prepare_support(session)),
                    "retirement at fold publication refuses the operation");
            require(PYOBF_NATIVE_ATOMIC_LOAD32(&session.context->phase) ==
                    static_cast<std::uint32_t>(LifecyclePhase::retired), "ready publication cannot revive retirement");
            require(!support_is_ready(session) && release_and_load_payload(false, session) == -7 && counters.decrypts == 0,
                    "retired publication cannot decrypt");
            fold_context = nullptr;
        }
        verify_clean();
    }
    for (bool skip_environment : {true, false}) {
        reset();
        {
            RuntimeSession session;
            require(initialize_session(session, nullptr, nullptr), "omitted-step session initialization");
            if (skip_environment) {
                PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase,
                    static_cast<std::uint32_t>(LifecyclePhase::environment_accepted));
            } else require(pass_environment_gate(session.context), "omitted-support environment");
            if (skip_environment) require(prepare_support(session), "omitted-environment support");
            else PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase,
                static_cast<std::uint32_t>(LifecyclePhase::support_prepared));
            require(support_is_ready(session), "patched phase can satisfy lifecycle status alone");
            require(release_and_load_payload(false, session) == -4 && counters.decrypts == 1 && counters.loads == 0,
                    "forged lifecycle success cannot authenticate an omitted data dependency");
            output(skip_environment ? "skip-environment" : "skip-support", snapshot(session));
        }
        verify_clean();
    }
    reset();
    {
        RuntimeSession first, second;
        require(initialize_session(first, nullptr, nullptr) && initialize_session(second, nullptr, nullptr),
                "independent fold sessions");
        require(&first.context->fold != &second.context->fold, "fold storage belongs to its invocation");
        const auto untouched = snapshot(second);
        require(pass_environment_gate(first.context) && snapshot(second) == untouched,
                "one session cannot advance another fold");
        retire_payload(first);
        const auto closed = snapshot(first);
        require(!prepare_support(first) && snapshot(first) == closed, "retired support cannot advance fold");
    }
    verify_clean();
}
}  // namespace session_fixture
