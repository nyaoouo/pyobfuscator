#include "session_fixture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

extern "C" int pyobf_native_demo_run(int, int, void (*)(std::uint32_t, void *), void *);

int main(int argc, char **argv) {
    using namespace session_fixture;
    using namespace pyobfuscator::native;
    using namespace pyobfuscator::native::demo;
    require(argc == 3, "release fault needs mode and expected status");
    const int expected = std::atoi(argv[2]);
    reset();
    int result = 0;
    if (std::strcmp(argv[1], "root") == 0 || std::strcmp(argv[1], "failed-hash") == 0) {
        if (std::strcmp(argv[1], "failed-hash") == 0) counters.hash_succeeds = false;
        result = pyobf_native_demo_run(5, 0, nullptr, nullptr);
    } else {
        RuntimeSession session, other;
        require(initialize_session(session, nullptr, nullptr), "release fault session initialized");
        if (std::strcmp(argv[1], "reorder") == 0) {
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::environment_accepted));
            require(prepare_support(session), "reordered support update");
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::created));
            require(pass_environment_gate(session.context), "reordered environment update");
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::support_prepared));
        } else {
            require(pass_environment_gate(session.context) && prepare_support(session), "release fault ordinary prefix");
            if (std::strcmp(argv[1], "fold") == 0) session.context->fold.words[0] ^= 1;
            else if (std::strcmp(argv[1], "generation") == 0) ++session.context->generation;
            else if (std::strcmp(argv[1], "context") == 0) {
                require(initialize_session(other, nullptr, nullptr), "foreign release fault context");
                session.expected = other.owner.lease();
            } else require(false, "unknown release fault mode");
        }
        result = release_and_load_payload(false, session);
    }
    require(result == expected, "release fault reached the wrong refusal boundary");
    require(counters.decrypts == (expected == -4 ? 1u : 0u) && counters.loads == 0 && counters.entries == 0,
            "real cryptographic/data refusal precedes loader and original entry");
    verify_clean();
    std::puts("real CNG release fault refused before loader and entry");
}
