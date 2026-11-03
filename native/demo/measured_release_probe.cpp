#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "bootstrap/flow.hpp"
#include "bootstrap/path_events.hpp"
#include "payload_blob.hpp"
#include "measurement/observer_internal.hpp"
#include "owner_readers.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace native = pyobfuscator::native;
namespace demo = native::demo;
namespace {
void require(bool value, const char *message) { if (!value) { std::fprintf(stderr, "measured bootstrap: %s\n", message); std::exit(1); } }
struct Trace { unsigned count = 0; std::uint32_t stages[8]{}; };
std::uint64_t borrowed_generation = 0;
unsigned failed_hashes = 0, hash_failure = 0;
native::BootstrapContextResult foreign(const native::BootstrapContextRequest &, void *) noexcept {
    return {native::BootstrapContextStatus::ok, borrowed_generation};
}
void observe(std::uint32_t stage, void *opaque) {
    auto &trace = *static_cast<Trace *>(opaque); require(trace.count < 8, "bounded trace"); trace.stages[trace.count++] = stage;
}
void blank(const std::uint8_t (&key)[32]) { for (auto byte : key) require(byte == 0, "failed phase retained key"); }
void decrypt(const std::uint8_t (&key)[32]) {
    const auto size = sizeof(demo::packed::ciphertext);
    auto *plain = static_cast<std::uint8_t *>(PYOBF_NATIVE_ALLOCATE(size)); require(plain != nullptr, "test child buffer");
    require(PYOBF_NATIVE_DECRYPT(demo::packed::ciphertext, size, key, demo::packed::nonce, demo::packed::tag, plain), "actual phase key did not authenticate child");
    require(size > 2 && plain[0] == 'M' && plain[1] == 'Z', "actual child image");
    PYOBF_NATIVE_ERASE(plain, size); PYOBF_NATIVE_RELEASE(plain);
}
}
namespace pyobfuscator::native::platform {
bool hash_sha256_actual(const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;
bool hash_sha256(const std::uint8_t *input, std::size_t size, std::uint8_t *output) noexcept {
    constexpr char reference[] = "pyobf.native.code.reference.key.v1";
    constexpr char code[] = "pyobf.native.code.observation.v1";
    constexpr char key[] = "pyobf.native.release.measured.v1";
    const bool fail = (hash_failure == 1 && size >= sizeof(reference) && std::memcmp(input, reference, sizeof(reference)) == 0) ||
        (hash_failure == 2 && size >= sizeof(code) && std::memcmp(input, code, sizeof(code)) == 0) ||
        (hash_failure == 3 && size >= sizeof(key) && std::memcmp(input, key, sizeof(key)) == 0);
    if (fail) { ++failed_hashes; std::memset(output, 0xdd, 32); return false; }
    return hash_sha256_actual(input, size, output);
}
}
int main(int argc, char **argv) {
    if (argc == 4 && std::strcmp(argv[1], "dll") == 0) {
        const auto module = LoadLibraryA(argv[2]); require(module != nullptr, "test image load");
        using Run = int (*)(int, int, void (*)(std::uint32_t, void *), void *);
        const auto run = reinterpret_cast<Run>(GetProcAddress(module, "pyobf_native_demo_run")); require(run != nullptr, "test entry");
        Trace trace; const auto wanted = std::atoi(argv[3]);
        const auto status = run(5, 0, observe, &trace);
#if defined(PYOBF_DEMO_POST_CODE_HASH)
        constexpr unsigned successful_stages = 7;
#else
        constexpr unsigned successful_stages = 6;
#endif
        require(status == wanted && trace.count == (wanted == 16 ? successful_stages : 1u) && trace.stages[0] == 1,
            "wrong release status or plaintext/child stages reached on denial");
        require(FreeLibrary(module) != 0, "test image release"); return 0;
    }
    require(argc == 2 || argc == 3, "phase probe mode");
    demo::RuntimeSession session;
    require(demo::initialize_session(session, nullptr, nullptr), "real owned session");
    // Force the correct fold independently of phase, isolating actual phase/lease admission.
    pyobf_native_path_fold_step_v1(session.context->fold, demo::path_events::environment_tag, demo::path_events::environment_word);
    pyobf_native_path_fold_step_v1(session.context->fold, demo::path_events::support_tag, demo::path_events::support_word);
    pyobf_native_path_fold_step_v1(session.context->fold, demo::path_events::release_tag, demo::path_events::release_word);
    unsigned phase = static_cast<unsigned>(demo::LifecyclePhase::support_prepared);
    if (argc == 3 && std::strcmp(argv[1], "phase") == 0) {
        char *end = nullptr; const auto number = std::strtoull(argv[2], &end, 10);
        require(end != argv[2] && *end == 0 && number <= UINT32_MAX, "bounded phase value"); phase = static_cast<unsigned>(number);
    }
    if (std::strcmp(argv[1], "reference-hash-failed") == 0) hash_failure = 1;
    else if (std::strcmp(argv[1], "code-hash-failed") == 0) hash_failure = 2;
    else if (std::strcmp(argv[1], "key-hash-failed") == 0) hash_failure = 3;
    PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, phase);
    native::BootstrapContextOwner other;
    if (std::strcmp(argv[1], "wrong-lease") == 0) {
        borrowed_generation = session.context->generation;
        auto made = native::create_bootstrap_context({native::bootstrap_context_abi_version, foreign});
        require(made.status == native::BootstrapContextStatus::ok, "other context"); other = std::move(made.owner); session.expected = other.lease();
    } else if (std::strcmp(argv[1], "closed") == 0) session.owner.close();
    std::uint8_t key[32]; std::memset(key, 0xa5, sizeof(key));
    const bool admitted = demo::reconstruct_measured_payload_key(session, key);
    const bool valid = phase == static_cast<unsigned>(demo::LifecyclePhase::support_prepared) &&
        std::strcmp(argv[1], "wrong-lease") != 0 && std::strcmp(argv[1], "closed") != 0 && hash_failure == 0;
    require(admitted == valid, "correct fold bypassed actual phase/lease check");
    if (!valid) {
        blank(key);
        if (hash_failure != 0) {
            require(failed_hashes == 1 && session.code_stage_status == native::BootstrapContextStatus::ok,
                "targeted hash boundary not reached");
            if (hash_failure == 3) require(session.code_key_result.status == native::release::measured::Status::crypto_failed,
                "key expansion hash failure became observation success");
            else {
                const auto &error = session.code_key_result.observation;
                require(session.code_key_result.status == native::release::measured::Status::observation_failed &&
                    (hash_failure == 1 ? error.code == native::measurement::observer::Status::reference_failed &&
                        error.reference == native::measurement::reference::Status::crypto_failed :
                        error.code == native::measurement::observer::Status::capture_failed &&
                        error.capture == native::measurement::Status::crypto_failed), "reference/read hash failure source lost");
            }
        } else {
            const auto expected = std::strcmp(argv[1], "wrong-lease") == 0 ? native::BootstrapContextStatus::context_mismatch :
                std::strcmp(argv[1], "closed") == 0 || phase == static_cast<unsigned>(demo::LifecyclePhase::retired) ?
                native::BootstrapContextStatus::closed : native::BootstrapContextStatus::unavailable;
            require(session.code_stage_status == expected && session.code_key_result.status == native::release::measured::Status::observation_failed &&
                session.code_key_result.observation.context == expected, "phase failure provenance lost");
        }
    }
    else {
        const auto lease = session.code_owner.lease();
        const auto &owned = *static_cast<native::measurement::observer::detail::State *>(
            native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
        const auto &reader = native::measurement::generated_readers::bindings[0];
        require(owned.spec.reader == nullptr && owned.reader.owner == owned.identity.owner && owned.reader.key == reader.key &&
            owned.reader.capture == reader.capture && owned.reader.cache_codec == reader.cache_codec &&
            owned.reader_code.module != nullptr && owned.codec_code.module != nullptr &&
            std::memcmp(owned.cached.measured.digest, session.code_snapshot.data().measured.digest, 32) != 0,
            "pre-release path lost its actual owned reader/cache representation");
        decrypt(key); PYOBF_NATIVE_ERASE(key, sizeof(key));
        require(session.code_key_result.status == native::release::measured::Status::ok &&
            session.code_stage_status == native::BootstrapContextStatus::ok, "legitimate typed result lost");
        if (std::strcmp(argv[1], "repeated") == 0) {
            require(!demo::reconstruct_measured_payload_key(session, key), "same session replaced release observation"); blank(key);
        }
        auto held = std::move(session.code_snapshot); demo::retire_payload(session);
        require(held.check().error.code == native::measurement::observer::Status::closed, "retirement retained observation authority");
    }
    PYOBF_NATIVE_ERASE(key, sizeof(key));
}
