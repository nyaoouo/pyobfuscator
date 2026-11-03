#include "scope_cases.hpp"
#include "context/runtime.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <utility>

namespace native = pyobfuscator::native;
namespace scoped = native::contribution::scoped;
namespace observer = native::measurement::observer;
extern "C" int measured_scope_body(scoped::Scope &, int) noexcept(false);
namespace {
std::uint64_t generation = 0;
std::atomic<unsigned> action{0}, calls{0};
scoped::Scope *recursive = nullptr;
native::BootstrapContextOwner *parent_owner = nullptr;
const native::BootstrapContextLease *origin = nullptr;
bool bad_body = false;
void require(bool value, const char *why) {
    if (!value) { std::fprintf(stderr, "measured scope: %s\n", why); std::exit(1); }
}
unsigned references(const native::BootstrapContextLease &lease) {
    auto *state = native::detail::BootstrapContextAccess::state(lease);
    native::detail::context_lock(state->gate);
    const auto result = state->references;
    native::detail::context_unlock(state->gate); return result;
}
native::BootstrapContextResult dispatch(const native::BootstrapContextRequest &request, void *) noexcept {
    if (request.operation_id != 0x1020 || request.input_size != sizeof(scoped::Admission) || request.input == nullptr)
        return {native::BootstrapContextStatus::invalid_request, 0};
    scoped::Admission message; std::memcpy(&message, request.input, sizeof(message));
    if (message.version != scoped::admission_version || message.size != sizeof(message) || message.reserved != 0 ||
            message.routing != 0x1020 || message.domain != 1 || message.function != 7 || message.source != 13 ||
            message.observation_owner != 7 || message.generation != generation || origin == nullptr ||
            message.observation_instance != origin->generation() ||
            message.observation_context != reinterpret_cast<std::uintptr_t>(native::detail::BootstrapContextAccess::state(*origin)))
        return {native::BootstrapContextStatus::context_mismatch, 0};
    const auto count = ++calls;
    if (action == 1) return {native::BootstrapContextStatus::unavailable, 0};
    if (action == 2) return {native::BootstrapContextStatus::ok, generation + 1};
    if (action == 3 && count == 2) observer::invalidate(*origin);
    if (action == 4) require(recursive->query(0x1020, {1, 7, 11, 13, 0}).status ==
        native::BootstrapContextStatus::busy, "reentrant query did not reject");
    if (action == 5 && count == 2) parent_owner->close();
    if (action == 6 && count == 2) require(observer::observe(*origin, true).check().error.code == observer::Status::ok,
        "admission refresh failed");
    return {native::BootstrapContextStatus::ok, generation};
}
}
native::BootstrapContextCreation make_scope_parent() {
    auto made = native::create_bootstrap_context({native::bootstrap_context_abi_version, dispatch, nullptr, nullptr});
    require(made.status == native::BootstrapContextStatus::ok, "owned parent create"); generation = made.owner.generation();
    return made;
}
extern "C" int measured_scope_effect(scoped::Scope &scope, int value, int result) noexcept(false) {
    if (bad_body) std::exit(91);
    require(scope.observation().sequence != 0 && scope.observation().identity.owner == 7,
        "actual transition lost retained observation");
    if (value == 1777) throw 1777;
    return result;
}
void check_scopes(native::BootstrapContextOwner &parent, const native::BootstrapContextLease &observation,
        const native::path_fold::Storage &fold, const std::vector<std::uint8_t> &material,
        const native::measurement::reference::Identity &identity, std::uint32_t expected_word, unsigned broken, bool measure) {
    auto expected = parent.lease(); auto publication = native::bind_bootstrap_context(expected);
    require(publication.status == native::BootstrapContextStatus::ok, "strict parent publication");
    const scoped::Spec spec{0x1020, 1, 7, 13, identity};
    origin = &observation; parent_owner = &parent;
    if (broken == 2) {
        auto snapshot = observer::observe(observation);
        const_cast<observer::Observation &>(snapshot.data()).measured.digest[31] ^= 1;
        scoped::Scope scope(expected, spec, fold, material.data(), material.size(), std::move(snapshot));
        const auto denied = scope.query(0x1020, {1, 7, 11, 13, 0});
        require(denied.material.material.status == native::release::measured::Status::ok &&
            denied.authentication == native::archive::Status::verification_failed && denied.word == 0 &&
            denied.material.value.word == 0, "forged snapshot success did not reach actual AEAD material refusal");
        std::puts("forged snapshot check cannot authenticate material for a changed actual final digest byte");
        std::exit(0);
    }
    if (broken == 1) {
        auto changed = material; changed.back() ^= 1;
        scoped::Scope scope(expected, spec, fold, changed.data(), changed.size(), observer::observe(observation));
        bad_body = true;
        measured_scope_body(scope, 3);
        std::exit(92);
    }
    for (const int value : {-2, 0, 3, 1777}) {
        const auto parent_refs = references(expected), observation_refs = references(observation);
        try {
            scoped::Scope scope(expected, spec, fold, material.data(), material.size(), observer::observe(observation));
            const auto result = scope.query(0x1020, {1, 7, 11, 13, 0});
            require(result.status == native::BootstrapContextStatus::ok && result.word == expected_word, "independent word in live scope");
            require(references(expected) == parent_refs + 1 && references(observation) == observation_refs + 1,
                "scope did not retain parent and exact snapshot");
            const auto output = measured_scope_body(scope, value);
            require(output == (value < 0 ? -value + 11 : value == 0 ? 17 : value * 3 + 1), "actual scoped body result");
        } catch (int caught) { require(caught == 1777 && value == 1777, "wrong scoped exception"); }
        require(references(expected) == parent_refs && references(observation) == observation_refs,
            "normal or unwound scope leaked a parent/snapshot");
    }
    for (unsigned mode : {1u, 2u, 4u, 6u}) {
        action = mode; calls = 0;
        scoped::Scope scope(expected, spec, fold, material.data(), material.size(), observer::observe(observation)); recursive = &scope;
        const auto sequence = scope.observation().sequence;
        const auto result = scope.query(0x1020, {1, 7, 11, 13, 0});
        if (mode == 1 || mode == 2) require(result.word == 0 && result.status ==
            (mode == 1 ? native::BootstrapContextStatus::unavailable : native::BootstrapContextStatus::context_mismatch),
            "failed phase/origin published word");
        else require(result.status == native::BootstrapContextStatus::ok && result.word == expected_word &&
            scope.observation().sequence == sequence, "reentry/refresh changed immutable operation");
    }
    action = 0; recursive = nullptr;
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker != 4; ++worker) threads.emplace_back([&] {
        for (unsigned index = 0; index != 8; ++index) {
            scoped::Scope scope(expected, spec, fold, material.data(), material.size(), observer::observe(observation));
            require(scope.query(0x1020, {1, 7, 11, 13, 0}).word == expected_word, "concurrent distinct operation failed");
            require(measured_scope_body(scope, 3) == 10, "concurrent actual scoped body");
        }
    });
    for (auto &thread : threads) thread.join();
    if (measure) {
        for (unsigned batch = 0; batch != 7; ++batch) {
            const auto begin = std::chrono::steady_clock::now();
            for (unsigned index = 0; index != 64; ++index) {
                scoped::Scope scope(expected, spec, fold, material.data(), material.size(), observer::observe(observation));
                require(measured_scope_body(scope, 3) == 10, "timed actual scoped function");
            }
            const auto elapsed = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - begin).count();
            std::printf("scope-cost %.3f\n", elapsed / 64.0);
        }
    }
    {
        auto changed = material; changed.back() ^= 1;
        scoped::Scope scope(expected, spec, fold, changed.data(), changed.size(), observer::observe(observation));
        const auto denied = scope.query(0x1020, {1, 7, 11, 13, 0});
        require(denied.status == native::BootstrapContextStatus::unavailable && denied.word == 0 &&
            denied.material.value.word == 0 && denied.authentication == native::archive::Status::decode_failed,
            "bad authenticated material lost source or published a word");
    }
    scoped::Scope invalid_owner(expected, {0x1020, 1, 8, 13, identity}, fold, material.data(), material.size(), observer::observe(observation));
    require(invalid_owner.query(0x1020, {1, 8, 11, 13, 0}).word == 0, "same observer admitted another function owner");
    scoped::Scope absent(expected, spec, fold, material.data(), material.size(), {});
    require(absent.query(0x1020, {1, 7, 11, 13, 0}).word == 0, "missing snapshot admitted");
    {
        scoped::Scope scope(expected, spec, fold, material.data(), material.size(), observer::observe(observation));
        require(scope.query(0x1021, {1, 7, 11, 13, 0}).word == 0 && scope.query(0x1020, {1, 7, 11, 14, 0}).word == 0,
            "wrong routing/source accepted");
        action = 5; calls = 0;
        const auto closed = scope.query(0x1020, {1, 7, 11, 13, 0});
        require(closed.status == native::BootstrapContextStatus::closed && closed.word == 0 && closed.material.value.word == 0,
            "parent closed during consumption granted word");
    }
    action = 0; publication.binding.reset();
    std::puts("measured scope strict parent admission,retained word/transition,normal/EH cleanup,reentry,refresh,concurrency and origin/phase/close denials pass");
}
