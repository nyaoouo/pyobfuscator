#include "runtime_fixture.hpp"
#include "bootstrap/key_expansion.hpp"

#include <cstdio>
#include <cstring>
#include <initializer_list>

extern "C" int pyobf_native_demo_run(int, int, void (*)(std::uint32_t, void *), void *);

namespace decoy_fixture {
namespace {
using namespace pyobfuscator::native;
using namespace pyobfuscator::native::demo;

void no_real_image() {
    require(counters.real_load_attempts == 0 && counters.real_entries == 0,
            "failed real path never calls real loader or entry");
}
int root(bool denied, int corrupt, Trace *trace = nullptr) {
    counters.denied = denied;
    counters.public_allocation = denied ? 0 : 3;
    return pyobf_native_demo_run(5, corrupt, observe, trace);
}
void trace_matches(const Trace &trace, bool real, bool refused = false) {
    constexpr unsigned real_stages[]{1, 2, 3, 6}, decoy_stages[]{1, 7, 8, 9, 10};
    const auto *expected = real ? real_stages : decoy_stages;
    const unsigned count = refused ? 1 : real ? 4 : 5;
    require(trace.count == count, "observed role stage count");
    for (unsigned index = 0; index != count; ++index)
        require(trace.stages[index] == expected[index], "observed role stage order");
}
void output_fold() {
    std::printf("bootstrap-fold decoy-release");
    for (auto word : counters.decoy_fold) std::printf(" %u", word);
    std::puts("");
}
}

void release_fault(const char *mode) {
    reset();
    {
        RuntimeSession session, other;
        require(initialize_session(session, observe, nullptr), "fault real session initialized");
        retained = session.expected;
        if (std::strcmp(mode, "reorder") == 0) {
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::environment_accepted));
            require(prepare_support(session), "fault reordered support");
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::created));
            require(pass_environment_gate(session.context), "fault reordered environment");
            PYOBF_NATIVE_ATOMIC_STORE32(&session.context->phase, static_cast<std::uint32_t>(LifecyclePhase::support_prepared));
        } else {
            require(pass_environment_gate(session.context) && prepare_support(session), "fault real ordinary prefix");
            if (std::strcmp(mode, "fold") == 0) session.context->fold.words[0] ^= 1;
            else if (std::strcmp(mode, "generation") == 0) ++session.context->generation;
            else if (std::strcmp(mode, "context") == 0) {
                require(initialize_session(other, nullptr, nullptr), "fault foreign context");
                session.expected = other.owner.lease();
            } else if (std::strcmp(mode, "closed") == 0) session.owner.close();
            else require(false, "known real release fault");
        }
        counters.public_allocation = counters.attempts + 1;
        const int status = release_and_load_payload(false, session);
        require(status == -4 || status == -7, "actual data or context failure");
        require(finish_failed_release(session, 5, status, false) == 101, "independent failure release");
        require(retained.availability() == BootstrapContextStatus::closed, "real lease stays closed after decoy");
    }
    no_real_image();
    require(counters.decoy_entries == 1 && counters.decoy_hashes == 1, "one independent decoy release");
    verify_clean();
}

void suite() {
    for (bool denied : {false, true}) for (int corrupt : {0, 1, 2}) {
        reset();
        Trace trace;
        const bool real = !denied && corrupt == 0, refused = corrupt == 2;
        require(root(denied, corrupt, &trace) == (real ? 16 : refused ? -9 : 101), "actual real/decoy/refusal control");
        trace_matches(trace, real, refused);
        require(counters.real_entries == unsigned(real) && counters.decoy_entries == unsigned(!real && !refused),
                "actual classified entry control");
        if (!real) no_real_image();
        if (denied && corrupt == 0) output_fold();
        verify_clean();
    }
    for (bool denied : {true, false}) {
        reset();
        require(root(denied, denied ? 0 : 1) == 101, "OOM inventory control");
        const unsigned attempts = counters.attempts;
        require(attempts == (denied ? 8u : 13u), "every runtime and production CNG allocation inventoried");
        verify_clean();
        for (unsigned fail = 1; fail <= attempts; ++fail) {
            reset(); counters.fail_allocation = fail;
            const bool recovered = !denied && (fail == 6 || fail == 7);
            const int expected = recovered ? 101 : fail <= 2 || (!denied && fail <= 5) ? -3 : -9;
            require(root(denied, denied ? 0 : 1) == expected, "single-allocation fault follows documented bounded policy");
            no_real_image();
            require(counters.decoy_entries == unsigned(recovered), "OOM never falls back to real execution");
            verify_clean();
        }
    }
    for (unsigned mode = 0; mode != 5; ++mode) {
        reset();
        if (mode == 0) counters.decoy_hash_succeeds = false;
        if (mode == 1) counters.decoy_aead_succeeds = false;
        if (mode == 2) counters.load_succeeds = false;
        if (mode == 3) counters.resolve_succeeds = false;
        if (mode == 4) counters.real_hash_succeeds = false;
        require(root(mode != 4, 0) == (mode == 4 ? 101 : -9), "provider/load/resolve/material bounded failure");
        no_real_image();
        require(counters.decoy_entries == unsigned(mode == 4), "failed decoy never recursively releases real payload");
        if (mode == 2) require(counters.decoy_load_attempts == 1 && counters.decoy_loads == 0, "loader refusal observed");
        if (mode == 3) require(counters.decoy_loads == 1 && counters.decoy_unloads == 1, "missing entry unloads image");
        verify_clean();
    }
    for (const char *mode : {"reorder", "fold", "generation", "context", "closed"}) release_fault(mode);
    for (int reason : {-3, -5, -6}) {
        reset();
        {
            RuntimeSession session;
            require(initialize_session(session, nullptr, nullptr), "unselected failure session");
            require(finish_failed_release(session, 5, reason, false) == reason && !counters.decoy_started,
                    "unselected failure does not start decoy");
        }
        no_real_image(); verify_clean();
    }
    for (unsigned stage : {1u, 7u, 8u, 9u, 10u}) {
        reset(); counters.throw_stage = stage;
        bool caught = false;
        try { root(true, 0); }
        catch (const ObserverFailure &error) { require(error.stage == stage, "host exception identity preserved"); caught = true; }
        require(caught, "observer failure propagated");
        no_real_image(); verify_clean();
    }
    for (unsigned field = 0; field != 4; ++field) {
        reset();
        path_fold::Storage fold{};
        release::Record record = release::record;
        if (field == 0) record.magic[0] ^= 1;
        if (field == 1) ++record.version;
        if (field == 2) --record.size;
        if (field == 3) record.reserved[0] = 1;
        TransientBuffer key(32, true);
        require(!expand_release_key(fold, record, key.bytes) && counters.real_hashes == 0 && counters.decoy_hashes == 0,
                "malformed shared record refuses before hashing");
        key.reset(); verify_clean();
    }
    std::puts("observed decoy: exact-image roles,21 allocation faults,5 context/fold faults, providers,4 record refusals, host unwind and erased state/key/CNG storage");
}
}  // namespace decoy_fixture
