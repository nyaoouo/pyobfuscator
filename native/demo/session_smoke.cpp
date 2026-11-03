#include "session_fixture.hpp"

#include <cstdio>
#include <cstdlib>

extern "C" int pyobf_native_demo_run(int, int, void (*)(std::uint32_t, void *), void *);

int main() {
    using namespace session_fixture;
    for (unsigned stage = 0; stage != 7; ++stage) {
        reset();
        counters.throw_stage = stage;
        Trace trace;
        bool caught = false;
        try { require(pyobf_native_demo_run(5, 0, observe, &trace) == 16, "normal owned entry"); }
        catch (const ObserverFailure &error) { require(error.stage == stage, "original observer exception preserved"); caught = true; }
        require(caught == (stage != 0), "observer exception did not terminate or disappear");
        require(trace.count == (stage == 0 ? 6 : stage), "observer stage order/prefix");
        for (unsigned n = 0; n != trace.count; ++n) require(trace.stages[n] == n + 1, "ordered observer events");
        require(counters.unloads == (stage == 1 || stage == 2 ? 0u : 1u), "image cleanup across each observer exception");
        verify_clean();
    }
    for (unsigned failure = 1; failure != 8; ++failure) {
        reset(); counters.fail_allocation = failure;
        Trace trace;
        const int expected = failure <= 5 ? -3 : failure == 6 ? -8 : -4;
        require(pyobf_native_demo_run(5, 0, observe, &trace) == expected &&
                counters.decrypts == (failure == 7 ? 1u : 0u) && counters.loads == 0,
                "each state/control/sealed/plain/key/hash/AEAD allocation failure refuses before loading");
        verify_clean();
    }
    reset(); counters.hash_succeeds = false;
    Trace hash_failure;
    require(pyobf_native_demo_run(5, 0, observe, &hash_failure) == -8 && counters.decrypts == 0,
            "failed hash refuses before AEAD without a clean-zero contribution");
    verify_clean();
    for (unsigned failure = 0; failure != 3; ++failure) {
        reset(); Trace trace;
        counters.authenticated = failure != 0;
        counters.load_succeeds = failure != 1;
        counters.resolve_succeeds = failure != 2;
        require(pyobf_native_demo_run(5, 0, observe, &trace) == -4 - static_cast<int>(failure),
                "authentication/load/resolve error propagation");
        require(counters.entries == 0, "failed release does not enter application");
        verify_clean();
    }
    reset(); counters.environment = pyobfuscator::native::environment::Result::triggered;
    Trace blocked;
    require(pyobf_native_demo_run(5, 0, observe, &blocked) == -2 && counters.decrypts == 0,
            "triggered environment blocks before decrypt");
    verify_clean();
    reset(); counters.environment = pyobfuscator::native::environment::Result::clear;
    counters.environment_valid = false;
    Trace invalid;
    require(pyobf_native_demo_run(5, 0, observe, &invalid) == -2 && counters.decrypts == 0,
            "invalid environment report blocks before decrypt");
    verify_clean();
    reset(); counters.environment = pyobfuscator::native::environment::Result::unavailable;
    Trace unavailable;
    const bool allowed = pyobfuscator::native::demo::read_build_config().allow_unavailable;
    require(pyobf_native_demo_run(5, 0, observe, &unavailable) == (allowed ? 16 : -2), "explicit unavailable policy");
    verify_clean();
    reset(); counters.environment = pyobfuscator::native::environment::Result::clear;
    Trace clear;
    require(pyobf_native_demo_run(5, 0, observe, &clear) == 16, "clear environment is a valid admitted result");
    verify_clean();
    check_protocol();
    check_fold();
    std::puts("owned demo session cleanup verified");
}
