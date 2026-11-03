#include "observer_fixture.hpp"

namespace observer_test {
void failures() {
    using namespace capture_test;
    for (unsigned allocation = 1; allocation != 5; ++allocation) {
        reset(); faults.allocation_failure_at = allocation;
        auto result = make();
        const auto wanted = allocation < 3 ? observer::Status::reference_failed : allocation == 3 ?
            observer::Status::allocation_failed : observer::Status::context_failed;
        require(result.error.code == wanted, "factory allocation failure source");
        balanced();
    }
    for (unsigned which = 0; which != 5; ++which) {
        reset();
        if (which < 2) fail_pin = which + 1;
        else if (which == 2) fail_access = true;
        else if (which == 3) fail_body = true;
        else faults.partial_view = true;
        auto result = make();
        const auto wanted = which < 2 ? observer::Status::context_failed : which < 4 ?
            observer::Status::reference_failed : observer::Status::capture_failed;
        require(result.error.code == wanted, "partial factory acquisition failure"); balanced();
    }
    for (unsigned which = 0; which != 7; ++which) {
        reset();
        {
            auto made = make(); auto lease = made.owner.lease(); auto old = observer::observe(lease);
            if (which == 0) faults.allocation = true;
            else if (which == 1) faults.read = true;
            else if (which == 2) faults.hash = true;
            else if (which == 3) faults.clock_failure = counters.clocks + 1;
            else if (which == 4) faults.clock_frequency += 1;
            else if (which == 5) faults.clock_ticks = 99;
            else {
                auto &value = state(lease); internal::lock(value); value.admitted = UINT64_MAX; internal::unlock(value);
            }
            auto denied = observer::observe(lease, which != 4 && which != 5);
            const auto wanted = which < 4 ? observer::Status::capture_failed : which < 6 ?
                observer::Status::clock_failed : observer::Status::generation_exhausted;
            require(denied.data().error.code == wanted && old.check().error.code == wanted,
                "failed refresh preserved old clean authority");
            if (which == 2) require(denied.data().error.capture == native::measurement::Status::crypto_failed,
                "raw hash failure became clean zero");
            faults.allocation = faults.read = faults.hash = false; faults.clock_failure = 0;
            require(observer::observe(lease).data().error.code == wanted, "normal scan reopened revoked owner");
        }
    }
    reset();
    {
        auto made = make(); auto lease = made.owner.lease(); auto old = observer::observe(lease);
        auto &value = state(lease); internal::lock(value); value.epoch = UINT64_MAX; internal::unlock(value);
        require(observer::invalidate(lease).code == observer::Status::generation_exhausted &&
            old.check().error.code == observer::Status::generation_exhausted, "epoch wrapped to fresh authority");
    }
    balanced();
}
}
