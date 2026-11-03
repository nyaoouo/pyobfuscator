#include "observer_fixture.hpp"

#include <cstring>

namespace observer_test {
namespace {
void slow_hash(std::uint8_t *) { capture_test::faults.clock_ticks = 400; }
}
void policies() {
    using namespace capture_test;
    reset();
    {
        auto made = make({observer::Mode::periodic_bounded_age, 50, 20});
        auto lease = made.owner.lease(); auto original = observer::observe(lease);
        require(original.data().error.code == observer::Status::ok && counters.reads == 1, "bounded initial read");
        faults.clock_ticks = 150;
        require(original.check().error.code == observer::Status::ok, "inclusive start-based deadline");
        auto cached = observer::observe(lease); require(cached.reused() && counters.reads == 1, "fresh bounded cache");
        faults.clock_ticks = 151;
        require(original.check().error.code == observer::Status::expired, "pending snapshot expiry");
        auto refreshed = observer::observe(lease);
        require(!refreshed.reused() && refreshed.data().sequence == 2 && counters.reads == 2 &&
            refreshed.check().error.code == observer::Status::ok, "expired cache synchronous refresh");
        require(original.data().measured.read_started == 100 && original.check().error.code == observer::Status::expired,
            "refresh rewrote pending snapshot");
    }
    reset();
    {
        auto made = make({observer::Mode::per_use, 100, 100}); auto lease = made.owner.lease();
        auto one = observer::observe(lease), two = observer::observe(lease);
        require(counters.reads == 2 && !one.reused() && !two.reused() && one.data().sequence != two.data().sequence,
            "per-use coalesced actual reads");
        require(one.check().error.code == observer::Status::ok, "unchanged refresh invalidated old operation");
    }
    for (auto age_only : {false, true}) {
        reset();
        {
            auto made = make({observer::Mode::periodic_bounded_age, age_only ? 200ull : 1000ull,
                age_only ? 1000ull : 200ull}); auto lease = made.owner.lease();
            on_hash = slow_hash;
            auto denied = observer::observe(lease); on_hash = nullptr;
            const auto wanted = age_only ? observer::Status::expired : observer::Status::scan_expired;
            require(denied.data().error.code == wanted && denied.data().measured.read_started == 100 &&
                denied.data().measured.read_completed == 400, "completion incorrectly reset freshness");
            require(observer::observe(lease).data().error.code == wanted && counters.reads == 1,
                "late required scan reopened failed owner");
        }
    }
    for (unsigned mutation = 0; mutation != 15; ++mutation) {
        reset();
        {
            auto made = make(); auto lease = made.owner.lease(); auto original = observer::observe(lease);
            auto &owned = state(lease); internal::lock(owned);
            auto &cache = owned.cached;
            switch (mutation) {
            case 0: cache.identity.build[0] ^= 1; break;
            case 1: cache.identity.image[0] ^= 1; break;
            case 2: ++cache.identity.owner; break;
            case 3: ++cache.instance; break;
            case 4: ++cache.epoch; break;
            case 5: cache.sequence = 0; break;
            case 6: ++cache.sequence; break;
            case 7: cache.policy.max_age_ns = 1; break;
            case 8: cache.measured.status = native::measurement::Status::unavailable; break;
            case 9: ++cache.measured.owner; break;
            case 10: cache.measured.digest[31] ^= 1; break;
            case 11: cache.measured.frequency = 0; break;
            case 12: cache.measured.read_completed = 99; break;
            case 13: cache.error.code = observer::Status::unavailable; break;
            case 14: ++cache.subject_instance; break;
            }
            internal::unlock(owned);
            require(observer::observe(lease).data().error.code != observer::Status::ok &&
                original.check().error.code != observer::Status::ok && counters.reads == 1,
                "corrupt cache accepted or silently recalibrated");
        }
    }
    reset();
    {
        auto made = make({observer::Mode::periodic_bounded_age, 100, 1000}); auto lease = made.owner.lease();
        faults.clock_advance_at = 3; faults.clock_advance_to = 500;
        auto late = observer::observe(lease);
        require(late.data().error.code == observer::Status::expired && late.data().measured.read_started == 100 &&
            late.data().measured.read_completed == 100, "publication delay looked fresh after a short scan");
    }
    reset();
    {
        auto made = make({observer::Mode::periodic_bounded_age, 100, 1000}); auto lease = made.owner.lease();
        auto old = observer::observe(lease);
        faults.clock_advance_at = counters.clocks + 1; faults.clock_advance_to = 201;
        require(old.check().error.code == observer::Status::expired, "expiry at consumption accepted");
        auto fresh = observer::observe(lease);
        require(fresh.check().error.code == observer::Status::ok && old.data().measured.read_started == 100 &&
            old.check().error.code == observer::Status::expired, "new request silently refreshed pending grant");
    }
    reset();
    {
        auto a = make(), b = make(); auto lease_a = a.owner.lease(), lease_b = b.owner.lease();
        auto first = observer::observe(lease_a), second = observer::observe(lease_b);
        auto &target = state(lease_a); internal::lock(target); target.cached = second.data(); internal::unlock(target);
        require(observer::observe(lease_a).data().error.code == observer::Status::invalid_snapshot,
            "other instance supplied cache authority");
        require(observer::observe(lease_b).reused() && second.check().error.code == observer::Status::ok && counters.reads == 2,
            "cross-cache failure touched independent owner");
    }
    balanced();
}
}
