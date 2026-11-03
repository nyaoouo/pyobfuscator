#include "observer_fixture.hpp"

#include <atomic>
#include <thread>

namespace observer_test {
namespace {
std::atomic<bool> entered{false}, resume{false};
native::BootstrapContextLease *active = nullptr;
std::atomic<unsigned> hashes{0};
void paused(std::uint8_t *) {
    if (hashes.fetch_add(1) != 0) return;
    entered.store(true);
    while (!resume.load()) std::this_thread::yield();
}
void reentered(std::uint8_t *) {
    if (hashes.fetch_add(1) != 0) return;
    auto nested = observer::observe(*active, true);
    require(nested.data().sequence == 2 && nested.check().error.code == observer::Status::ok, "same-owner reentry");
}
}
void races() {
    using namespace capture_test;
    reset();
    {
        auto made = make(); auto lease = made.owner.lease(); active = &lease; hashes = 0; on_hash = reentered;
        auto old = observer::observe(lease); on_hash = nullptr;
        require(old.data().sequence == 1 && old.check().error.code == observer::Status::ok &&
            observer::observe(lease).data().sequence == 2 && counters.reads == 2, "reentrant older scan replaced cache");
    }
    for (unsigned action = 0; action != 4; ++action) {
        reset();
        {
            auto made = make({observer::Mode::periodic_bounded_age, 100, 100}); auto lease = made.owner.lease();
            entered = false; resume = false; hashes = 0; on_hash = paused;
            observer::Snapshot older;
            std::thread worker([&] { older = observer::observe(lease, true); });
            while (!entered.load()) std::this_thread::yield();
            if (action == 0) {
                auto newer = observer::observe(lease, true);
                require(newer.data().sequence == 2, "newer actual read");
            } else if (action == 1) require(observer::invalidate(lease).code == observer::Status::revoked, "invalidate active scan");
            else if (action == 2) require(made.owner.close() == native::BootstrapContextStatus::busy, "close sees in-flight scan");
            else faults.clock_ticks = 500;
            resume = true; worker.join(); on_hash = nullptr;
            if (action == 0) {
                require(older.data().sequence == 1 && older.check().error.code == observer::Status::ok &&
                    observer::observe(lease).data().sequence == 2 && counters.reads == 2, "older scan overwrote cache");
            } else {
                const auto wanted = action == 1 ? observer::Status::revoked : action == 2 ?
                    observer::Status::closed : observer::Status::scan_expired;
                require(older.data().error.code == wanted && older.check().error.code == wanted,
                    "late revoked/closed/expired result accepted");
                const auto before = counters.reads;
                require(observer::observe(lease).data().error.code == wanted && counters.reads == before,
                    "late completion revived owner");
            }
        }
    }
    balanced();
}
}
