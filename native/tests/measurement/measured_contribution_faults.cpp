#include "measured_contribution_cases.hpp"
#include "observer_fixture.hpp"

#include <cstdio>

namespace {
using namespace observer_test;
namespace measured = native::contribution::measured;
native::BootstrapContextLease *active = nullptr;
native::BootstrapContextOwner *owner = nullptr;
unsigned action = 0, calls = 0, erasures = 0;
bool nested = false;
void erased(void *value, std::size_t size) {
    for (std::size_t index = 0; index != size; ++index)
        require(static_cast<std::uint8_t *>(value)[index] == 0, "decoded contribution material not erased");
    if (size == 32) ++erasures;
}
void hashed(std::uint8_t *) {
    if (nested) return;
    ++calls;
    if (action == 1 && calls == 1) capture_test::faults.hash = true;
    if (calls != 2) return;
    if (action == 2) capture_test::faults.hash = true;
    else if (action == 3) capture_test::faults.clock_ticks = 151;
    else if (action == 4) observer::invalidate(*active);
    else if (action == 5) owner->close();
    else if (action == 6) ++capture_test::faults.clock_frequency;
    else if (action == 8) {
        nested = true;
        require(observer::observe(*active, true).check().error.code == observer::Status::ok, "contribution-time refresh");
        nested = false;
    }
}
}
void measured_contribution_faults() {
    using namespace observer_test;
    namespace measured = native::contribution::measured;
    const auto previous_stage = identity.stage; identity.stage = 2;
    // The controlled envelope fixture authenticates its supplied plaintext. Keep the
    // independent identity in that test input consistent with this post-release purpose.
    for (unsigned byte = 0; byte != 4; ++byte)
        plaintext[40 + byte] = static_cast<std::uint8_t>(identity.stage >> (byte * 8));
    for (action = 0; action != 11; ++action) {
        reset();
        {
            auto made = make({observer::Mode::periodic_bounded_age, 50, 50});
            auto lease = made.owner.lease(); auto snapshot = observer::observe(lease);
            native::release::Record record{"PYOBF-RELKEY-v2", 2, 64, {}, {}};
            for (auto &byte : record.mask) byte = 0x11;
            native::path_fold::Storage fold{};
            active = &lease; owner = &made.owner; calls = erasures = 0;
            if (action == 7) capture_test::faults.allocation_failure_at = capture_test::counters.allocation_attempts + 1;
            if (action == 10) { record.version = 1; record.magic[14] = '1'; }
            capture_test::on_hash = hashed; capture_test::on_erased = erased;
            observer::Snapshot missing;
            const auto result = measured::derive(fold, record, action == 9 ? missing : snapshot, 7, {3, 5, 7, 11, 13});
            capture_test::on_hash = nullptr; capture_test::on_erased = nullptr; capture_test::faults.hash = false;
            require(erasures >= (calls >= 2 ? 4u : 3u), "decoded bytes/words or reconstructed material not erased");
            if (action == 0 || action == 8) {
                require(result.status == measured::Status::ok && result.value.word == 0xddddddddu,
                    "normal refresh changed valid contribution material");
                require(snapshot.data().sequence == 1, "refresh replaced retained contribution snapshot");
            } else {
                require(result.value.word == 0, "failed operation published a contribution");
                if (action == 1 || action == 9 || action == 10) {
                    const auto wanted = action == 1 ? native::release::measured::Status::crypto_failed :
                        action == 9 ? native::release::measured::Status::observation_failed : native::release::measured::Status::invalid_record;
                    require(result.status == measured::Status::material_failed && result.material.status == wanted,
                        "material failure lost origin");
                } else if (action == 2 || action == 7) {
                    require(result.status == measured::Status::derivation_failed && result.value.status ==
                        (action == 2 ? native::BootstrapContextStatus::unavailable : native::BootstrapContextStatus::allocation_failed),
                        "derivation failure lost hash/allocation origin");
                } else {
                    const auto wanted = action == 3 ? observer::Status::expired : action == 4 ? observer::Status::revoked :
                        action == 5 ? observer::Status::closed : observer::Status::clock_failed;
                    require(result.status == measured::Status::observation_failed && result.observation.code == wanted,
                        "contribution-time expiry/revoke/close/clock change granted word");
                }
            }
        }
    }
    identity.stage = previous_stage;
    for (unsigned byte = 0; byte != 4; ++byte)
        plaintext[40 + byte] = static_cast<std::uint8_t>(identity.stage >> (byte * 8));
    balanced();
    std::puts("measured contribution material/word erasure,dirty hashes,allocation,expiry/revoke/close/clock,refresh and missing/v1 sources pass");
}
