#include "observer_fixture.hpp"
#include "measurement/snapshot_report.hpp"

#include <cstdio>
#include <cstring>
#include <type_traits>

static_assert(std::is_trivially_copyable_v<pyobfuscator::native::measurement::observer::SnapshotReport>,
    "the report must remain a value-only record");

namespace {
using namespace observer_test;

std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "report input open");
    std::vector<std::uint8_t> bytes;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        require(bytes.size() < 512 * 1024, "report input budget");
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "report input read");
    return bytes;
}

bool same(const observer::Observation &a, const observer::Observation &b) {
    return internal::same_identity(a.identity, b.identity) &&
        a.policy.mode == b.policy.mode && a.policy.max_age_ns == b.policy.max_age_ns &&
        a.policy.max_scan_ns == b.policy.max_scan_ns && a.instance == b.instance &&
        a.subject_instance == b.subject_instance && a.epoch == b.epoch && a.sequence == b.sequence &&
        a.measured.status == b.measured.status && a.measured.kind == b.measured.kind &&
        a.measured.subject == b.measured.subject && a.measured.owner == b.measured.owner &&
        a.measured.read_started == b.measured.read_started &&
        a.measured.read_completed == b.measured.read_completed &&
        a.measured.frequency == b.measured.frequency &&
        std::memcmp(a.measured.digest, b.measured.digest, sizeof(a.measured.digest)) == 0 &&
        a.error.code == b.error.code && a.error.context == b.error.context &&
        a.error.reference == b.error.reference && a.error.capture == b.error.capture;
}
}

int main(int argc, char **argv) {
    using namespace observer_test;
    using namespace capture_test;
    require(argc == 4, "report metadata/package/plaintext");
    const auto meta = read(argv[1]); package = read(argv[2]); plaintext = read(argv[3]);
    require(meta.size() == 84, "report typed metadata");
    std::memcpy(&identity, meta.data(), 52); std::memcpy(words, meta.data() + 52, 32);

    reset();
    {
        auto a = make({observer::Mode::periodic_bounded_age, 50, 20});
        auto b = make({observer::Mode::periodic_bounded_age, 50, 20});
        auto lease_a = a.owner.lease(), lease_b = b.owner.lease();
        auto first = observer::observe(lease_a), second = observer::observe(lease_b);
        observer::SnapshotReport report_a{}, report_b{};
        const auto before = counters.clocks;
        require(observer::copy_snapshot_report(first, report_a) == observer::Status::ok,
            "first owner report denied");
        const auto one_check_clocks = counters.clocks - before;
        const auto before_direct = counters.clocks;
        require(first.check().error.code == observer::Status::ok &&
            one_check_clocks == 1 && counters.clocks - before_direct == one_check_clocks,
            "report did not perform exactly one check");
        require(observer::copy_snapshot_report(second, report_b) == observer::Status::ok &&
            same(report_a.observation, first.data()) && same(report_b.observation, second.data()) &&
            report_a.validation.consumed_at == 100 && report_a.validation.frequency == 1000000000 &&
            !report_a.reused && !report_b.reused &&
            report_a.observation.instance != report_b.observation.instance && counters.reads == 2,
            "independent owner value copies");

        auto cached = observer::observe(lease_b); observer::SnapshotReport reused{};
        require(observer::copy_snapshot_report(cached, reused) == observer::Status::ok && reused.reused &&
            same(reused.observation, report_b.observation) && counters.reads == 2,
            "reused report changed the measured value");
        faults.clock_ticks = 151;
        observer::SnapshotReport expired{};
        require(observer::copy_snapshot_report(first, expired) == observer::Status::expired &&
            expired.observation.error.code == observer::Status::ok &&
            expired.validation.error.code == observer::Status::expired &&
            same(expired.observation, report_a.observation) && counters.reads == 2,
            "expired pending report refreshed or lost provenance");
        auto refreshed = observer::observe(lease_a);
        require(refreshed.data().sequence == 2 && counters.reads == 3 &&
            same(report_a.observation, first.data()) &&
            report_a.validation.error.code == observer::Status::ok,
            "refresh changed copied report");
        require(observer::invalidate(lease_b).code == observer::Status::revoked,
            "second owner invalidate");
        observer::SnapshotReport revoked{};
        require(observer::copy_snapshot_report(second, revoked) == observer::Status::revoked &&
            same(revoked.observation, report_b.observation) &&
            revoked.validation.error.code == observer::Status::revoked &&
            report_b.validation.error.code == observer::Status::ok,
            "revocation changed earlier copy or lost error");
    }

    reset();
    {
        observer::Snapshot empty; observer::SnapshotReport report{};
        require(observer::copy_snapshot_report(empty, report) == observer::Status::unavailable &&
            report.observation.error.code == observer::Status::unavailable &&
            report.validation.error.code == observer::Status::unavailable,
            "failed acquisition became success");
        auto made = make(); auto lease = made.owner.lease();
        faults.read = true;
        auto denied = observer::observe(lease); observer::SnapshotReport failed{};
        require(observer::copy_snapshot_report(denied, failed) == observer::Status::capture_failed &&
            same(failed.observation, denied.data()) &&
            failed.validation.error.code == observer::Status::capture_failed &&
            failed.observation.error.capture == native::measurement::Status::read_failed,
            "failed acquisition lost source");
    }

    reset();
    {
        auto a = make(), b = make(); auto lease_a = a.owner.lease(), lease_b = b.owner.lease();
        auto first = observer::observe(lease_a), second = observer::observe(lease_b);
        observer::SnapshotReport original{};
        require(observer::copy_snapshot_report(first, original) == observer::Status::ok,
            "cross-owner baseline");
        auto &target = state(lease_a); internal::lock(target);
        target.cached = second.data(); internal::unlock(target);
        auto denied = observer::observe(lease_a); observer::SnapshotReport substitution = original;
        require(observer::copy_snapshot_report(denied, substitution) == observer::Status::invalid_snapshot &&
            substitution.observation.error.code == observer::Status::invalid_snapshot &&
            substitution.validation.error.code == observer::Status::invalid_snapshot &&
            original.validation.error.code == observer::Status::ok &&
            observer::copy_snapshot_report(second, substitution) == observer::Status::ok &&
            same(substitution.observation, second.data()),
            "cross-owner cache substitution granted authority or leaked failure");
    }
    balanced();
    std::puts("snapshot report: two owners, single check, copy stability, expiry, revocation, acquisition and substitution pass");
}
