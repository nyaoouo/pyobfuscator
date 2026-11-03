#include "observer_fixture.hpp"
#include "measurement/owned_capture.hpp"
#include "measurement/owner_cache.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace test = observer_test;
namespace native = test::native;
namespace observer = test::observer;
namespace {
constexpr std::uint64_t key_a = 0x0123456789abcdefull, key_b = 0xfedcba9876543210ull;
native::measurement::Capture capture_a(const native::measurement::Descriptor &input,
        native::platform::CodeAddress member, std::uint64_t binding) noexcept {
    return native::measurement::capture_owner<7, key_a>(input, member, binding);
}
bool cache_a(std::uint64_t binding, observer::Observation &record) noexcept {
    return observer::transform_owner_cache<7, key_a>(binding, record);
}
bool cache_b(std::uint64_t binding, observer::Observation &record) noexcept {
    return observer::transform_owner_cache<7, key_b>(binding, record);
}
const observer::ReaderBinding reader{1, 7, key_a, capture_a, cache_a};
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); test::require(file != nullptr, "owner fault input");
    std::vector<std::uint8_t> bytes;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        test::require(bytes.size() < 512 * 1024, "owner fault input budget"); bytes.push_back(static_cast<std::uint8_t>(value));
    }
    test::require(!std::ferror(file) && std::fclose(file) == 0, "owner fault input close"); return bytes;
}
void check_cleanup_failure() {
    // Reader release failure terminates inside State destruction, before the two
    // generic context provider pins are released. Ignoring that failure fails here.
    if (test::pins != 4 || test::unpins != 2) std::_Exit(1);
}
void slow_hash(std::uint8_t *) { capture_test::faults.clock_ticks = 400; }
void cases() {
    using namespace test;
    using namespace capture_test;
    for (unsigned pin = 1; pin != 5; ++pin) {
        reset(); fail_pin = pin;
        auto made = make({}, &reader);
        require(made.error.code == (pin < 3 ? observer::Status::invalid_specification : observer::Status::context_failed),
            "partial reader/context pin failure origin"); balanced();
    }
    for (unsigned allocation = 1; allocation != 5; ++allocation) {
        reset(); faults.allocation_failure_at = allocation;
        auto made = make({}, &reader);
        const auto wanted = allocation < 3 ? observer::Status::reference_failed : allocation == 3 ?
            observer::Status::allocation_failed : observer::Status::context_failed;
        require(made.error.code == wanted, "reader factory allocation failure"); balanced();
    }
    reset();
    {
        auto made = make({observer::Mode::periodic_bounded_age, 50, 20}, &reader); auto lease = made.owner.lease();
        require(made.error.code == observer::Status::ok && pins == 4, "both reader callbacks and context code pinned");
        auto old = observer::observe(lease);
        require(old.check().error.code == observer::Status::ok && counters.reads == 1 &&
            std::memcmp(state(lease).cached.measured.digest, old.data().measured.digest, 32) != 0, "encoded owner cache");
        faults.clock_ticks = 150; auto hit = observer::observe(lease);
        require(hit.reused() && hit.check().error.code == observer::Status::ok && counters.reads == 1 &&
            hit.data().measured.read_started == 100, "decode retained exact conservative acquisition age");
        faults.clock_ticks = 151; auto fresh = observer::observe(lease);
        require(!fresh.reused() && fresh.check().error.code == observer::Status::ok && fresh.data().measured.read_started == 151 &&
            old.data().measured.read_started == 100 && old.check().error.code == observer::Status::expired && counters.reads == 2,
            "refresh changed a pending snapshot or rebased its old timestamp");
    }
    reset();
    {
        auto made = make({observer::Mode::periodic_bounded_age, 1000, 200}, &reader); auto lease = made.owner.lease();
        on_hash = slow_hash; auto late = observer::observe(lease); on_hash = nullptr;
        require(late.data().error.code == observer::Status::scan_expired && !state(lease).has_cache &&
            observer::observe(lease).data().error.code == observer::Status::scan_expired && counters.reads == 1,
            "late scan published or reopened encoded success");
    }
    for (unsigned fault = 0; fault != 3; ++fault) {
        reset();
        {
            auto made = make({}, &reader); auto lease = made.owner.lease(); auto old = observer::observe(lease);
            if (fault == 0) state(lease).cached.measured.digest[0] ^= 1;
            if (fault == 1) state(lease).reader.cache_codec = cache_b;
            if (fault == 2) { faults.allocation = true; }
            auto denied = observer::observe(lease, fault == 2);
            const auto wanted = fault == 0 ? observer::Status::digest_mismatch : fault == 1 ?
                observer::Status::invalid_snapshot : observer::Status::capture_failed;
            require(denied.data().error.code == wanted && old.check().error.code == wanted,
                "bad encoded cache/codec/allocation preserved authority");
            faults.allocation = false;
            require(observer::observe(lease).data().error.code == wanted, "codec/source failure silently recovered");
        }
    }
    balanced();
}
}
int main(int argc, char **argv) {
    test::require(argc == 4 || argc == 5, "owner fault metadata/package/plaintext");
    const auto metadata = read(argv[1]); test::require(metadata.size() == 84, "owner fault metadata size");
    std::memcpy(&test::identity, metadata.data(), 52); std::memcpy(test::words, metadata.data() + 52, 32);
    test::package = read(argv[2]); test::plaintext = read(argv[3]);
    if (argc == 5) {
        test::require(std::strcmp(argv[4], "reader-close") == 0, "owner terminal failure mode");
        test::reset(); auto made = test::make({}, &reader);
        test::require(made.error.code == observer::Status::ok && std::atexit(check_cleanup_failure) == 0, "owned close setup");
        test::fail_release = true; return 3;
    }
    cases();
    std::puts("owned reader: callback pins/partial failures/erasure, decoded deadline/refresh, late scan and cache/codec/source refusals pass");
}
