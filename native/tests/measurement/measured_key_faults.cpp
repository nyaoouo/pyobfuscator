#include "observer_fixture.hpp"
#include "release/measured_internal.hpp"

#include <cstdio>
#include <cstring>

#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
#include "measured_contribution_cases.hpp"
#endif
#if defined(PYOBF_TEST_MEASURED_SCOPE)
void scope_faults();
#endif

namespace measured = pyobfuscator::native::release::measured;
namespace {
using namespace observer_test;
native::BootstrapContextLease *active = nullptr;
native::BootstrapContextOwner *owner = nullptr;
std::uint8_t *watched = nullptr;
unsigned action = 0, erased_keys = 0;
bool nested = false;
void erased(void *pointer, std::size_t size) {
    for (std::size_t index = 0; index != size; ++index)
        require(static_cast<std::uint8_t *>(pointer)[index] == 0, "key/material erasure incomplete");
    if (pointer == watched && size == 32) { watched = nullptr; ++erased_keys; }
}
void hashed(std::uint8_t *key) {
    if (nested) return;
    require(watched == nullptr, "previous expansion key still visible"); watched = key;
    nested = true;
    if (action == 2) capture_test::faults.clock_ticks = 151;
    else if (action == 3) require(observer::invalidate(*active).code == observer::Status::revoked, "hash-time invalidation");
    else if (action == 4) owner->close();
    else if (action == 5) require(observer::observe(*active, true).check().error.code == observer::Status::ok, "hash-time normal refresh");
    else if (action == 6) ++capture_test::faults.clock_frequency;
    nested = false;
}
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "key fault input open");
    std::vector<std::uint8_t> data;
    for (int byte; (byte = std::fgetc(file)) != EOF;) {
        require(data.size() < 512 * 1024, "key fault input bound"); data.push_back(static_cast<std::uint8_t>(byte));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "key fault input read"); return data;
}
void blank(const std::uint8_t (&key)[32]) { for (auto byte : key) require(byte == 0, "failed published key survived"); }
}
int main(int argc, char **argv) {
    using namespace observer_test;
    require(argc == 4 || argc == 5, "key fault independent metadata/package/plaintext");
    const auto meta = read(argv[1]); package = read(argv[2]); plaintext = read(argv[3]);
    require(meta.size() == 84, "key fault identity/material frame");
    std::memcpy(&identity, meta.data(), 52); std::memcpy(words, meta.data() + 52, 32);
    if (argc == 5) {
        reset(); auto made = make(); auto lease = made.owner.lease(); auto snapshot = observer::observe(lease);
        if (std::strcmp(argv[4], "module-close") == 0) capture_test::faults.close = true;
        else if (std::strcmp(argv[4], "provider-close") == 0) fail_release = true;
        else return 2;
        return 3;
    }
    native::release::Record record{"PYOBF-RELKEY-v2", 2, 64, {}, {}};
    for (auto &byte : record.mask) byte = 0x11;
    native::path_fold::Storage fold{};
    for (action = 0; action != 7; ++action) {
        reset();
        {
            auto made = make({observer::Mode::periodic_bounded_age, 50, 50}); auto lease = made.owner.lease();
            auto snapshot = observer::observe(lease); active = &lease; owner = &made.owner;
            std::uint8_t key[32]; std::memset(key, 0xa5, sizeof(key));
            watched = nullptr; erased_keys = 0; capture_test::on_hash = hashed; capture_test::on_erased = erased;
            capture_test::faults.hash = action == 1;
            const auto result = measured::reconstruct(fold, record, snapshot, key);
            capture_test::on_hash = nullptr; capture_test::on_erased = nullptr; capture_test::faults.hash = false;
            require(watched == nullptr && erased_keys == 1, "transient expansion key not erased before return");
            if (action == 0 || action == 5) {
                require(result.status == measured::Status::ok, "normal refresh changed legitimate key availability");
                for (auto byte : key) require(byte == 0xcc, "typed mask not applied to actual expansion");
                require(snapshot.data().sequence == 1, "refresh rewrote in-flight key snapshot");
            } else if (action == 1) {
                require(result.status == measured::Status::crypto_failed, "dirty hash failure lost provenance"); blank(key);
            } else {
                const auto wanted = action == 2 ? observer::Status::expired : action == 3 ? observer::Status::revoked :
                    action == 4 ? observer::Status::closed : observer::Status::clock_failed;
                require(result.status == measured::Status::observation_failed && result.observation.code == wanted,
                    "hash-time expiry/revoke/close/clock failure granted key"); blank(key);
            }
            PYOBF_NATIVE_ERASE(key, sizeof(key));
        }
    }
    reset();
    {
        auto made = make(); auto snapshot = observer::observe(made.owner.lease());
        std::uint8_t key[32]; std::memset(key, 0xa5, sizeof(key)); auto invalid = identity; invalid.owner = 0;
        const auto count = capture_test::counters.hashes;
        require(measured::detail::expand(fold.words, invalid, snapshot.data().measured.digest, key) == measured::Status::invalid_identity,
            "invalid identity accepted"); blank(key);
        require(measured::detail::expand(fold.words, identity, nullptr, key) == measured::Status::invalid_argument,
            "null digest accepted"); blank(key);
        require(measured::detail::expand(fold.words, identity, snapshot.data().measured.digest, nullptr) == measured::Status::invalid_argument &&
            measured::reconstruct(fold, record, snapshot, nullptr).status == measured::Status::invalid_argument,
            "null key accepted");
        auto legacy = record; legacy.version = 1; legacy.magic[14] = '1';
        require(measured::reconstruct(fold, legacy, snapshot, key).status == measured::Status::invalid_record, "v1 downgrade"); blank(key);
        require(capture_test::counters.hashes == count, "invalid arguments reached expansion hash");
    }
    balanced();
#if defined(PYOBF_TEST_MEASURED_CONTRIBUTION)
    measured_contribution_faults();
#endif
#if defined(PYOBF_TEST_MEASURED_SCOPE)
    scope_faults();
#endif
    std::puts("measured key dirty hash/material/output erasure,expiry/revoke/close/reentry/refresh,origin errors and v1 refusal pass");
}
