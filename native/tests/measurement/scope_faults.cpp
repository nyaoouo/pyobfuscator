#include "observer_fixture.hpp"
#include "contribution/scope.hpp"
#include "context/runtime.hpp"
#include "pyobfuscator_native/bootstrap_binding.hpp"

#include <cstdio>
#include <cstring>
#include <utility>

namespace {
using namespace observer_test;
namespace scoped = native::contribution::scoped;
unsigned action = 0, hashes = 0, clears = 0, admissions = 0;
std::uint64_t generation = 0;
native::BootstrapContextLease *origin = nullptr;
native::BootstrapContextOwner *parent = nullptr;
bool nested = false;
native::BootstrapContextResult admit(const native::BootstrapContextRequest &request, void *) noexcept {
    require(request.input_size == sizeof(scoped::Admission) && request.input != nullptr, "scope admission frame");
    scoped::Admission message; std::memcpy(&message, request.input, sizeof(message));
    require(message.version == scoped::admission_version && message.generation == generation &&
        message.function == identity.owner && message.observation_owner == identity.owner && message.reserved == 0 &&
        origin != nullptr && message.observation_instance == origin->generation() &&
        message.observation_context == reinterpret_cast<std::uintptr_t>(native::detail::BootstrapContextAccess::state(*origin)),
        "scope admission identity");
    if (++admissions == 2 && action == 6) parent->close();
    return {native::BootstrapContextStatus::ok, generation};
}
void hashed(std::uint8_t *) {
    if (nested) return;
    ++hashes;
    if (action >= 1 && action <= 3 && hashes == action) capture_test::faults.hash = true;
    if (hashes != 3) return;
    if (action == 4) capture_test::faults.clock_ticks = 151;
    else if (action == 5) observer::invalidate(*origin);
    else if (action == 7) ++capture_test::faults.clock_frequency;
    else if (action == 8) {
        nested = true;
        require(observer::observe(*origin, true).check().error.code == observer::Status::ok, "scope derivation refresh");
        nested = false;
    }
}
void erased(void *value, std::size_t size) {
    for (std::size_t index = 0; index != size; ++index)
        require(static_cast<std::uint8_t *>(value)[index] == 0, "scope material erased incompletely");
    if (size == 32) ++clears;
}
void write64(std::vector<std::uint8_t> &data, unsigned offset, std::uint64_t value) {
    for (unsigned byte = 0; byte != 8; ++byte) data[offset + byte] = static_cast<std::uint8_t>(value >> (byte * 8));
}
}
void scope_faults() {
    using namespace observer_test;
    const auto previous_stage = identity.stage; identity.stage = 2;
    for (unsigned byte = 0; byte != 4; ++byte) plaintext[40 + byte] = static_cast<std::uint8_t>(identity.stage >> (byte * 8));
    auto material = package; material.resize(scoped::material_bytes);
    write64(material, 32, material.size()); write64(material, 40 + 16, 32);
    for (action = 0; action != 12; ++action) {
        reset();
        {
            auto made_parent = native::create_bootstrap_context({native::bootstrap_context_abi_version, admit, nullptr, nullptr});
            require(made_parent.status == native::BootstrapContextStatus::ok, "scope fault parent");
            generation = made_parent.owner.generation(); parent = &made_parent.owner;
            auto expected = made_parent.owner.lease(); auto publication = native::bind_bootstrap_context(expected);
            require(publication.status == native::BootstrapContextStatus::ok, "scope fault publication");
            auto made = observer::create(package.data(), package.size(), identity, words,
                {{observer::Mode::per_use, 50, 50}, anchor, generation});
            require(made.error.code == observer::Status::ok, "scope fault observation owner");
            auto lease = made.owner.lease(); origin = &lease;
            native::path_fold::Storage fold{};
            scoped::Scope scope(expected, {0x1020, 1, identity.owner, 13, identity}, fold,
                material.data(), material.size(), observer::observe(lease));
            hashes = clears = admissions = 0; scope_material = true;
            capture_test::on_hash = hashed; capture_test::on_erased = erased;
            if (action == 9) capture_test::faults.allocation_failure_at = capture_test::counters.allocation_attempts + 1;
            fail_access = action == 10; fail_body = action == 11;
            const auto result = scope.query(0x1020, {1, identity.owner, 11, 13, 0});
            capture_test::on_hash = nullptr; capture_test::on_erased = nullptr;
            capture_test::faults.hash = false; fail_access = fail_body = false;
            require(clears >= 4, "scoped key/plaintext/word material survived");
            if (action == 0 || action == 8) {
                require(result.status == native::BootstrapContextStatus::ok && result.word == 0xddddddddu &&
                    result.authentication == native::archive::Status::ready, "valid/refresh scope lost material");
            } else {
                require(result.word == 0 && result.material.value.word == 0, "scope failure exposed nested or outer word");
                if (action == 1 || action == 2) require(result.material.material.status ==
                    native::release::measured::Status::crypto_failed, "scoped expansion failure source");
                else if (action == 3 || action == 9) require(result.material.status == native::contribution::measured::Status::derivation_failed &&
                    result.material.value.status == (action == 9 ? native::BootstrapContextStatus::allocation_failed :
                        native::BootstrapContextStatus::unavailable), "scoped word failure source");
                else if (action == 6) require(result.status == native::BootstrapContextStatus::closed, "scoped admission-time close");
                else if (action >= 10) require(result.authentication == (action == 10 ? native::archive::Status::verification_failed :
                    native::archive::Status::decode_failed), "scoped AEAD error source");
                else require(result.observation.code == (action == 4 ? observer::Status::expired :
                    action == 5 ? observer::Status::revoked : observer::Status::clock_failed), "scoped final observation error source");
            }
        }
    }
    identity.stage = previous_stage;
    for (unsigned byte = 0; byte != 4; ++byte) plaintext[40 + byte] = static_cast<std::uint8_t>(identity.stage >> (byte * 8));
    scope_material = false; balanced();
    std::puts("scoped 12 hash/AEAD/clock/close/revoke/refresh/allocation/error/erasure cases pass");
}
