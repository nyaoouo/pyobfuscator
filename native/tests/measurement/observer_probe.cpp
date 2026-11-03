#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "measurement/observer_internal.hpp"
#include "measurement/snapshot_report.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

namespace native = pyobfuscator::native;
namespace measurement = native::measurement;
namespace reference = measurement::reference;
namespace observer = measurement::observer;
namespace internal = observer::detail;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "observer contract: %s\n", message); std::exit(1); }
}
std::vector<std::uint8_t> read(const char *path, std::size_t limit) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "open input");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        require(data.size() < limit, "bounded input"); data.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "read input"); return data;
}
struct Input {
    reference::Identity identity{};
    std::uint32_t words[8]{};
    std::vector<std::uint8_t> package;
};
Input input(const char *metadata, const char *package) {
    auto bytes = read(metadata, 84); require(bytes.size() == 84, "independent metadata");
    Input result; std::memcpy(&result.identity, bytes.data(), 52); std::memcpy(result.words, bytes.data() + 52, 32);
    result.package = read(package, 512 * 1024); return result;
}
observer::Creation create(const Input &data, observer::Mode mode, native::platform::CodeAddress member,
        std::uint64_t subject_instance = 1) {
    const observer::Policy policy{mode, mode == observer::Mode::once_per_instance ? 0ull : 10000000000ull, 10000000000ull};
    return observer::create(data.package.data(), data.package.size(), data.identity, data.words, {policy, member, subject_instance});
}
native::BootstrapContextResult foreign(const native::BootstrapContextRequest &, void *) noexcept {
    return {native::BootstrapContextStatus::ok, internal::reply};
}
std::uint8_t patch(native::platform::CodeAddress member, std::uint8_t replacement) {
    auto *byte = reinterpret_cast<volatile std::uint8_t *>(member);
    const auto previous = *byte;
    DWORD protection = 0, ignored = 0;
    auto *address = reinterpret_cast<void *>(member);
    require(VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &protection) != 0, "protect test function");
    *byte = replacement;
    require(FlushInstructionCache(GetCurrentProcess(), address, 1) != 0 &&
        VirtualProtect(address, 1, protection, &ignored) != 0, "restore test function RX protection");
    return previous;
}
}

int main(int argc, char **argv) {
    require(argc == 7, "two metadata/package inputs, ordinary and fixed-address DLLs");
    const auto a = input(argv[1], argv[2]), b = input(argv[3], argv[4]);
    // The GNU fixture imports this runtime. Keep dependencies fixed while testing target
    // unload/reload; an MSVC harness otherwise unloads and remaps them with the target.
    const auto fixture_runtime = LoadLibraryA("libc++.dll");
    require(fixture_runtime != nullptr, "pin fixture runtime dependency");
    auto module = LoadLibraryA(argv[5]); require(module != nullptr, "load actual module");
    auto member = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    require(member != nullptr, "actual member");
    for (auto mode : {observer::Mode::once_per_instance, observer::Mode::periodic_bounded_age, observer::Mode::per_use}) {
        auto made = create(a, mode, member); require(made.error.code == observer::Status::ok, "create owner");
        auto lease = made.owner.lease();
        auto first = observer::observe(lease); require(first.data().error.code == observer::Status::ok, "fresh read");
        require(!first.reused() && first.data().instance == lease.generation() && first.data().sequence == 1 &&
            first.data().subject_instance == 1 && first.data().epoch == 1 &&
            first.data().measured.frequency != 0, "actual tuple");
        require(first.check().error.code == observer::Status::ok, "consume fresh");
        observer::SnapshotReport first_report{};
        require(observer::copy_snapshot_report(first, first_report) == observer::Status::ok &&
            first_report.validation.error.code == observer::Status::ok &&
            first_report.observation.instance == lease.generation() &&
            first_report.observation.sequence == first.data().sequence &&
            first_report.observation.measured.read_started == first.data().measured.read_started &&
            std::memcmp(first_report.observation.measured.digest, first.data().measured.digest, 32) == 0 &&
            !first_report.reused, "actual Windows report copy");
        auto second = observer::observe(lease); require(second.data().error.code == observer::Status::ok, "second use");
        require(second.reused() == (mode != observer::Mode::per_use), "policy cache boundary");
        require(second.data().sequence == (mode == observer::Mode::per_use ? 2 : 1), "actual read sequence");
        auto refreshed = observer::observe(lease, true);
        require(refreshed.data().sequence > second.data().sequence && !refreshed.reused(), "explicit stronger refresh");
        require(first.data().sequence == 1 && first.check().error.code == observer::Status::ok, "old snapshot survived refresh");
        require(first_report.observation.sequence == 1 && first_report.validation.error.code == observer::Status::ok,
            "actual Windows refresh changed copied report");
        observer::Snapshot moved = std::move(first);
        require(first.data().error.code == observer::Status::unavailable, "move retired source");
        second = std::move(moved);
        require(moved.data().error.code == observer::Status::unavailable && second.check().error.code == observer::Status::ok,
            "replacement move");
        require(observer::invalidate(lease).code == observer::Status::revoked, "explicit invalidation");
        require(second.check().error.code == observer::Status::revoked &&
            observer::observe(lease).data().error.code == observer::Status::revoked, "revoked cannot reopen");
        observer::SnapshotReport denied_report{};
        require(observer::copy_snapshot_report(second, denied_report) == observer::Status::revoked &&
            denied_report.observation.error.code == observer::Status::ok &&
            denied_report.validation.error.code == observer::Status::revoked,
            "actual Windows report lost revoked origin");
        made.owner.close();
        require(second.check().error.code == observer::Status::closed, "closed origin rejected retained snapshot");
    }
    {
        auto owner_a = create(a, observer::Mode::once_per_instance, member);
        auto owner_b = create(b, observer::Mode::once_per_instance, member);
        require(owner_a.error.code == observer::Status::ok && owner_b.error.code == observer::Status::ok, "two owners");
        auto lease_a = owner_a.owner.lease(), lease_b = owner_b.owner.lease();
        auto snap_a = observer::observe(lease_a), snap_b = observer::observe(lease_b);
        observer::SnapshotReport report_a{}, report_b{};
        require(observer::copy_snapshot_report(snap_a, report_a) == observer::Status::ok &&
            observer::copy_snapshot_report(snap_b, report_b) == observer::Status::ok &&
            report_a.observation.instance != report_b.observation.instance &&
            report_a.observation.identity.owner != report_b.observation.identity.owner,
            "actual Windows reports shared owner identity");
        require(snap_a.data().error.code == observer::Status::ok && snap_b.data().error.code == observer::Status::ok &&
            snap_a.data().instance != snap_b.data().instance &&
            std::memcmp(snap_a.data().measured.digest, snap_b.data().measured.digest, 32) != 0, "independent domains/contexts");
        auto *state_a = static_cast<internal::State *>(native::detail::BootstrapContextAccess::state(lease_a)->spec.user_data);
        internal::lock(*state_a); state_a->cached.measured.digest[0] ^= 1; internal::unlock(*state_a);
        require(observer::observe(lease_a).data().error.code == observer::Status::digest_mismatch, "poisoned own cache");
        require(snap_a.check().error.code == observer::Status::digest_mismatch, "poison revoked old authority");
        observer::SnapshotReport poisoned{};
        require(observer::copy_snapshot_report(snap_a, poisoned) == observer::Status::digest_mismatch &&
            poisoned.observation.instance == report_a.observation.instance &&
            poisoned.validation.error.code == observer::Status::digest_mismatch &&
            report_a.validation.error.code == observer::Status::ok,
            "actual Windows report accepted poisoned owner");
        auto still_b = observer::observe(lease_b);
        require(still_b.reused() && still_b.check().error.code == observer::Status::ok &&
            still_b.data().sequence == snap_b.data().sequence, "other owner did not inherit poison/refresh");
    }
    auto wrong = a; wrong.words[0] ^= 1;
    const auto denied = create(wrong, observer::Mode::once_per_instance, member);
    require(denied.error.code == observer::Status::reference_failed &&
        denied.error.reference == reference::Status::authentication_failed, "reference failure source");
    auto invalid = observer::create(a.package.data(), a.package.size(), a.identity, a.words,
        {{observer::Mode::per_use, 0, 1}, member, 1});
    require(invalid.error.code == observer::Status::invalid_specification, "invalid freshness rejected");
    {
        auto made = create(a, observer::Mode::per_use, member); auto lease = made.owner.lease();
        observer::Snapshot snapshots[16]; std::thread workers[16];
        for (unsigned index = 0; index != 16; ++index) workers[index] = std::thread([&, index] {
            snapshots[index] = observer::observe(lease);
        });
        for (auto &worker : workers) worker.join();
        for (unsigned index = 0; index != 16; ++index) {
            require(!snapshots[index].reused() && snapshots[index].check().error.code == observer::Status::ok,
                "concurrent operation failed or coalesced");
            for (unsigned previous = 0; previous != index; ++previous)
                require(snapshots[index].data().sequence != snapshots[previous].data().sequence, "concurrent sequence alias");
        }
        internal::Response output;
        internal::Request request{internal::version, sizeof(internal::Request), internal::Action::observe,
            0, lease.generation(), nullptr, &output};
        for (unsigned which = 0; which != 5; ++which) {
            auto bad = request;
            if (which == 0) ++bad.version;
            else if (which == 1) bad.force = 2;
            else if (which == 2) bad.action = static_cast<internal::Action>(0);
            else if (which == 3) bad.output = nullptr;
            else ++bad.instance;
            const auto result = lease.invoke({internal::operation, &bad, sizeof(bad)});
            require(result.status == (which == 4 ? native::BootstrapContextStatus::context_mismatch :
                native::BootstrapContextStatus::invalid_request), "private protocol malformed/origin source");
        }
        require(snapshots[0].check().error.code == observer::Status::ok, "malformed request corrupted existing authority");
    }
    {
        auto arbitrary = native::create_bootstrap_context({native::bootstrap_context_abi_version, foreign});
        auto denied_foreign = observer::observe(arbitrary.owner.lease());
        require(denied_foreign.data().error.code != observer::Status::ok &&
            denied_foreign.check().error.code != observer::Status::ok, "success-only foreign context forged observation");
    }
    for (auto mode : {observer::Mode::once_per_instance, observer::Mode::periodic_bounded_age, observer::Mode::per_use}) {
        const observer::Policy policy{mode, mode == observer::Mode::once_per_instance ? 0ull : 1000000000ull, 1000000000ull};
        auto made = observer::create(a.package.data(), a.package.size(), a.identity, a.words, {policy, member, 1});
        auto lease = made.owner.lease(); auto initial = observer::observe(lease);
        require(initial.check().error.code == observer::Status::ok, "pre-mutation observation");
        auto modified = member;
        if (a.identity.kind != 1) {
            const auto *owned = static_cast<const internal::State *>(
                native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
            modified = reinterpret_cast<native::platform::CodeAddress>(
                const_cast<std::uint8_t *>(owned->view.base) + owned->reference.descriptor().ranges[0].rva);
        }
        const auto original = *reinterpret_cast<const volatile std::uint8_t *>(modified);
        patch(modified, original ^ 1);
        auto changed = observer::observe(lease);
        if (mode != observer::Mode::per_use) {
            require(changed.reused() && changed.check().error.code == observer::Status::ok,
                "declared cached mutation window not exercised");
            if (mode == observer::Mode::periodic_bounded_age) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1100));
                changed = observer::observe(lease);
            } else changed = observer::observe(lease, true);
        }
        patch(modified, original);
        require(changed.data().error.code == observer::Status::digest_mismatch && !changed.reused() &&
            initial.check().error.code == observer::Status::digest_mismatch &&
            observer::observe(lease).data().error.code == observer::Status::digest_mismatch,
            "actual changed code escaped detection or reference rebased after restoration");
    }
    {
        require(FreeLibrary(module) != 0, "ordinary ASLR fixture release");
        module = LoadLibraryA(argv[6]); require(module != nullptr, "fixed-address fixture load");
        member = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
        auto made = create(a, observer::Mode::once_per_instance, member, 2); auto lease = made.owner.lease();
        auto retained = observer::observe(lease); const auto previous_instance = retained.data().instance;
        const auto previous_base = module;
        require(FreeLibrary(module) != 0, "external module release"); module = nullptr;
        require(GetModuleHandleA(argv[6]) == previous_base && retained.check().error.code == observer::Status::ok,
            "observer failed to pin target through use");
        made.owner.close(); made.owner = {}; lease.reset();
        require(GetModuleHandleA(argv[6]) == previous_base && retained.check().error.code == observer::Status::closed,
            "closed origin freed retained target or granted permission");
        retained.reset();
        require(GetModuleHandleA(argv[6]) == nullptr, "last snapshot retained target module");
        module = LoadLibraryA(argv[6]);
        if (module != previous_base)
            std::fprintf(stderr, "reload address old=%p new=%p error=%lu\n", static_cast<void *>(previous_base),
                static_cast<void *>(module), static_cast<unsigned long>(GetLastError()));
        require(module != nullptr && module == previous_base, "exercise actual same-address reload");
        auto replacement = create(a, observer::Mode::once_per_instance,
            reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target")), 3);
        auto next = observer::observe(replacement.owner.lease());
        require(next.check().error.code == observer::Status::ok && next.data().instance != previous_instance &&
            next.data().subject_instance == 3, "same address reused old module/owner generation");
    }
    require(FreeLibrary(module) != 0, "replacement module release");
    require(FreeLibrary(fixture_runtime) != 0, "fixture runtime release");
    std::puts("actual AEAD/code three-policy mutation windows, snapshots/moves/poison,16 concurrent operations/protocol errors and retained same-address reload pass");
}
