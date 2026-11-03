#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "owner_readers.hpp"
#include "measurement/observer_internal.hpp"
#include "measurement/internal.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace native = pyobfuscator::native;
namespace measurement = native::measurement;
namespace observer = measurement::observer;
namespace generated = measurement::generated_readers;
extern "C" observer::Creation pyobf_test_owner_create(unsigned, const std::uint8_t *, std::size_t,
    const measurement::reference::Identity &, const std::uint32_t (&)[8], observer::Policy,
    native::platform::CodeAddress, std::uint64_t) noexcept;
namespace {
unsigned reads[10]{}, failing_owner = 0;
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "owner reader: %s\n", message); std::exit(1); }
}
std::vector<std::uint8_t> read(const char *path) {
    auto *file = std::fopen(path, "rb"); require(file != nullptr, "input open");
    std::vector<std::uint8_t> data;
    for (int value; (value = std::fgetc(file)) != EOF;) {
        require(data.size() < 512 * 1024, "input bound"); data.push_back(static_cast<std::uint8_t>(value));
    }
    require(!std::ferror(file) && std::fclose(file) == 0, "input read"); return data;
}
struct Input {
    measurement::reference::Identity identity{};
    std::uint32_t words[8]{};
    std::uint8_t expected[32]{};
    std::vector<std::uint8_t> package;
};
Input input(const char *metadata, const char *package) {
    const auto data = read(metadata); require(data.size() == 116, "typed metadata/expected digest");
    Input result; std::memcpy(&result.identity, data.data(), 52);
    std::memcpy(result.words, data.data() + 52, 32); std::memcpy(result.expected, data.data() + 84, 32);
    result.package = read(package); return result;
}
observer::Creation make(const Input &data, unsigned index, native::platform::CodeAddress member,
        observer::Mode mode, const observer::ReaderBinding *binding = nullptr) {
    const observer::Policy policy{mode, mode == observer::Mode::once_per_instance ? 0ull : 1000000000000ull,
        1000000000000ull};
    if (binding != nullptr) return observer::create(data.package.data(), data.package.size(), data.identity, data.words,
        {policy, member, 1, binding});
    return pyobf_test_owner_create(index, data.package.data(), data.package.size(), data.identity, data.words,
        policy, member, 1);
}
observer::detail::State &state(const native::BootstrapContextLease &lease) {
    return *static_cast<observer::detail::State *>(native::detail::BootstrapContextAccess::state(lease)->spec.user_data);
}
void reset_counts() { std::memset(reads, 0, sizeof(reads)); failing_owner = 0; }
void check(const observer::Snapshot &snapshot, const Input &data) {
    require(snapshot.check().error.code == observer::Status::ok &&
        snapshot.data().measured.owner == data.identity.owner &&
        std::memcmp(snapshot.data().measured.digest, data.expected, 32) == 0, "actual canonical CNG digest");
}
void policies(const Input (&data)[3], native::platform::CodeAddress member) {
    observer::Creation made[3]; native::BootstrapContextLease leases[3]; observer::Snapshot original[3];
    for (unsigned index = 0; index != 3; ++index) {
        made[index] = make(data[index], index, member, static_cast<observer::Mode>(index));
        require(made[index].error.code == observer::Status::ok, "owner creation"); leases[index] = made[index].owner.lease();
    }
    reset_counts();
    for (unsigned index = 0; index != 3; ++index) {
        original[index] = observer::observe(leases[index]); check(original[index], data[index]);
        require(!original[index].reused() && reads[7 + index] == 1, "each owner performs its own first read");
        require(state(leases[index]).spec.reader == nullptr &&
            std::memcmp(state(leases[index]).cached.measured.digest, original[index].data().measured.digest, 32) != 0,
            "persistent cache must have an owned representation, not a borrowed binding pointer");
        for (unsigned prior = 0; prior != index; ++prior)
            require(&state(leases[index]).cached != &state(leases[prior]).cached &&
                generated::bindings[index].capture != generated::bindings[prior].capture &&
                generated::bindings[index].cache_codec != generated::bindings[prior].cache_codec, "distinct cache/code addresses");
    }
    for (unsigned index = 0; index != 3; ++index) {
        auto next = observer::observe(leases[index]); check(next, data[index]);
        require(next.reused() == (index != 2) && reads[7 + index] == (index == 2 ? 2u : 1u), "independent policy hits/misses");
        if (index != 2) require(next.data().sequence == original[index].data().sequence, "cache decode changed its publication tuple");
    }
    auto refreshed = observer::observe(leases[1], true); check(refreshed, data[1]);
    require(!refreshed.reused() && reads[7] == 1 && reads[8] == 2 && reads[9] == 2, "one refresh supplied another owner's read");
    check(original[1], data[1]);
    state(leases[0]).cached = state(leases[1]).cached;
    require(observer::observe(leases[0]).data().error.code == observer::Status::invalid_snapshot &&
        original[0].check().error.code == observer::Status::invalid_snapshot, "cross-owner cache was accepted");
    auto peer = observer::observe(leases[1]); check(peer, data[1]); require(peer.reused() && reads[8] == 2, "peer cache invalidated");
}
void domains(const Input &data, native::platform::CodeAddress member) {
    for (unsigned mutation = 0; mutation != 5; ++mutation) {
        auto binding = generated::bindings[0];
        if (mutation == 0) ++binding.owner;
        if (mutation == 1) ++binding.key;
        if (mutation == 2) binding.capture = generated::bindings[1].capture;
        if (mutation == 3) binding.cache_codec = generated::bindings[1].cache_codec;
        if (mutation == 4) binding.capture = nullptr;
        auto made = make(data, 0, member, observer::Mode::once_per_instance, &binding);
        if (mutation == 0 || mutation == 4) {
            require(made.error.code == observer::Status::invalid_specification, "invalid binding admission"); continue;
        }
        require(made.error.code == observer::Status::ok, "domain fault setup");
        auto lease = made.owner.lease(); auto denied = observer::observe(lease);
        const auto wanted = mutation == 3 ? observer::Status::invalid_snapshot : observer::Status::capture_failed;
        require(denied.data().error.code == wanted && observer::observe(lease).data().error.code == wanted,
            "wrong callback domain published or revived a cache");
    }
    auto binding = generated::bindings[0]; auto made = make(data, 0, member, observer::Mode::once_per_instance, &binding);
    require(made.error.code == observer::Status::ok, "binding copy setup");
    binding = {}; auto lease = made.owner.lease(); auto observed = observer::observe(lease); check(observed, data);
}
void failure(const Input (&data)[3], native::platform::CodeAddress member) {
    auto a = make(data[0], 0, member, observer::Mode::per_use), b = make(data[1], 1, member, observer::Mode::per_use);
    auto first = a.owner.lease(), second = b.owner.lease();
    reset_counts(); auto old = observer::observe(first); check(old, data[0]);
    failing_owner = 7;
    auto denied = observer::observe(first), peer = observer::observe(second);
    require(denied.data().error.code == observer::Status::capture_failed &&
        denied.data().error.capture == measurement::Status::crypto_failed && reads[7] == 2,
        "source-specific hash failure lost its actual origin");
    check(peer, data[1]); require(reads[8] == 1 && old.check().error.code == observer::Status::capture_failed, "source failure crossed owners");
    failing_owner = 0;
}
void code_damage(const Input (&data)[3], native::platform::CodeAddress member) {
    auto a = make(data[0], 0, member, observer::Mode::once_per_instance), b = make(data[1], 1, member, observer::Mode::per_use);
    auto first = a.owner.lease(), second = b.owner.lease();
    auto cached = observer::observe(first); check(cached, data[0]);
    auto &owned = state(first);
    const auto rva = owned.reference.descriptor().ranges[0].rva;
    auto *byte = const_cast<volatile std::uint8_t *>(PYOBF_NATIVE_CODE_SPAN(owned.view, rva, 1));
    require(byte != nullptr, "actual measured function range"); const auto previous = *byte;
    DWORD protection = 0, ignored = 0; auto *address = const_cast<std::uint8_t *>(byte);
    require(VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &protection) != 0, "test code protection");
    *byte ^= 1;
    require(FlushInstructionCache(GetCurrentProcess(), address, 1) && VirtualProtect(address, 1, protection, &ignored), "test code RX restore");
    auto denied = observer::observe(second), retained = observer::observe(first);
    require(denied.data().error.code == observer::Status::digest_mismatch && retained.reused(), "per-use damage or declared once cache window");
    check(retained, data[0]);
    require(VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &protection) != 0, "test code undo protection");
    *byte = previous;
    require(FlushInstructionCache(GetCurrentProcess(), address, 1) && VirtualProtect(address, 1, protection, &ignored), "test code undo RX");
}
}
namespace pyobfuscator::native::platform {
bool hash_sha256_actual(const std::uint8_t *, std::size_t, std::uint8_t *) noexcept;
bool hash_sha256(const std::uint8_t *bytes, std::size_t size, std::uint8_t *output) noexcept {
    if (size >= sizeof(measurement::detail::domain) + 20 &&
            std::memcmp(bytes, measurement::detail::domain, sizeof(measurement::detail::domain)) == 0) {
        const auto *word = bytes + sizeof(measurement::detail::domain) + 12;
        const std::uint32_t owner = word[0] | std::uint32_t(word[1]) << 8 | std::uint32_t(word[2]) << 16 | std::uint32_t(word[3]) << 24;
        require(owner >= 7 && owner <= 9, "actual hash frame owner"); ++reads[owner];
        if (owner == failing_owner) return false;
    }
    return hash_sha256_actual(bytes, size, output);
}
}
int main(int argc, char **argv) {
    require(argc == 8 && generated::count == 3, "three metadata/package inputs and real subject DLL");
    const Input data[]{input(argv[1], argv[2]), input(argv[3], argv[4]), input(argv[5], argv[6])};
    const auto module = LoadLibraryA(argv[7]); require(module != nullptr, "load actual subject");
    const auto member = reinterpret_cast<native::platform::CodeAddress>(GetProcAddress(module, "measurement_target"));
    require(member != nullptr, "actual subject module anchor");
    policies(data, member); domains(data[0], member); failure(data, member); code_damage(data, member);
    require(FreeLibrary(module) != 0, "release actual subject");
    std::puts("three generated owners: actual canonical CNG reads, private encoded cache hits/refresh, cross-owner/domain/failure/damage refusals pass");
}
