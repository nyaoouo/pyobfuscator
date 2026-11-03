#include "session_fixture.hpp"
#include "context/publication.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <unordered_map>

extern "C" int pyobf_native_inner_entry(const pyobfuscator::native::demo::PayloadHandoff *, int);

namespace session_fixture {
Counters counters;
pyobfuscator::native::BootstrapContextLease retained;
pyobfuscator::native::demo::RuntimeContext *fold_context = nullptr;
namespace {
struct Allocation { std::size_t size; bool sensitive; bool erased = false; };
std::unordered_map<void *, Allocation> allocations;
int image;
}

void reset() {
    require(allocations.empty(), "previous test left allocations");
    require(counters.pins == counters.unpins, "previous test left code references");
    retained.reset();
    counters = {};
    fold_context = nullptr;
    hash_material = nullptr;
    hash_material_size = 0;
    active_key = nullptr;
    active_key_erased = false;
}

void verify_clean() {
    retained.reset();
    require(allocations.empty() && counters.allocations == counters.releases, "session state/buffers released once");
    require(counters.pins == counters.unpins, "session code references balanced");
    require(hash_material == nullptr, "serialized key material was erased before stack expiry");
    require(active_key == nullptr && counters.keys == counters.erased_keys, "reconstructed keys erased and retired");
    require(pyobfuscator::native::detail::context_publication().context == nullptr, "session publication withdrawn");
}

int enter(const pyobfuscator::native::demo::PayloadHandoff *handoff, int value) {
    ++counters.entries;
    retained = *handoff->expected;
    return pyobf_native_inner_entry(handoff, value);
}
}  // namespace session_fixture

namespace pyobfuscator::native::platform {

void *allocate(std::size_t size) noexcept {
    using namespace session_fixture;
    if (++counters.allocation_attempts == counters.fail_allocation) return nullptr;
    void *memory = std::malloc(size);
    if (memory != nullptr) {
        std::memset(memory, 0xcc, size);
        allocations.emplace(memory, Allocation{size, counters.allocation_attempts != 3});
        ++counters.allocations;
    }
    return memory;
}
void erase(void *memory, std::size_t size) noexcept {
    if (memory == nullptr) return;
    using namespace session_fixture;
    if (memory == hash_material && size == hash_material_size) {
        auto *bytes = static_cast<volatile unsigned char *>(memory);
        while (size != 0) bytes[--size] = 0;
        hash_material = nullptr;
        hash_material_size = 0;
        ++counters.material_erasures;
        return;
    }
    auto found = allocations.find(memory);
    require(found != allocations.end() && found->second.size == size, "erase exact owned allocation");
    auto *bytes = static_cast<volatile unsigned char *>(memory);
    while (size != 0) bytes[--size] = 0;
    found->second.erased = true;
    if (memory == active_key && !active_key_erased) {
        require(found->second.size == 32, "exact reconstructed key span");
        active_key_erased = true;
        ++counters.erased_keys;
    }
    ++counters.erasures;
}
void release(void *memory) noexcept {
    if (memory == nullptr) return;
    using namespace session_fixture;
    const auto found = allocations.find(memory);
    require(found != allocations.end(), "no duplicate or foreign allocation release");
    if (found->second.erased) {
        const auto *bytes = static_cast<const unsigned char *>(memory);
        for (std::size_t i = 0; i != found->second.size; ++i) require(bytes[i] == 0, "erase persists until free");
    }
    // RuntimeContext/control block and plaintext must be erased; sealed bytes are public ciphertext.
    require(found->second.erased || !found->second.sensitive, "owned state/plaintext erased before free");
    if (memory == active_key) {
        require(active_key_erased, "reconstructed key erased before release");
        active_key = nullptr;
    }
    allocations.erase(found);
    ++counters.releases;
    std::free(memory);
}
CodeLease retain_code(CodeAddress address) noexcept {
    if (address == nullptr) return {};
    ++session_fixture::counters.pins;
    return {reinterpret_cast<void *>(std::uintptr_t{1})};
}
bool release_code(CodeLease lease) noexcept {
    if (lease.module != nullptr) ++session_fixture::counters.unpins;
    return true;
}
std::uint32_t atomic_load32(const AtomicWord32 *word) noexcept { return word->load(); }
std::uint32_t atomic_compare_exchange32(AtomicWord32 *word, std::uint32_t expected, std::uint32_t desired) noexcept {
    using namespace session_fixture;
    using pyobfuscator::native::demo::LifecyclePhase;
    if (fold_context != nullptr && word == &fold_context->phase) {
        const int stage = expected == static_cast<std::uint32_t>(LifecyclePhase::environment_accepting) &&
                desired == static_cast<std::uint32_t>(LifecyclePhase::environment_accepted) ? 0 :
            expected == static_cast<std::uint32_t>(LifecyclePhase::support_preparing) &&
                desired == static_cast<std::uint32_t>(LifecyclePhase::support_prepared) ? 1 : -1;
        if (stage >= 0) {
            std::memcpy(counters.phase_fold[stage], fold_context->fold.words, sizeof(counters.phase_fold[stage]));
            if (counters.retire_on_phase == desired) {
                word->store(static_cast<std::uint32_t>(LifecyclePhase::retired));
                counters.retire_on_phase = 0;
            }
        }
    }
    word->compare_exchange_strong(expected, desired);
    return expected;
}
void atomic_store32(AtomicWord32 *word, std::uint32_t value) noexcept { word->store(value); }
void spin_pause() noexcept { std::this_thread::yield(); }
[[noreturn]] void protection_failure(std::uint32_t) noexcept { std::abort(); }

void *load_payload(const std::uint8_t *, std::size_t) noexcept {
    ++session_fixture::counters.loads;
    return session_fixture::counters.load_succeeds ? &session_fixture::image : nullptr;
}
void *resolve_payload_entry(void *) noexcept {
    return session_fixture::counters.resolve_succeeds ? reinterpret_cast<void *>(&session_fixture::enter) : nullptr;
}
void unload_payload(void *memory) noexcept {
    using namespace session_fixture;
    require(memory == &image, "unload exact loaded image");
    require(detail::context_publication().context == nullptr, "withdraw publication before unloading code");
    if (retained.generation() != 0) require(retained.availability() == BootstrapContextStatus::closed,
                                         "stop context admission before unloading code");
    ++counters.unloads;
}
}  // namespace pyobfuscator::native::platform

namespace pyobfuscator::native::environment {
Report inspect(const char *) noexcept {
    Report report;
    report.valid = session_fixture::counters.environment_valid;
    report.overall = session_fixture::counters.environment;
    return report;
}
}  // namespace pyobfuscator::native::environment
