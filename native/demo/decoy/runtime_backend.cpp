#include "runtime_fixture.hpp"
#include "context/publication.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <thread>
#include <unordered_map>
#include <vector>

namespace decoy_fixture {
Counters counters;
pyobfuscator::native::demo::RuntimeContext *real_context = nullptr;
pyobfuscator::native::path_fold::Storage *decoy_fold = nullptr;
pyobfuscator::native::BootstrapContextLease retained;
namespace {
struct Allocation { std::size_t size; bool sensitive, erased = false; };
std::unordered_map<void *, Allocation> allocations;
std::vector<std::uint8_t> real_image_bytes, decoy_image_bytes;
int real_image, decoy_image;
}

void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "decoy observation failed: %s\n", message); std::exit(1); }
}
void initialize_images(const char *real, const char *decoy) {
    auto read = [](const char *path) {
        std::ifstream stream(path, std::ios::binary);
        require(stream.good(), "exact child image opened");
        return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream), {});
    };
    real_image_bytes = read(real); decoy_image_bytes = read(decoy);
    require(!real_image_bytes.empty() && !decoy_image_bytes.empty() && real_image_bytes != decoy_image_bytes,
            "independent nonempty image identities");
}
void reset() {
    require(allocations.empty() && counters.pins == counters.unpins, "previous invocation fully retired");
    retained.reset();
    counters = {};
    real_context = nullptr; decoy_fold = nullptr;
    hash_material = nullptr; hash_material_size = 0;
    active_key = nullptr; active_key_erased = false;
}
void verify_clean() {
    retained.reset();
    require(allocations.empty() && counters.allocations == counters.releases, "every owned allocation released once");
    require(counters.pins == counters.unpins && real_context == nullptr && decoy_fold == nullptr,
            "owned state and code references retired");
    require(hash_material == nullptr && active_key == nullptr && counters.keys == counters.erased_keys,
            "serialization and reconstructed keys erased before expiry");
    require(pyobfuscator::native::detail::context_publication().context == nullptr, "real publication withdrawn");
    require(counters.real_loads == counters.real_unloads && counters.decoy_loads == counters.decoy_unloads,
            "each successful image retired exactly once");
}
void observe(std::uint32_t stage, void *opaque) {
    if (stage >= 2)
        require(active_key == nullptr && counters.keys == counters.erased_keys && hash_material == nullptr,
                "key and serialization retired before host callback");
    if (stage >= 7) {
        require(real_context != nullptr && PYOBF_NATIVE_ATOMIC_LOAD32(&real_context->phase) ==
                static_cast<std::uint32_t>(pyobfuscator::native::demo::LifecyclePhase::retired),
                "real admission closed before decoy notifications");
        if (retained.generation() != 0)
            require(retained.availability() == pyobfuscator::native::BootstrapContextStatus::closed,
                    "retained real lease cannot admit decoy work");
    }
    if (opaque != nullptr) {
        auto &trace = *static_cast<Trace *>(opaque);
        require(trace.count < 16, "bounded role trace");
        trace.stages[trace.count++] = stage;
    }
    if (stage == counters.throw_stage) throw ObserverFailure{stage};
}
int enter_real(const pyobfuscator::native::demo::PayloadHandoff *handoff, int value) {
    ++counters.real_entries;
    require(handoff != nullptr && handoff->expected != nullptr, "real handoff remains typed");
    return value * 3 + 1;
}
int enter_decoy(const pyobfuscator::native::demo::DecoyHandoff *handoff, int value) {
    using namespace pyobfuscator::native::demo;
    ++counters.decoy_entries;
    require(handoff != nullptr && handoff->abi_version == decoy_handoff_version &&
            handoff->size == sizeof(DecoyHandoff) && handoff->role == decoy_role, "distinct decoy POD handoff");
    require(handoff->failure == -2 || handoff->failure == -4 || handoff->failure == -7 || handoff->failure == -8,
            "only named failures enter decoy");
    return value > 0 ? 101 : value < 0 ? 202 : 303;
}
}  // namespace decoy_fixture

namespace pyobfuscator::native::platform {
void *allocate(std::size_t size) noexcept {
    using namespace decoy_fixture;
    const unsigned attempt = ++counters.attempts;
    const bool first_decoy = !counters.decoy_started && real_context != nullptr &&
        PYOBF_NATIVE_ATOMIC_LOAD32(&real_context->phase) == static_cast<std::uint32_t>(demo::LifecyclePhase::retired) &&
        size == sizeof(path_fold::Storage);
    if (first_decoy) {
        counters.decoy_started = true;
        std::memcpy(counters.failed_real_fold, real_context->fold.words, sizeof(counters.failed_real_fold));
    }
    if (attempt == counters.fail_allocation) return nullptr;
    void *memory = std::malloc(size);
    if (memory != nullptr) {
        std::memset(memory, 0xcc, size);
        allocations.emplace(memory, Allocation{size, first_decoy || attempt != counters.public_allocation});
        ++counters.allocations;
        if (attempt == 1 && size == sizeof(demo::RuntimeContext)) real_context = static_cast<demo::RuntimeContext *>(memory);
        if (first_decoy) decoy_fold = static_cast<path_fold::Storage *>(memory);
    }
    return memory;
}
void erase(void *memory, std::size_t size) noexcept {
    if (memory == nullptr) return;
    using namespace decoy_fixture;
    if (memory == real_context && counters.decoy_started)
        require(std::memcmp(real_context->fold.words, counters.failed_real_fold, sizeof(counters.failed_real_fold)) == 0,
                "decoy never repairs or advances failed real fold");
    auto found = allocations.find(memory);
    if (found == allocations.end()) {
        require(memory == hash_material && size == hash_material_size, "erase exact observed stack serialization");
        hash_material = nullptr; hash_material_size = 0;
        ++counters.material_erasures;
    } else {
        require(found->second.size == size, "erase exact owned allocation span");
        found->second.erased = true;
    }
    auto *bytes = static_cast<volatile unsigned char *>(memory);
    while (size != 0) bytes[--size] = 0;
    if (memory == active_key && !active_key_erased) { active_key_erased = true; ++counters.erased_keys; }
}
void release(void *memory) noexcept {
    if (memory == nullptr) return;
    using namespace decoy_fixture;
    const auto found = allocations.find(memory);
    require(found != allocations.end(), "no duplicate or foreign release");
    require(found->second.erased || !found->second.sensitive, "state/fold/plain/key/CNG objects erased before free");
    if (found->second.erased) {
        auto *bytes = static_cast<const std::uint8_t *>(memory);
        for (std::size_t index = 0; index != found->second.size; ++index)
            require(bytes[index] == 0, "erasure persists through release");
    }
    if (memory == active_key) { require(active_key_erased, "key erased before free"); active_key = nullptr; }
    if (memory == real_context) real_context = nullptr;
    if (memory == decoy_fold) decoy_fold = nullptr;
    allocations.erase(found); ++counters.releases;
    std::free(memory);
}
CodeLease retain_code(CodeAddress address) noexcept {
    if (address == nullptr) return {};
    ++decoy_fixture::counters.pins;
    return {reinterpret_cast<void *>(std::uintptr_t{1})};
}
bool release_code(CodeLease lease) noexcept { if (lease.module != nullptr) ++decoy_fixture::counters.unpins; return true; }
std::uint32_t atomic_load32(const AtomicWord32 *word) noexcept { return word->load(); }
std::uint32_t atomic_compare_exchange32(AtomicWord32 *word, std::uint32_t expected, std::uint32_t desired) noexcept {
    word->compare_exchange_strong(expected, desired); return expected;
}
void atomic_store32(AtomicWord32 *word, std::uint32_t value) noexcept { word->store(value); }
void spin_pause() noexcept { std::this_thread::yield(); }
[[noreturn]] void protection_failure(std::uint32_t) noexcept { std::abort(); }
void *load_payload(const std::uint8_t *bytes, std::size_t size) noexcept {
    using namespace decoy_fixture;
    const bool real = size == real_image_bytes.size() && std::memcmp(bytes, real_image_bytes.data(), size) == 0;
    const bool decoy = size == decoy_image_bytes.size() && std::memcmp(bytes, decoy_image_bytes.data(), size) == 0;
    if (!real && !decoy) { ++counters.invalid_load_attempts; return nullptr; }
    require(real != decoy, "loader input has a unique exact child identity");
    if (real) ++counters.real_load_attempts; else ++counters.decoy_load_attempts;
    if (!counters.load_succeeds) return nullptr;
    if (real) { ++counters.real_loads; return &real_image; }
    ++counters.decoy_loads; return &decoy_image;
}
void *resolve_payload_entry(void *image) noexcept {
    using namespace decoy_fixture;
    if (!counters.resolve_succeeds) return nullptr;
    require(image == &real_image || image == &decoy_image, "resolve exact classified image");
    return image == &real_image ? reinterpret_cast<void *>(&enter_real) : reinterpret_cast<void *>(&enter_decoy);
}
void unload_payload(void *image) noexcept {
    using namespace decoy_fixture;
    require(detail::context_publication().context == nullptr, "withdraw real publication before unload");
    if (image == &real_image) ++counters.real_unloads;
    else { require(image == &decoy_image, "unload exact decoy image"); ++counters.decoy_unloads; }
}
}  // namespace pyobfuscator::native::platform

namespace pyobfuscator::native::environment {
Report inspect(const char *) noexcept {
    Report report;
    report.valid = true;
    report.overall = decoy_fixture::counters.denied ? Result::triggered : Result::clear;
    return report;
}
}  // namespace pyobfuscator::native::environment
