#include "failure_fixture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace capture_test {
Faults faults{};
Counters counters{};
const pyobfuscator::native::measurement::Data *closing_data = nullptr;
void (*on_hash)(std::uint8_t *) = nullptr;
void (*on_erased)(void *, std::size_t) = nullptr;
namespace {
struct Allocation { void *pointer = nullptr; std::size_t size = 0; } allocations[8];
std::uint8_t bytes[32]{};
bool nested = false;
}
void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "capture failure contract: %s\n", message); std::exit(1); }
}
bool cleared(const pyobfuscator::native::measurement::Data &data) {
    if (data.kind || data.subject || data.owner || data.frequency || data.read_started || data.read_completed) return false;
    for (auto byte : data.digest) if (byte) return false;
    return true;
}
void reset_fixture() {
    require(counters.views == 0 && counters.allocations == counters.releases, "previous resources still owned");
    faults = {}; counters = {}; closing_data = nullptr; on_hash = nullptr; on_erased = nullptr;
    for (unsigned index = 0; index != sizeof(bytes); ++index) bytes[index] = static_cast<std::uint8_t>(index);
}
pyobfuscator::native::measurement::Descriptor input() {
    static const pyobfuscator::native::measurement::Range range{0x1000, sizeof(bytes)};
    return {1, 11, 7, 0x3000, 0x180000000, &range, 1, nullptr, 0};
}
}

namespace pyobfuscator::native::platform {
using namespace capture_test;
using measurement::Status;

void *allocate(std::size_t size) noexcept {
    ++counters.allocation_attempts;
    if (faults.allocation || faults.allocation_failure_at == counters.allocation_attempts) return nullptr;
    for (auto &allocation : allocations) if (allocation.pointer == nullptr) {
        allocation.pointer = std::malloc(size + 16); allocation.size = size;
        require(allocation.pointer != nullptr, "fixture allocator");
        std::memset(allocation.pointer, 0xa5, size); ++counters.allocations;
        std::memset(static_cast<std::uint8_t *>(allocation.pointer) + size, 0x6d, 16);
        return allocation.pointer;
    }
    require(false, "fixture allocation budget"); return nullptr;
}
void erase(void *memory, std::size_t size) noexcept {
    auto *bytes = static_cast<volatile std::uint8_t *>(memory);
    for (std::size_t index = 0; index != size; ++index) bytes[index] = 0;
    if (on_erased != nullptr) on_erased(memory, size);
}
void release(void *memory) noexcept {
    for (auto &allocation : allocations) if (allocation.pointer == memory) {
        for (std::size_t index = 0; index != allocation.size; ++index)
            require(static_cast<std::uint8_t *>(memory)[index] == 0, "material not erased before release");
        for (unsigned index = 0; index != 16; ++index)
            require(static_cast<std::uint8_t *>(memory)[allocation.size + index] == 0x6d, "allocation end guard overwritten");
        std::free(memory); allocation = {}; ++counters.releases; return;
    }
    require(false, "unknown released allocation");
}
bool hash_sha256(const std::uint8_t *bytes, std::size_t size, std::uint8_t *digest) noexcept {
    ++counters.hashes;
    require(size > 32 && bytes[0] == 'p', "missing canonical material frame");
    std::memset(digest, 0xdd, 32);
    if (on_hash != nullptr) on_hash(digest);
    return !faults.hash;
}
measurement::Status open_code_view(CodeAddress, measurement::ModuleView &view) noexcept {
    view = {};
    if (faults.open) return Status::unavailable;
    view.lease.module = reinterpret_cast<void *>(1);
    view.base = bytes; view.loaded_base = view.header_base = 0x180000000;
    view.image_size = 0x3000; view.section_count = faults.partial_view ? 0 : 1;
    view.sections[0] = {0x1000, sizeof(bytes), sizeof(bytes), 0x60000020};
    ++counters.views; ++counters.opens;
    return Status::ok;
}
bool close_code_view(measurement::ModuleView &view) noexcept {
    if (closing_data != nullptr) require(cleared(*closing_data), "snapshot not retired before code release");
    if (view.lease.module != nullptr) {
        if (faults.close) return false;
        require(counters.views > 0, "double code release");
        --counters.views; ++counters.closes;
    }
    view = {}; return true;
}
const volatile std::uint8_t *code_span(const measurement::ModuleView &, std::uint32_t rva,
        std::uint32_t size) noexcept {
    ++counters.reads;
    if (faults.read || rva != 0x1000 || size != sizeof(bytes)) return nullptr;
    if (faults.reenter && !nested) {
        nested = true;
        auto descriptor = input(); ++descriptor.owner;
        auto other = measurement::capture(descriptor, nullptr);
        require(other.data().status == Status::ok && other.data().owner == 8, "reentrant capture");
        nested = false;
    }
    return bytes;
}
bool measurement_clock(measurement::ClockSample &sample) noexcept {
    const auto call = ++counters.clocks;
    if (faults.fixed_clock && call == faults.clock_advance_at) faults.clock_ticks = faults.clock_advance_to;
    sample = faults.fixed_clock ? measurement::ClockSample{faults.clock_ticks, faults.clock_frequency} :
        measurement::ClockSample{100u * call, 1000};
    if (faults.backward && call == 2) sample.ticks = 99;
    if (faults.frequency && call == 2) sample.frequency = 1001;
    return faults.clock_failure != call;
}
[[noreturn]] void protection_failure(std::uint32_t reason) noexcept {
    std::exit((reason == 0x702 || reason == 0x703) && faults.close ? 74 : 75);
}
}
