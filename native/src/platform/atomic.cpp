#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::platform {

static_assert(AtomicWord32::is_always_lock_free, "SDK publication requires lock-free 32-bit atomics");

std::uint32_t atomic_load32(const AtomicWord32 *value) noexcept {
    return value->load(std::memory_order_acquire);
}

std::uint32_t atomic_compare_exchange32(AtomicWord32 *value, std::uint32_t expected,
                                       std::uint32_t desired) noexcept {
    value->compare_exchange_strong(expected, desired, std::memory_order_acq_rel, std::memory_order_acquire);
    return expected;
}

void atomic_store32(AtomicWord32 *value, std::uint32_t desired) noexcept {
    value->store(desired, std::memory_order_release);
}

// The SDK-only stub has no OS scheduler dependency; another backend may provide a hint.
void spin_pause() noexcept {}

}  // namespace pyobfuscator::native::platform
