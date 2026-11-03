#include "pyobfuscator_native/system_ops.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace pyobfuscator::native::platform {

static_assert(AtomicWord32::is_always_lock_free, "archive publication requires lock-free 32-bit atomics");

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

void spin_pause() noexcept { YieldProcessor(); }

}  // namespace pyobfuscator::native::platform
