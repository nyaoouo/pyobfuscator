#include "runtime.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

#include <limits>

namespace pyobfuscator::native::detail {
namespace {
platform::AtomicWord32 generation_gate{0};
std::uint64_t generation_counter = 0;
}

PYOBF_NATIVE_CFF_SDK void context_lock(platform::AtomicWord32 &gate) noexcept {
    while (PYOBF_NATIVE_ATOMIC_CAS32(&gate, 0, 1) != 0) PYOBF_NATIVE_SPIN_PAUSE();
}

PYOBF_NATIVE_CFF_SDK void context_unlock(platform::AtomicWord32 &gate) noexcept {
    PYOBF_NATIVE_ATOMIC_STORE32(&gate, 0);
}

PYOBF_NATIVE_CFF_SDK std::uint64_t next_context_generation() noexcept {
    context_lock(generation_gate);
    const auto result = advance_context_generation(generation_counter);
    context_unlock(generation_gate);
    return result;
}

PYOBF_NATIVE_CFF_SDK std::uint64_t advance_context_generation(std::uint64_t &counter) noexcept {
    return counter == std::numeric_limits<std::uint64_t>::max() ? 0 : ++counter;
}

}  // namespace pyobfuscator::native::detail
