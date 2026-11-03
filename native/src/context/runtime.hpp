#pragma once

#include "pyobfuscator_native/bootstrap_context.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::detail {

struct BootstrapContextState {
    const BootstrapContextSpec spec;
    const std::uint64_t generation;
    const platform::CodeLease providers[2];
    platform::AtomicWord32 gate{0};
    std::uint32_t references = 1, active_calls = 0;
    bool closing = false;
};

// Private access for source-owned observation publication; not an installed callable API.
struct BootstrapContextAccess {
    static BootstrapContextState *state(const BootstrapContextLease &) noexcept;
};

void context_lock(platform::AtomicWord32 &) noexcept;
void context_unlock(platform::AtomicWord32 &) noexcept;
std::uint64_t next_context_generation() noexcept;
std::uint64_t advance_context_generation(std::uint64_t &) noexcept;
BootstrapContextStatus retain_context(BootstrapContextState *, bool allow_closed) noexcept;
void release_context(BootstrapContextState *) noexcept;
BootstrapContextStatus context_availability(BootstrapContextState *) noexcept;
BootstrapContextStatus admit_context_call(BootstrapContextState *) noexcept;
void complete_context_call(BootstrapContextState *) noexcept;

}  // namespace pyobfuscator::native::detail
