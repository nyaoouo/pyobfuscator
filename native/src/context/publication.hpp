#pragma once

#include "runtime.hpp"

namespace pyobfuscator::native::detail {

struct ContextPublication {
    platform::AtomicWord32 gate{0};
    BootstrapContextState *context = nullptr;
    platform::CodeLease provider{};
    std::uint64_t serial = 0;
};

ContextPublication &context_publication() noexcept;
void release_publication(ContextPublication *, std::uint64_t serial) noexcept;

}  // namespace pyobfuscator::native::detail
