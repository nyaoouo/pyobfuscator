#pragma once

#include "bootstrap_context.hpp"

namespace pyobfuscator::native {
namespace detail { struct ContextPublication; }

class BootstrapContextBinding {
public:
    BootstrapContextBinding() noexcept;
    BootstrapContextBinding(const BootstrapContextBinding &) = delete;
    BootstrapContextBinding &operator=(const BootstrapContextBinding &) = delete;
    BootstrapContextBinding(BootstrapContextBinding &&) noexcept;
    BootstrapContextBinding &operator=(BootstrapContextBinding &&) noexcept;
    ~BootstrapContextBinding();
    void reset() noexcept;
    std::uint64_t generation() const noexcept;

private:
    BootstrapContextBinding(detail::ContextPublication *, std::uint64_t serial, std::uint64_t generation) noexcept;
    detail::ContextPublication *publication_ = nullptr;
    std::uint64_t serial_ = 0;
    std::uint64_t generation_ = 0;
    friend BootstrapContextBindingCreation bind_bootstrap_context(const BootstrapContextLease &) noexcept;
};

struct BootstrapContextBindingCreation {
    BootstrapContextStatus status;
    BootstrapContextBinding binding;
};

// One scoped publication per consuming runtime. Calls require the actual expected lease;
// numeric generations alone are not identities across source-built runtime instances.
// Unpublish prevents later acquisitions. Already captured calls may finish; owner.close()
// separately stops context admission. This endpoint never falls back to BootstrapApi v1.

}  // namespace pyobfuscator::native
