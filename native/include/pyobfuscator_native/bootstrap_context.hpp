#pragma once

#include <cstddef>
#include <cstdint>

namespace pyobfuscator::native {

inline constexpr std::uint32_t bootstrap_context_abi_version = 1;
inline constexpr std::size_t bootstrap_context_max_input = 65536;

enum class BootstrapContextStatus : std::uint32_t {
    ok, unavailable, invalid_specification, invalid_request, allocation_failed,
    code_unavailable, generation_exhausted, reference_limit, closed, busy, context_mismatch
};

struct BootstrapContextRequest {
    std::uint32_t operation_id;
    const void *input = nullptr;
    std::size_t input_size = 0;
};

struct BootstrapContextResult {
    BootstrapContextStatus status = BootstrapContextStatus::unavailable;
    std::uint64_t value = 0;
};

struct BootstrapContextSpec {
    std::uint32_t abi_version = bootstrap_context_abi_version;
    BootstrapContextResult (*dispatch)(const BootstrapContextRequest &, void *) noexcept = nullptr;
    void *user_data = nullptr;
    void (*destroy)(void *) noexcept = nullptr;
};

namespace detail { struct BootstrapContextState; struct BootstrapContextAccess; }
struct BootstrapContextCreation;
struct BootstrapContextBindingCreation;
class BootstrapContextOwner;
class BootstrapContextLease;
BootstrapContextCreation create_bootstrap_context(const BootstrapContextSpec &) noexcept;
BootstrapContextBindingCreation bind_bootstrap_context(const BootstrapContextLease &) noexcept;
BootstrapContextResult call_bound_bootstrap(const BootstrapContextLease &, const BootstrapContextRequest &) noexcept;

class BootstrapContextLease {
public:
    BootstrapContextLease() noexcept;
    BootstrapContextLease(const BootstrapContextLease &) noexcept;
    BootstrapContextLease(BootstrapContextLease &&) noexcept;
    BootstrapContextLease &operator=(const BootstrapContextLease &) noexcept;
    BootstrapContextLease &operator=(BootstrapContextLease &&) noexcept;
    ~BootstrapContextLease();
    void reset() noexcept;
    BootstrapContextStatus availability() const noexcept;
    std::uint64_t generation() const noexcept;
    BootstrapContextResult invoke(const BootstrapContextRequest &) const noexcept;

private:
    BootstrapContextLease(detail::BootstrapContextState *, BootstrapContextStatus) noexcept;
    detail::BootstrapContextState *context_ = nullptr;
    BootstrapContextStatus error_ = BootstrapContextStatus::unavailable;
    friend class BootstrapContextOwner;
    friend struct detail::BootstrapContextAccess;
    friend BootstrapContextBindingCreation bind_bootstrap_context(const BootstrapContextLease &) noexcept;
    friend BootstrapContextResult call_bound_bootstrap(const BootstrapContextLease &, const BootstrapContextRequest &) noexcept;
};

class BootstrapContextOwner {
public:
    BootstrapContextOwner() noexcept;
    BootstrapContextOwner(const BootstrapContextOwner &) = delete;
    BootstrapContextOwner &operator=(const BootstrapContextOwner &) = delete;
    BootstrapContextOwner(BootstrapContextOwner &&) noexcept;
    BootstrapContextOwner &operator=(BootstrapContextOwner &&) noexcept;
    ~BootstrapContextOwner();
    BootstrapContextLease lease() const noexcept;
    BootstrapContextStatus close() noexcept;
    bool quiescent() const noexcept;
    std::uint64_t generation() const noexcept;

private:
    explicit BootstrapContextOwner(detail::BootstrapContextState *) noexcept;
    detail::BootstrapContextState *context_ = nullptr;
    friend BootstrapContextCreation create_bootstrap_context(const BootstrapContextSpec &) noexcept;
};

struct BootstrapContextCreation {
    BootstrapContextStatus status;
    BootstrapContextOwner owner;
};

// Handles share a build/runtime ABI and backend. Availability/generation are lifecycle
// information, not authorization. Input is borrowed only for the synchronous callback.
// Creation failure leaves userdata with its caller; success transfers it to destroy.

}  // namespace pyobfuscator::native
