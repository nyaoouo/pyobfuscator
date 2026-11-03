#pragma once

#include <cstdint>

namespace pyobfuscator::native {

inline constexpr std::uint32_t bootstrap_abi_version = 1;

struct BootstrapApi {
    std::uint32_t abi_version;
    // A callback cannot unwind across the SDK's noexcept dispatch boundary.
    int (*call)(std::uint32_t operation_id, void *context) noexcept;
    void (*record_stage)(std::uint32_t stage, void *context);
    void *context;
};

// Copies the descriptor at bind time. Userdata and callback-code lifetime remain borrowed:
// keep both alive through every in-flight call, including calls captured before unbind.
// Unbind stops later captures and does not wait on a reentrant callback.
bool bind_bootstrap_api(const BootstrapApi *api) noexcept;
void unbind_bootstrap_api() noexcept;
int call_bootstrap(std::uint32_t operation_id) noexcept;

}  // namespace pyobfuscator::native
