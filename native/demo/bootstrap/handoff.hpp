#pragma once

#include "pyobfuscator_native/bootstrap_binding.hpp"

namespace pyobfuscator::native::demo {

inline constexpr std::uint32_t handoff_abi_version = 3;
struct PostHandoff;
enum class LifecycleOperation : std::uint32_t { prepare_support = 1, verify_support = 2, enter_payload = 3 };

struct LifecycleMessage {
    std::uint64_t generation;
    std::uint32_t routing_tag;
    LifecycleOperation operation;
};

struct PayloadHandoff {
    std::uint32_t abi_version;
    std::uint32_t routing_tag;
    std::uint64_t generation;
    const BootstrapContextLease *expected;
    BootstrapContextBindingCreation *publication;
    void (*record_stage)(std::uint32_t, void *);
    void *observer_context;
    const PostHandoff *post = nullptr;
};

// Borrowed views live through the synchronous entry. The outer owns the published token,
// allowing cleanup after inner exceptions while its loader reference is still retained.
using InnerEntry = int (*)(const PayloadHandoff *, int);

}  // namespace pyobfuscator::native::demo
