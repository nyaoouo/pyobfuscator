#pragma once

#include "measured.hpp"
#include "archive/runtime.hpp"

namespace pyobfuscator::native::contribution::scoped {

inline constexpr std::uint32_t admission_version = 2;
inline constexpr std::size_t material_bytes = 168;
struct Admission {
    std::uint32_t version, size, routing, domain, function, source;
    std::uint64_t generation;
    std::uint32_t observation_owner, reserved;
    std::uint64_t observation_instance;
    std::uintptr_t observation_context;
};
static_assert(sizeof(Admission) == 48 + sizeof(std::uintptr_t) && offsetof(Admission, generation) == 24);
struct Spec {
    std::uint32_t routing, domain, function, source;
    measurement::reference::Identity reference;
};
struct Result {
    BootstrapContextStatus status = BootstrapContextStatus::unavailable;
    std::uint32_t word = 0;
    measured::Result material{};
    measurement::observer::Error observation{};
    archive::Status authentication = archive::Status::invalid_record;
};

// One function-invocation operation, owned outside parent userdata. Its per-use snapshot
// remains immutable and pinned through every consuming transition and normal/EH exit.
// Instances are thread-confined; recursive queries on the same instance reject as busy.
class Scope {
public:
    Scope(const BootstrapContextLease &, const Spec &, const path_fold::Storage &, const std::uint8_t *, std::size_t,
        measurement::observer::Snapshot &&) noexcept;
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
    ~Scope();
    Result query(std::uint32_t routing, const Site &) noexcept;
    BootstrapContextStatus binding_status(const BootstrapContextLease &) const noexcept;
    const measurement::observer::Observation &observation() const noexcept;

private:
    BootstrapContextLease parent_;
    Spec spec_{};
    path_fold::Storage fold_{};
    std::uint8_t material_[material_bytes]{};
    measurement::observer::Snapshot snapshot_;
    BootstrapContextStatus initial_ = BootstrapContextStatus::invalid_request;
    platform::AtomicWord32 busy_{0};
};
namespace detail {
Result authenticated_material(const path_fold::Storage &, const std::uint8_t *, std::size_t,
    const measurement::observer::Snapshot &, std::uint32_t, const Site &) noexcept;
}
}

// Private generated-call ABI; it cannot be substituted for the legacy lease query.
extern "C" std::uint32_t pyobf_native_measured_contribution_word_v1(
    pyobfuscator::native::contribution::scoped::Scope &, std::uint32_t routing,
    std::uint32_t domain, std::uint32_t function, std::uint32_t site,
    std::uint32_t source, std::uint32_t current) noexcept;
extern "C" void pyobf_native_measured_contribution_site_v1(
    pyobfuscator::native::contribution::scoped::Scope &, std::uint32_t site) noexcept;
// A versioned source marker for one CFF site that consumes both reference kinds.
// The compiler owns the provider-to-argument mapping; plain builds use its no-op definition.
extern "C" void pyobf_native_mixed_contribution_site_v1(
    const pyobfuscator::native::BootstrapContextLease &,
    pyobfuscator::native::contribution::scoped::Scope &, std::uint32_t site) noexcept;
// Schema4 generated-call ABI. Each word is bound to both references before acquisition.
extern "C" std::uint32_t pyobf_native_mixed_owned_contribution_word_v1(
    const pyobfuscator::native::BootstrapContextLease &, std::uint32_t routing,
    std::uint32_t domain, std::uint32_t function, std::uint32_t site,
    std::uint32_t source, std::uint32_t current,
    pyobfuscator::native::contribution::scoped::Scope &) noexcept;
extern "C" std::uint32_t pyobf_native_mixed_measured_contribution_word_v1(
    pyobfuscator::native::contribution::scoped::Scope &, std::uint32_t routing,
    std::uint32_t domain, std::uint32_t function, std::uint32_t site,
    std::uint32_t source, std::uint32_t current,
    const pyobfuscator::native::BootstrapContextLease &) noexcept;
