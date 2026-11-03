#pragma once

#include "reference.hpp"
#include "capture.hpp"
#include "pyobfuscator_native/bootstrap_context.hpp"
#include "pyobfuscator_native/system_ops.hpp"

namespace pyobfuscator::native::contribution::scoped { class Scope; }

namespace pyobfuscator::native::measurement::observer {

enum class Mode : std::uint32_t { once_per_instance, periodic_bounded_age, per_use };
struct Policy {
    Mode mode = Mode::once_per_instance;
    std::uint64_t max_age_ns = 0, max_scan_ns = 0;
};
enum class Status : std::uint32_t {
    ok, unavailable, invalid_specification, invalid_request, closed, allocation_failed,
    context_failed, reference_failed, capture_failed, clock_failed, expired, scan_expired,
    digest_mismatch, revoked, generation_exhausted, invalid_snapshot
};
struct Error {
    Status code = Status::unavailable;
    BootstrapContextStatus context = BootstrapContextStatus::unavailable;
    reference::Status reference = reference::Status::unavailable;
    measurement::Status capture = measurement::Status::unavailable;
};
struct Observation {
    reference::Identity identity{};
    Policy policy{};
    std::uint64_t instance = 0, subject_instance = 0, epoch = 0, sequence = 0;
    Data measured{};
    Error error{};
};
struct Validation {
    Error error{};
    std::uint64_t consumed_at = 0, frequency = 0;
};
struct ReaderBinding {
    std::uint32_t version = 1, owner = 0;
    std::uint64_t key = 0;
    Capture (*capture)(const Descriptor &, platform::CodeAddress, std::uint64_t) noexcept = nullptr;
    bool (*cache_codec)(std::uint64_t, Observation &) noexcept = nullptr;
};
struct Spec {
    Policy policy{};
    platform::CodeAddress member = nullptr;
    std::uint64_t subject_instance = 0;
    const ReaderBinding *reader = nullptr;
};
struct Creation { Error error; BootstrapContextOwner owner; };

class Snapshot {
public:
    Snapshot() noexcept = default;
    Snapshot(const Snapshot &) = delete;
    Snapshot &operator=(const Snapshot &) = delete;
    Snapshot(Snapshot &&) noexcept;
    Snapshot &operator=(Snapshot &&) noexcept;
    ~Snapshot();
    void reset() noexcept;
    const Observation &data() const noexcept;
    const std::uint8_t *reference_digest() const noexcept;
    bool reused() const noexcept;
    Validation check() const noexcept;

private:
    friend Snapshot observe(const BootstrapContextLease &, bool) noexcept;
    friend class contribution::scoped::Scope;
    BootstrapContextLease owner_;
    Observation data_{};
    std::uint8_t expected_[32]{};
    bool reused_ = false;
};

// Private same-build C++ seam. Inputs are immutable through creation. Stage authority is
// established by the integrating loader; the new owned context pins this actual target.
Creation create(const std::uint8_t *, std::size_t, const reference::Identity &,
    const std::uint32_t (&)[8], const Spec &) noexcept;
Snapshot observe(const BootstrapContextLease &, bool force_refresh = false) noexcept;
Error invalidate(const BootstrapContextLease &) noexcept;

}  // namespace pyobfuscator::native::measurement::observer
