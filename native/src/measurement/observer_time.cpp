#include "observer_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement::observer::detail {
namespace {
struct Product { std::uint64_t high, low; };
PYOBF_NATIVE_CFF_SDK Product multiply(std::uint64_t a, std::uint64_t b) noexcept {
    const auto a0 = std::uint64_t(static_cast<std::uint32_t>(a)), a1 = a >> 32;
    const auto b0 = std::uint64_t(static_cast<std::uint32_t>(b)), b1 = b >> 32;
    const auto p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    const auto middle = (p00 >> 32) + static_cast<std::uint32_t>(p01) +
        std::uint64_t(static_cast<std::uint32_t>(p10));
    return {p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32),
        (middle << 32) | static_cast<std::uint32_t>(p00)};
}
}
PYOBF_NATIVE_CFF_SDK bool within(std::uint64_t ticks, std::uint64_t frequency, std::uint64_t ns) noexcept {
    if (frequency == 0) return false;
    const auto elapsed = multiply(ticks, 1000000000), limit = multiply(ns, frequency);
    return elapsed.high < limit.high || (elapsed.high == limit.high && elapsed.low <= limit.low);
}
PYOBF_NATIVE_CFF_SDK bool valid_policy(const Policy &policy) noexcept {
    if (policy.mode == Mode::once_per_instance) return policy.max_age_ns == 0;
    return (policy.mode == Mode::periodic_bounded_age || policy.mode == Mode::per_use) &&
        policy.max_age_ns != 0 && policy.max_scan_ns != 0;
}
PYOBF_NATIVE_CFF_SDK Status interval(const Data &data, const Policy &policy, const ClockSample &now) noexcept {
    if (data.frequency == 0 || now.frequency != data.frequency || data.read_completed < data.read_started ||
            now.ticks < data.read_completed) return Status::clock_failed;
    if (policy.max_scan_ns != 0 && !within(data.read_completed - data.read_started, data.frequency, policy.max_scan_ns))
        return Status::scan_expired;
    if (policy.mode != Mode::once_per_instance && !within(now.ticks - data.read_started, data.frequency, policy.max_age_ns))
        return Status::expired;
    return Status::ok;
}
}  // namespace pyobfuscator::native::measurement::observer::detail
