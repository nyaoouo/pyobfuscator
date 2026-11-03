#include "internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::measurement {

PYOBF_NATIVE_CFF_SDK Capture capture(const Descriptor &descriptor, platform::CodeAddress member) noexcept {
    const Descriptor input = descriptor;
    Capture result;
    std::size_t size = 0;
    auto status = detail::validate(input, nullptr, size);
    if (status != Status::ok) { result.fail(status); return result; }
    status = PYOBF_NATIVE_OPEN_CODE_VIEW(member, result.view_);
    if (status != Status::ok) { result.fail(status); return result; }
    status = detail::validate(input, &result.view_, size);
    if (status != Status::ok) { result.fail(status); return result; }
    auto *material = static_cast<std::uint8_t *>(PYOBF_NATIVE_ALLOCATE(size));
    if (material == nullptr) { result.fail(Status::allocation_failed); return result; }
    auto *body = detail::write_prefix(input, material);
    ClockSample begin{}, end{};
    if (!PYOBF_NATIVE_MEASUREMENT_CLOCK(begin) || begin.frequency == 0) status = Status::clock_failed;
    if (status == Status::ok) status = detail::read_material(input, result.view_, body);
    if (status == Status::ok && !PYOBF_NATIVE_SHA256(material, size, result.data_.digest)) status = Status::crypto_failed;
    if (status == Status::ok && (!PYOBF_NATIVE_MEASUREMENT_CLOCK(end) || end.frequency != begin.frequency ||
            end.ticks < begin.ticks)) status = Status::clock_failed;
    PYOBF_NATIVE_ERASE(material, size);
    PYOBF_NATIVE_RELEASE(material);
    if (status != Status::ok) { result.fail(status); return result; }
    result.data_.kind = input.kind; result.data_.subject = input.subject; result.data_.owner = input.owner;
    result.data_.read_started = begin.ticks; result.data_.read_completed = end.ticks; result.data_.frequency = begin.frequency;
    result.data_.status = Status::ok;
    return result;
}

}  // namespace pyobfuscator::native::measurement
