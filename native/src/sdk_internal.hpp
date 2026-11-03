#pragma once

namespace pyobfuscator::native::detail {

enum class DetectionState {
    unavailable,
    clear,
    triggered,
};

// Platform probes stay behind the SDK report type and callback API.
DetectionState inspect_current_process() noexcept;

}  // namespace pyobfuscator::native::detail
