#include "../sdk_internal.hpp"

namespace pyobfuscator::native::detail {

DetectionState inspect_current_process() noexcept {
    // Linux and macOS backends are reserved but not implemented or verified.
    return DetectionState::unavailable;
}

}  // namespace pyobfuscator::native::detail
