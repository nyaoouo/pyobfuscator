#include "../../src/sdk_internal.hpp"
#include "pyobfuscator_native/cff_marker.hpp"

namespace pyobfuscator::native::detail {

PYOBF_NATIVE_CFF_SDK DetectionState inspect_current_process() noexcept {
    // Public SDK inspection remains unavailable until a real detector is implemented.
    return DetectionState::unavailable;
}

}  // namespace pyobfuscator::native::detail
