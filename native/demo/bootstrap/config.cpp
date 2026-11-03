#include "flow.hpp"
#include "demo_config.hpp"

namespace pyobfuscator::native::demo {

PYOBF_NATIVE_CFF_BOOTSTRAP RuntimeConfig read_build_config() noexcept {
    return {PYOBF_DEMO_ENV_OPERATION_ID, PYOBF_DEMO_ALLOW_UNAVAILABLE != 0,
            PYOBF_DEMO_ENV_DETECTORS};
}

}  // namespace pyobfuscator::native::demo
