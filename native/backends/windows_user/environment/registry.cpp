#include "../../../src/environment_internal.hpp"

namespace pyobfuscator::native::environment {

Result inspect_placeholder() noexcept;
#ifdef PYOBF_NATIVE_TEST_DETECTORS
Result inspect_clear() noexcept;
Result inspect_triggered() noexcept;
#endif

DetectorCatalog catalog() noexcept {
    static const DetectorDefinition detectors[]{
        {"placeholder", inspect_placeholder},
#ifdef PYOBF_NATIVE_TEST_DETECTORS
        {"clear_fixture", inspect_clear},
        {"triggered", inspect_triggered},
#endif
    };
    return {detectors, sizeof(detectors) / sizeof(detectors[0])};
}

}  // namespace pyobfuscator::native::environment
