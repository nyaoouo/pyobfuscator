#include "pyobfuscator_native/bootstrap_context.hpp"

extern "C" __declspec(dllexport) void pyobf_test_foreign_context(
        const pyobfuscator::native::BootstrapContextSpec *spec,
        pyobfuscator::native::BootstrapContextCreation *output) noexcept {
    *output = pyobfuscator::native::create_bootstrap_context(*spec);
}
