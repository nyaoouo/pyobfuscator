#include "scope.hpp"

extern "C" void pyobf_native_mixed_contribution_site_v1(
    const pyobfuscator::native::BootstrapContextLease &,
    pyobfuscator::native::contribution::scoped::Scope &, std::uint32_t) noexcept {}
