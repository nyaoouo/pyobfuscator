#pragma once

#include "bootstrap_context.hpp"

// A source marker, not a device validator. The CFF component replaces this call and
// keeps its lease reference local to the consuming invocation. Plain builds link
// pyobf_native_contribution_reference; protected IR must contain only this declaration.
extern "C" void pyobf_native_contribution_site_v1(
    const pyobfuscator::native::BootstrapContextLease &, std::uint32_t site) noexcept;
