#pragma once

#include "contribution/scope.hpp"
#include <vector>

pyobfuscator::native::BootstrapContextCreation make_scope_parent();
void check_scopes(pyobfuscator::native::BootstrapContextOwner &,
    const pyobfuscator::native::BootstrapContextLease &, const pyobfuscator::native::path_fold::Storage &,
    const std::vector<std::uint8_t> &, const pyobfuscator::native::measurement::reference::Identity &,
    std::uint32_t expected_word, unsigned broken = 0, bool measure = false);
