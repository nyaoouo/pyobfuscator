#pragma once

#include "contribution/measured.hpp"
#include <vector>

void check_contributions(const pyobfuscator::native::path_fold::Storage &,
    const pyobfuscator::native::release::Record &, const pyobfuscator::native::measurement::observer::Snapshot &,
    const std::vector<std::uint8_t> &, bool correct);
void measured_contribution_faults();
