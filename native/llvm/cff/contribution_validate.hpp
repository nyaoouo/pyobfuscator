#pragma once

#include "contribution_contract.hpp"

namespace pyobfuscator::native::cff {

bool contribution_identifier(const std::string &) noexcept;
std::string validate_contribution_source(const SourceSpec &, const ContributionLimits &);
std::string contribution_capability_failure(const SourceSpec &, const ProviderCapabilities *, unsigned stage);

}  // namespace pyobfuscator::native::cff
