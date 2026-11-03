#pragma once

#include "contribution_contract.hpp"

#include <map>
#include <optional>

#include "llvm/ADT/ArrayRef.h"
namespace llvm::json { class Object; }
namespace pyobfuscator::native::cff {
struct ContributionPrivate;
struct ContributionSourceGroup {
    ResolvedSiteBinding binding;
    std::uint32_t domain;
    std::optional<std::uint32_t> reference_site;
};
struct ContributionOwnerGroups {
    std::optional<ContributionSourceGroup> defaults;
    std::map<std::uint32_t, ContributionSourceGroup> sites;
};
ProviderCapabilities owned_contribution_provider();
ProviderCapabilities measured_contribution_provider();
SourceSpec owned_contribution_source(std::string id, std::uint32_t label, std::string group);
SourceSpec measured_contribution_source(std::string id, std::uint32_t label, std::string group);
void read_contribution_sources(const llvm::json::Object &, ContributionPrivate &, bool allow_bounded_schema4_sites);
const ContributionSourceGroup &contribution_source_group(const ContributionPrivate &, const std::string &owner, std::uint32_t site);
std::string validate_contribution_group_sites(const ContributionPrivate &, const std::string &owner,
    llvm::ArrayRef<std::uint32_t> sites, unsigned maximum_queries, llvm::ArrayRef<std::uint32_t> original_aliases = {});
std::uint32_t reference_contribution_group(const ContributionPrivate &, const std::string &owner,
    std::uint32_t site, std::uint32_t state);
}
