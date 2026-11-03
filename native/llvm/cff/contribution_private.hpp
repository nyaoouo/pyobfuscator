#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "contribution_sources.hpp"

#include "llvm/ADT/StringRef.h"

namespace pyobfuscator::native::cff {
struct ContributionPrivate {
    unsigned schema = 1;
    std::string provider = "owned-context-v1";
    std::string input_sha256;
    std::uint32_t routing, domain, source;
    std::array<std::uint32_t, 8> words;
    bool provider_split = false;
    std::array<std::uint32_t, 8> measured_words{};
    std::map<std::string, std::uint32_t> owners;
    std::map<std::string, ContributionOwnerGroups> groups;
    const ContributionSourceGroup *group(const std::string &owner, std::uint32_t site) const {
        const auto found = groups.find(owner);
        if (found == groups.end()) return nullptr;
        if (const auto exact = found->second.sites.find(site); exact != found->second.sites.end()) return &exact->second;
        return found->second.defaults ? &*found->second.defaults : nullptr;
    }
};
std::shared_ptr<const ContributionPrivate> read_contribution_private(llvm::StringRef,
    bool allow_bounded_schema4_sites = false);
std::uint32_t reference_contribution(const ContributionPrivate &, llvm::StringRef owner,
    std::uint32_t site, std::uint32_t current, std::uint32_t source = 0,
    llvm::StringRef provider = {});
}
