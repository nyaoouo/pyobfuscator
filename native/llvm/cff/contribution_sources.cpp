#include "contribution_sources.hpp"
#include "contribution_private.hpp"
#include "contribution/value.hpp"

#include <set>

#include "llvm/Support/ErrorHandling.h"

namespace pyobfuscator::native::cff {
ProviderCapabilities owned_contribution_provider() {
    ProviderCapabilities provider;
    provider.id = "owned-context-v1"; provider.version = 1;
    provider.classes = {SourceClass::authenticated_material}; provider.widths = {32};
    provider.references = {ReferenceSemantics::authenticated_context};
    provider.policies = {ObservationPolicy::per_use}; provider.encodings = {{"le-u32", 1}};
    provider.earliest_readiness = 4; provider.available = true;
    return provider;
}
ProviderCapabilities measured_contribution_provider() {
    auto provider = owned_contribution_provider();
    provider.id = "measured-scope-v1";
    provider.classes = {SourceClass::referenced_evidence};
    provider.references = {ReferenceSemantics::independent_build};
    // The Scope provider owns an invocation snapshot. The grouped adapter still
    // needs separate generated-owner evidence before admitting independent groups.
    provider.independent_observations = true;
    return provider;
}
SourceSpec owned_contribution_source(std::string id, std::uint32_t label, std::string group) {
    SourceSpec source;
    source.id = std::move(id); source.source_class = SourceClass::authenticated_material;
    source.bit_width = 32; source.reference = ReferenceSemantics::authenticated_context;
    source.earliest_readiness = 4; source.provider = "owned-context-v1"; source.provider_version = 1;
    source.encoding = "le-u32"; source.word_label = label;
    source.sharing = ObservationSharing::context_material; source.group = std::move(group);
    return source;
}
SourceSpec measured_contribution_source(std::string id, std::uint32_t label, std::string group) {
    auto source = owned_contribution_source(std::move(id), label, std::move(group));
    source.provider = "measured-scope-v1";
    source.source_class = SourceClass::referenced_evidence;
    source.reference = ReferenceSemantics::independent_build;
    source.sharing = ObservationSharing::owner_independent;
    return source;
}
const ContributionSourceGroup &contribution_source_group(const ContributionPrivate &input,
    const std::string &owner, std::uint32_t site) {
    if (const auto *group = input.group(owner, site)) return *group;
    llvm::report_fatal_error("contribution site has no configured source binding");
}
std::string validate_contribution_group_sites(const ContributionPrivate &input, const std::string &owner,
    llvm::ArrayRef<std::uint32_t> sites, unsigned maximum_queries, llvm::ArrayRef<std::uint32_t> original_aliases) {
    const auto found = input.groups.find(owner);
    if (found == input.groups.end()) return "contribution owner has no source binding rules";
    std::set<std::uint32_t> present(sites.begin(), sites.end());
    present.insert(original_aliases.begin(), original_aliases.end());
    if (input.schema >= 3) {
        if (!original_aliases.empty() || present.size() != sites.size() ||
                present.size() != found->second.sites.size())
            return "mixed source markers must exactly match explicit site rules";
        std::set<std::string> providers;
        for (auto label : sites) {
            const auto rule = found->second.sites.find(label);
            if (rule == found->second.sites.end()) return "mixed source marker has no explicit site rule";
            for (const auto &source : rule->second.binding.sources) providers.insert(source.spec.provider);
        }
        if (providers != std::set<std::string>{"owned-context-v1", "measured-scope-v1"})
            return "mixed source sites must retain both providers";
    }
    for (const auto &[label, rule] : found->second.sites)
        if (!present.count(label)) return "contribution configured point label was not retained";
    std::uint64_t queries = 0;
    for (auto label : sites) queries += contribution_source_group(input, owner, label).binding.sources.size();
    if (queries > maximum_queries) return "contribution queries exceed max_contribution_sites";
    return {};
}
std::uint32_t reference_contribution_group(const ContributionPrivate &input, const std::string &owner,
    std::uint32_t site, std::uint32_t current) {
    const auto &group = contribution_source_group(input, owner, site);
    auto state = contribution::initialize(group.domain, input.owners.at(owner), site);
    for (const auto &source : group.binding.sources) {
        state = contribution::source(state, source.spec.word_label, source.encoding_tag, 1);
        state = contribution::word(state, reference_contribution(input, owner, site, current,
            source.spec.word_label, source.spec.provider));
    }
    return contribution::finish(state);
}
}
