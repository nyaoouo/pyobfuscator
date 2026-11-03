#include "contribution_validate.hpp"

#include <utility>

namespace pyobfuscator::native::cff {

ContributionResolution resolve_contribution_contract(const std::vector<ProviderCapabilities> &catalog,
    const std::vector<SourceSpec> &sources, const std::vector<SiteBindingSpec> &sites, const ContributionLimits &limits) {
    auto fail = [](std::string reason) { return ContributionResolution{{}, std::move(reason)}; };
    if (sources.size() > limits.max_sources || sites.size() > limits.max_sites || limits.max_source_bits % 32 != 0)
        return fail("contribution plan exceeds its declared descriptor budget");
    std::map<std::pair<std::string, unsigned>, const ProviderCapabilities *> providers;
    std::map<std::string, std::uint32_t> encoding_ids;
    std::map<std::uint32_t, std::string> encoding_tags;
    for (const auto &provider : catalog) {
        if (!contribution_identifier(provider.id) || provider.version == 0 || provider.earliest_readiness > 5 ||
                !providers.emplace(std::make_pair(provider.id, provider.version), &provider).second)
            return fail("invalid or duplicate provider identity/version");
        for (const auto &[name, tag] : provider.encodings) {
            if (!contribution_identifier(name) || tag == 0 ||
                    (encoding_ids.count(name) && encoding_ids.at(name) != tag) ||
                    (encoding_tags.count(tag) && encoding_tags.at(tag) != name))
                return fail("encoding identity/tag aliases are not admitted");
            encoding_ids[name] = tag; encoding_tags[tag] = name;
        }
    }
    std::map<std::string, const SourceSpec *> definitions;
    std::set<std::uint32_t> labels;
    for (const auto &source : sources) {
        if (const auto reason = validate_contribution_source(source, limits); !reason.empty())
            return fail(source.id + ": " + reason);
        if (!definitions.emplace(source.id, &source).second || !labels.insert(source.word_label).second)
            return fail("duplicate source identity or aliased word label");
    }
    ContributionResolution result;
    std::set<std::pair<std::string, std::string>> identities;
    for (const auto &site : sites) {
        if (!contribution_identifier(site.site) || !contribution_identifier(site.owner) ||
                !contribution_identifier(site.mixing_domain) || site.result_width != 32 || site.readiness > 5 ||
                !identities.emplace(site.owner, site.site).second)
            return fail("invalid or duplicate owner/site/mixing identity or result width");
        ResolvedSiteBinding resolved{site, {}};
        std::set<std::string> selected;
        for (const auto &id : site.sources) {
            const auto found = definitions.find(id);
            if (found == definitions.end() || !selected.insert(id).second)
                return fail(site.site + ": unknown or duplicate source assignment");
            const auto &source = *found->second;
            const auto entry = providers.find({source.provider, source.provider_version});
            const auto *provider = entry == providers.end() ? nullptr : entry->second;
            if (source.reportable && provider != nullptr && !provider->reportable)
                return fail(id + ": source cannot upgrade provider reportability");
            auto reason = contribution_capability_failure(source, provider, site.readiness);
            if (!reason.empty() && !source.observation_only) return fail(id + ": " + reason);
            const auto use = source.observation_only ? ContributionUse::observation_only :
                source.source_class == SourceClass::dynamic_value ? ContributionUse::diversity : ContributionUse::required_binding;
            ResolvedSource item{source, site.owner, 0, use, false, reason};
            if (reason.empty()) {
                item.encoding_tag = provider->encodings.at(source.encoding);
                item.independent_declared = source.sharing == ObservationSharing::owner_independent &&
                    provider->independent_observations && source.source_class == SourceClass::referenced_evidence;
            } else item.spec.reportable = false;
            switch (item.use) {
            case ContributionUse::required_binding: ++resolved.bound_sources; break;
            case ContributionUse::diversity: ++resolved.diversity_sources; break;
            case ContributionUse::observation_only: ++resolved.observation_sources; break;
            }
            resolved.sources.push_back(std::move(item));
        }
        std::set<std::string> groups;
        for (const auto &group : site.groups) {
            if (!contribution_identifier(group.id) || group.minimum == 0 || !groups.insert(group.id).second)
                return fail(site.site + ": invalid or duplicate required group");
            unsigned count = 0;
            for (const auto &source : resolved.sources)
                if (source.use == ContributionUse::required_binding &&
                        source.spec.group == group.id && (!group.independent_evidence || source.independent_declared)) ++count;
            if (count < group.minimum) return fail(site.site + ": required source group is not covered");
        }
        if (site.required_real_path && resolved.bound_sources == 0)
            return fail(site.site + ": required real binding cannot be satisfied by diversity or observation only");
        result.sites.push_back(std::move(resolved));
    }
    return result;
}

}  // namespace pyobfuscator::native::cff
