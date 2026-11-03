#include "contribution_sources.hpp"
#include "contribution_private.hpp"
#include "contribution_validate.hpp"

#include <algorithm>
#include <set>

#include "llvm/ADT/Twine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"

namespace pyobfuscator::native::cff {
std::uint32_t component_seed(std::uint32_t, llvm::StringRef, llvm::StringRef);
namespace {
[[noreturn]] void invalid(const llvm::Twine &reason) { llvm::report_fatal_error("native contribution sources: " + reason); }
const llvm::json::Object &object(const llvm::json::Value &value) {
    const auto *result = value.getAsObject(); if (result == nullptr) invalid("expected an object"); return *result;
}
void fields(const llvm::json::Object &value, const std::set<std::string> &allowed) {
    for (const auto &entry : value) if (!allowed.count(entry.first.str())) invalid(llvm::Twine("unknown field ") + entry.first.str());
}
std::string text(const llvm::json::Value *value) {
    const auto result = value == nullptr ? std::optional<llvm::StringRef>{} : value->getAsString();
    if (!result || !contribution_identifier(result->str())) invalid("expected a bounded identity"); return result->str();
}
std::uint32_t number(const llvm::json::Value *value) {
    const auto result = value == nullptr ? std::optional<std::int64_t>{} : value->getAsInteger();
    if (!result || *result < 1 || *result > UINT32_MAX) invalid("expected a nonzero uint32"); return *result;
}
ContributionSourceGroup rule(const llvm::json::Value &value, const ContributionPrivate &input,
    const std::vector<SourceSpec> &sources, const std::string &owner, const std::string &site) {
    const auto &record = object(value); fields(record, {"sources", "mixing_domain", "groups", "reference_site"});
    std::optional<std::uint32_t> reference_site;
    if (const auto *anchor = record.get("reference_site")) {
        if (input.schema != 2 || input.provider != "measured-scope-v1" || site == "default")
            invalid("reference_site requires an explicit schema2 measured site rule");
        reference_site = number(anchor);
    }
    SiteBindingSpec spec;
    spec.owner = owner; spec.site = site; spec.mixing_domain = text(record.get("mixing_domain")); spec.readiness = 4;
    const auto *selected = record.getArray("sources");
    if (selected == nullptr || selected->empty() || selected->size() > 256) invalid("invalid source subset");
    for (const auto &id : *selected) spec.sources.push_back(text(&id));
    std::string provider = input.provider;
    if (input.schema >= 3) {
        provider.clear();
        std::size_t prior = 0;
        bool first = true;
        for (const auto &id : spec.sources) {
            const auto source = std::find_if(sources.begin(), sources.end(), [&](const SourceSpec &entry) { return entry.id == id; });
            if (source == sources.end()) invalid("site uses an unknown source");
            if (input.schema == 3 && !provider.empty() && provider != source->provider) invalid("site mixes provider references");
            const auto position = static_cast<std::size_t>(source - sources.begin());
            if (input.schema == 4 && !first && position <= prior)
                invalid("source-mixed binding must follow catalog order");
            prior = position; first = false;
            provider = source->provider;
        }
    }
    if (const auto *groups = record.get("groups")) {
        const auto *list = groups->getAsArray(); if (list == nullptr || list->size() > 256) invalid("invalid required groups");
        for (const auto &entry : *list) {
            const auto &group = object(entry); fields(group, {"id", "minimum", "independent_evidence"});
            auto independent = group.getBoolean("independent_evidence");
            if (group.get("independent_evidence") != nullptr && !independent) invalid("independence must be boolean");
            if (independent.value_or(false) && (provider == "measured-scope-v1" || input.schema >= 3))
                invalid("mixed or measured grouped independence is not proven");
            spec.groups.push_back({text(group.get("id")), number(group.get("minimum")), independent.value_or(false)});
        }
    }
    auto resolved = resolve_contribution_contract(input.schema >= 3 ?
        std::vector<ProviderCapabilities>{owned_contribution_provider(), measured_contribution_provider()} :
        std::vector<ProviderCapabilities>{provider == "measured-scope-v1" ?
            measured_contribution_provider() : owned_contribution_provider()}, sources, {spec});
    if (!resolved.valid()) invalid(resolved.failure);
    if (input.schema == 4) {
        unsigned owned = 0, measured = 0;
        for (const auto &source : resolved.sites.front().sources) {
            owned += source.spec.provider == "owned-context-v1";
            measured += source.spec.provider == "measured-scope-v1";
        }
        if (owned == 0 || measured != 1)
            invalid("source-mixed site needs one measured and at least one owned reference");
    } else if (provider == "measured-scope-v1" && resolved.sites.front().sources.size() != 1)
        invalid("measured scope supports exactly one source per binding");
    const auto domain = component_seed(input.domain, owner, spec.mixing_domain);
    if (domain == 0) invalid("mixing domain maps to zero; choose another identity");
    return {std::move(resolved.sites.front()), domain, reference_site};
}
}
void read_contribution_sources(const llvm::json::Object &root, ContributionPrivate &input,
                               bool allow_bounded_schema4_sites) {
    const auto *catalog = root.getArray("sources");
    if (catalog == nullptr || catalog->empty() || catalog->size() > 256) invalid("invalid source catalog");
    std::vector<SourceSpec> sources;
    for (const auto &entry : *catalog) {
        const auto &record = object(entry);
        fields(record, {"id", "word_label", "group", "provider", "provider_version"});
        const auto provider = input.schema >= 3 ? text(record.get("provider")) : input.provider;
        if (input.schema >= 3 && ((provider != "owned-context-v1" && provider != "measured-scope-v1") ||
                number(record.get("provider_version")) != 1))
            invalid("mixed catalog has an unsupported provider/version");
        auto source = provider == "measured-scope-v1" ?
            measured_contribution_source(text(record.get("id")), number(record.get("word_label")), text(record.get("group"))) :
            owned_contribution_source(text(record.get("id")), number(record.get("word_label")), text(record.get("group")));
        if (input.schema < 3 && record.get("provider")) source.provider = text(record.get("provider"));
        if (input.schema < 3 && record.get("provider_version")) source.provider_version = number(record.get("provider_version"));
        if (input.provider == "measured-scope-v1" &&
                (source.provider != "measured-scope-v1" || source.provider_version != 1))
            invalid("measured scope catalog has an unsupported provider/version");
        sources.push_back(std::move(source));
    }
    const auto *owners = root.getObject("bindings");
    if (owners == nullptr || owners->empty() || owners->size() > 65536) invalid("invalid binding owners");
    std::map<std::uint32_t, std::pair<std::string, std::string>> domains;
    for (const auto &entry : *owners) {
        const auto owner = entry.first.str();
        if (!input.owners.count(owner)) invalid("binding owner has no private identity");
        const auto &record = object(entry.second); fields(record, {"default", "sites"});
        ContributionOwnerGroups rules;
        if (const auto *defaults = record.get("default")) rules.defaults = rule(*defaults, input, sources, owner, "default");
        if (const auto *points = record.get("sites")) {
            const auto &sites = object(*points); if (sites.size() > 65536) invalid("too many point rules");
            for (const auto &point : sites) {
                std::uint32_t label = 0;
                if (llvm::StringRef(point.first).getAsInteger(10, label) || label == 0 || std::to_string(label) != point.first.str()) invalid("point labels must be canonical nonzero uint32");
                rules.sites.emplace(label, rule(point.second, input, sources, owner, point.first.str()));
            }
        }
        if (!rules.defaults && rules.sites.empty()) invalid("owner has no binding rules");
        if (input.schema >= 3) {
            if (rules.defaults || rules.sites.empty()) invalid("mixed owner needs explicit site rules");
            if (input.schema == 4 && rules.sites.size() > (allow_bounded_schema4_sites ? 8u : 2u))
                invalid(allow_bounded_schema4_sites ?
                    "source-mixed owner supports at most eight explicit sites" :
                    "source-mixed owner supports at most two explicit sites");
            if (input.schema == 3) {
                std::set<std::string> providers;
                for (const auto &[point, group] : rules.sites) providers.insert(group.binding.sources.front().spec.provider);
                if (providers != std::set<std::string>{"owned-context-v1", "measured-scope-v1"})
                    invalid("mixed owner needs both source providers");
            }
        }
        const auto domain = [&](const ContributionSourceGroup &group) {
            const auto identity = std::make_pair(owner, group.binding.spec.mixing_domain);
            const auto [found, inserted] = domains.emplace(group.domain, identity);
            if (!inserted && found->second != identity) invalid("mixing domain identity collision");
        };
        if (rules.defaults) domain(*rules.defaults);
        for (const auto &[label, group] : rules.sites) domain(group);
        input.groups.emplace(owner, std::move(rules));
    }
}
}
