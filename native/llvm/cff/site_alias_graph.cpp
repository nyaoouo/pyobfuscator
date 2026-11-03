#include "site_alias_graph.hpp"

#include "site_report.hpp"

#include <set>

namespace pyobfuscator::native::cff {

const SiteRecord *resolve_site_alias(const std::vector<SiteRecord> &sites,
                                      const std::map<std::string, unsigned> &positions,
                                      const SiteRecord &site) {
    const auto *current = &site;
    std::set<std::string> visited;
    while (current->status == "coalesced" || current->status == "relocated") {
        if (!visited.insert(current->id).second) return nullptr;
        const auto target = positions.find(current->replacement);
        if (target == positions.end() || target->second >= sites.size()) return nullptr;
        current = &sites[target->second];
        if (current->component != site.component) return nullptr;
    }
    return current;
}

std::string validate_site_alias(const std::vector<SiteRecord> &sites,
                                const std::map<std::string, unsigned> &positions,
                                const SiteRecord &site) {
    const auto *target = resolve_site_alias(sites, positions, site);
    if (target == nullptr) return site.component + " required site has a broken or cyclic alias: " + site.id;
    if (target->status != "applied" || target->applied_instances < target->instances)
        return site.component + " required alias target was not protected: " + site.id;
    return {};
}

}  // namespace pyobfuscator::native::cff
