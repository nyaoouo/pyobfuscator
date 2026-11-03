#pragma once

#include <map>
#include <string>
#include <vector>

namespace pyobfuscator::native::cff {

struct SiteRecord;
const SiteRecord *resolve_site_alias(const std::vector<SiteRecord> &sites,
                                      const std::map<std::string, unsigned> &positions,
                                      const SiteRecord &site);
std::string validate_site_alias(const std::vector<SiteRecord> &sites,
                                const std::map<std::string, unsigned> &positions,
                                const SiteRecord &site);

}  // namespace pyobfuscator::native::cff
