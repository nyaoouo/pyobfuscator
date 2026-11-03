#include "contribution_contract.hpp"

#include <cstdio>
#include <cstdlib>
#include <functional>

namespace {
using namespace pyobfuscator::native::cff;
struct Input {
    std::vector<ProviderCapabilities> providers;
    std::vector<SourceSpec> sources;
    std::vector<SiteBindingSpec> sites;
    ContributionLimits limits;
};
void require(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "contribution contract failed: %s\n", message); std::exit(1); }
}
Input fixture() {
    ProviderCapabilities provider;
    provider.id = "fixture-only"; provider.version = 1;
    provider.classes = {SourceClass::referenced_evidence, SourceClass::authenticated_material, SourceClass::dynamic_value};
    provider.widths = {32, 256};
    provider.references = {ReferenceSemantics::independent_build, ReferenceSemantics::authenticated_context, ReferenceSemantics::symbolic_relation};
    provider.policies = {ObservationPolicy::per_use, ObservationPolicy::once_per_instance, ObservationPolicy::periodic_bounded_age};
    provider.encodings = {{"words-le-v1", 0x1001}};
    provider.symbolic_normalizers = {"fixture-symbolic-u32"};
    provider.available = provider.independent_observations = provider.monotonic_clock = true;
    provider.earliest_readiness = 2; provider.age_unit = "monotonic-ns-v1";
    SourceSpec hash;
    hash.id = "hash"; hash.provider = provider.id; hash.provider_version = 1;
    hash.bit_width = 256; hash.earliest_readiness = 2; hash.word_label = 11;
    hash.encoding = "words-le-v1"; hash.group = "integrity";
    auto context = hash;
    context.id = "context"; context.word_label = 12; context.bit_width = 32;
    context.source_class = SourceClass::authenticated_material; context.reference = ReferenceSemantics::authenticated_context;
    context.sharing = ObservationSharing::context_material; context.group = "material";
    auto dynamic = hash;
    dynamic.id = "dynamic"; dynamic.word_label = 13; dynamic.bit_width = 32;
    dynamic.source_class = SourceClass::dynamic_value; dynamic.reference = ReferenceSemantics::symbolic_relation;
    dynamic.normalizer = "fixture-symbolic-u32"; dynamic.group = "diversity";
    auto diagnostic = hash;
    diagnostic.id = "diagnostic"; diagnostic.word_label = 14;
    diagnostic.provider = "absent-diagnostic-provider"; diagnostic.observation_only = true; diagnostic.reportable = true;
    SiteBindingSpec a{"edge.0", "owner-A", {"hash", "context", "diagnostic"}, "domain-v1"};
    a.readiness = 4; a.groups = {{"integrity", 1, true}, {"material", 1, false}};
    auto b = a; b.owner = "owner-B"; b.sources = {"hash"}; b.groups = {{"integrity", 1, true}};
    auto c = a; c.owner = "owner-C"; c.sources = {"context", "dynamic"}; c.groups = {{"material", 1, false}};
    return {{provider}, {hash, context, dynamic, diagnostic}, {a, b, c}, {}};
}
ContributionResolution resolve(const Input &input) {
    return resolve_contribution_contract(input.providers, input.sources, input.sites, input.limits);
}
unsigned checked = 0;
void reject(const char *name, const std::function<void(Input &)> &mutate) {
    auto input = fixture(); mutate(input);
    const auto result = resolve(input);
    if (result.valid() || !result.sites.empty()) {
        std::fprintf(stderr, "accepted or partially published invalid contribution contract: %s\n", name); std::exit(1);
    }
    ++checked;
}
}

int main() {
    const auto result = resolve(fixture());
    require(result.valid() && result.sites.size() == 3, "different ordered site subsets resolve");
    require(result.sites[0].bound_sources == 2 && result.sites[0].observation_sources == 1 &&
            result.sites[2].bound_sources == 1 && result.sites[2].diversity_sources == 1, "use classes remain distinct");
    const auto &unavailable = result.sites[0].sources[2];
    require(unavailable.use == ContributionUse::observation_only && !unavailable.unavailable_reason.empty() &&
            !unavailable.spec.reportable && unavailable.encoding_tag == 0,
            "observation-only unavailable source supplies no clean value or required coverage");
    require(result.sites[0].sources[0].owner != result.sites[1].sources[0].owner &&
            result.sites[0].sources[0].independent_declared && !result.sites[0].sources[1].independent_declared,
            "owner identity and declared evidence independence survive resolution");
    require(result.sites[2].sources[1].use == ContributionUse::diversity, "dynamic value cannot masquerade as required evidence");
    auto periodic = fixture();
    periodic.sources[0].policy = ObservationPolicy::periodic_bounded_age;
    periodic.sources[0].max_age = 1000; periodic.sources[0].age_unit = "monotonic-ns-v1";
    require(resolve(periodic).valid(), "matching bounded periodic capability");
    auto diversity = fixture(); diversity.sites = {diversity.sites[2]};
    diversity.sites[0].sources = {"dynamic"}; diversity.sites[0].groups.clear(); diversity.sites[0].required_real_path = false;
    require(resolve(diversity).valid() && resolve(diversity).sites[0].bound_sources == 0, "explicit diversity-only is not required binding");
    require(resolve_contribution_contract({}, {}, {}).valid(), "empty unrequested plan remains empty");

    reject("unknown provider", [](auto &i) { i.sources[0].provider = "missing"; });
    reject("wrong provider version", [](auto &i) { ++i.sources[0].provider_version; });
    reject("unavailable required implementation", [](auto &i) { i.providers[0].available = false; });
    reject("empty source", [](auto &i) { i.sources[0].id.clear(); });
    reject("embedded control", [](auto &i) { i.sources[0].id = std::string("a\0b", 3); });
    reject("duplicate source", [](auto &i) { i.sources.push_back(i.sources[0]); });
    reject("source label alias", [](auto &i) { i.sources[1].word_label = i.sources[0].word_label; });
    reject("unassigned source label", [](auto &i) { i.sources[0].word_label = 0; });
    reject("provider version zero", [](auto &i) { i.providers[0].version = 0; });
    reject("duplicate provider", [](auto &i) { i.providers.push_back(i.providers[0]); });
    reject("encoding tag alias", [](auto &i) { i.providers[0].encodings["alias"] = 0x1001; });
    reject("encoding name conflict", [](auto &i) { auto p = i.providers[0]; ++p.version; p.encodings["words-le-v1"] = 7; i.providers.push_back(p); });
    reject("encoding tag zero", [](auto &i) { i.providers[0].encodings["words-le-v1"] = 0; });
    reject("zero width", [](auto &i) { i.sources[0].bit_width = 0; });
    reject("partial word width", [](auto &i) { i.sources[0].bit_width = 33; });
    reject("word budget", [](auto &i) { i.sources[0].bit_width = 512; });
    reject("unsupported width", [](auto &i) { i.providers[0].widths.erase(256); });
    reject("unknown class", [](auto &i) { i.sources[0].source_class = static_cast<SourceClass>(77); });
    reject("unsupported class", [](auto &i) { i.providers[0].classes.erase(SourceClass::referenced_evidence); });
    reject("evidence self-reference", [](auto &i) { i.sources[0].reference = ReferenceSemantics::symbolic_relation; });
    reject("material build constant", [](auto &i) { i.sources[1].reference = ReferenceSemantics::independent_build; });
    reject("dynamic assumed constant", [](auto &i) { i.sources[2].reference = ReferenceSemantics::independent_build; });
    reject("missing symbolic adapter", [](auto &i) { i.sources[2].normalizer.clear(); });
    reject("unimplemented symbolic adapter", [](auto &i) { i.providers[0].symbolic_normalizers.clear(); });
    reject("unexpected symbolic adapter", [](auto &i) { i.sources[0].normalizer = "fixture-symbolic-u32"; });
    reject("unsupported reference", [](auto &i) { i.providers[0].references.erase(ReferenceSemantics::independent_build); });
    reject("unknown source policy", [](auto &i) { i.sources[0].policy = static_cast<ObservationPolicy>(77); });
    reject("unsupported policy", [](auto &i) { i.providers[0].policies.erase(ObservationPolicy::per_use); });
    reject("unknown encoding", [](auto &i) { i.sources[0].encoding = "unknown"; });
    reject("readiness range", [](auto &i) { i.sources[0].earliest_readiness = 6; });
    reject("provider readiness", [](auto &i) { i.sources[0].earliest_readiness = 1; });
    reject("early site", [](auto &i) { i.sites[0].readiness = 1; });
    reject("false independence", [](auto &i) { i.providers[0].independent_observations = false; });
    reject("shared evidence", [](auto &i) { i.sources[0].sharing = ObservationSharing::context_material; });
    reject("unknown sharing", [](auto &i) { i.sources[0].sharing = static_cast<ObservationSharing>(77); });
    reject("reportability upgrade", [](auto &i) { i.sources[1].reportable = true; });
    reject("ignored age", [](auto &i) { i.sources[0].max_age = 1; });
    reject("periodic age absent", [](auto &i) { i.sources[0].policy = ObservationPolicy::periodic_bounded_age; });
    reject("clock absent", [](auto &i) { i.sources[0].policy = ObservationPolicy::periodic_bounded_age; i.sources[0].max_age = 1; i.sources[0].age_unit = "monotonic-ns-v1"; i.providers[0].monotonic_clock = false; });
    reject("clock unit mismatch", [](auto &i) { i.sources[0].policy = ObservationPolicy::periodic_bounded_age; i.sources[0].max_age = 1; i.sources[0].age_unit = "milliseconds"; });
    reject("duplicate assignment", [](auto &i) { i.sites[0].sources.push_back("hash"); });
    reject("unknown assignment", [](auto &i) { i.sites[0].sources.push_back("missing"); });
    reject("duplicate owner/site", [](auto &i) { i.sites.push_back(i.sites[0]); });
    reject("empty owner", [](auto &i) { i.sites[0].owner.clear(); });
    reject("empty mixing domain", [](auto &i) { i.sites[0].mixing_domain.clear(); });
    reject("unsupported result width", [](auto &i) { i.sites[0].result_width = 64; });
    reject("empty group", [](auto &i) { i.sites[0].groups[0].id.clear(); });
    reject("zero group minimum", [](auto &i) { i.sites[0].groups[0].minimum = 0; });
    reject("duplicate group", [](auto &i) { i.sites[0].groups.push_back(i.sites[0].groups[0]); });
    reject("observation counted as binding", [](auto &i) { i.sources[0].observation_only = true; });
    reject("material counted as independent evidence", [](auto &i) { i.sites[0].groups[1].independent_evidence = true; });
    reject("diversity counted as binding", [](auto &i) { i.sites[2].sources = {"dynamic"}; i.sites[2].groups.clear(); });
    reject("diversity counted in group", [](auto &i) { i.sources[2].group = "material"; i.sites[2].groups[0].minimum = 2; });
    reject("source budget", [](auto &i) { i.limits.max_sources = 1; });
    reject("site budget", [](auto &i) { i.limits.max_sites = 1; });
    reject("partial budget word", [](auto &i) { i.limits.max_source_bits = 33; });
    reject("late invalid site clears partial plan", [](auto &i) { i.sites.back().readiness = 6; });
    std::printf("contribution contract: ordered owner subsets, explicit unavailable observation, periodic units and %u refusals; capability declarations are not runtime proof\n", checked);
}
