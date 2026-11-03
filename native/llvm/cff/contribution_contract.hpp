#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pyobfuscator::native::cff {

// Compiler-facing contracts only. Providers, clocks and lifecycle storage belong to runtime
// backends; registering a source must never create a shared observation/cache authority.
enum class SourceClass { referenced_evidence, authenticated_material, dynamic_value };
enum class ReferenceSemantics { independent_build, authenticated_context, symbolic_relation };
enum class ObservationPolicy { once_per_instance, periodic_bounded_age, per_use };
enum class ObservationSharing { owner_independent, context_material };
enum class ContributionUse { required_binding, diversity, observation_only };

struct SourceSpec {
    std::string id;
    SourceClass source_class = SourceClass::referenced_evidence;
    unsigned bit_width = 0;
    ReferenceSemantics reference = ReferenceSemantics::independent_build;
    unsigned earliest_readiness = 0;
    bool reportable = false;
    std::string provider, encoding, normalizer, group, age_unit;
    unsigned provider_version = 0;
    std::uint32_t word_label = 0;
    ObservationPolicy policy = ObservationPolicy::per_use;
    ObservationSharing sharing = ObservationSharing::owner_independent;
    std::uint64_t max_age = 0;
    bool observation_only = false;
};

struct ProviderCapabilities {
    std::string id;
    unsigned version = 0;
    std::set<SourceClass> classes;
    std::set<unsigned> widths;
    std::set<ReferenceSemantics> references;
    std::set<ObservationPolicy> policies;
    std::map<std::string, std::uint32_t> encodings;
    std::set<std::string> symbolic_normalizers;
    unsigned earliest_readiness = 0;
    bool available = false, reportable = false;
    bool independent_observations = false, monotonic_clock = false;
    std::string age_unit;
};

struct OwnerObservation {
    std::string owner;
    std::string source;
    std::uint64_t lifecycle_epoch;
    std::uint64_t observation_sequence;
    std::uint64_t read_started;
    std::uint64_t read_completed;
    ObservationPolicy policy;
    bool available;
};

struct SiteBindingSpec {
    std::string site;
    std::string owner;
    std::vector<std::string> sources;
    std::string mixing_domain;
    unsigned result_width = 32;
    bool required_real_path = true;
    unsigned readiness = 0;
    struct Group {
        std::string id;
        unsigned minimum = 1;
        bool independent_evidence = false;
    };
    std::vector<Group> groups;
};

struct ResolvedSource {
    SourceSpec spec;
    std::string owner;
    std::uint32_t encoding_tag = 0;
    ContributionUse use = ContributionUse::observation_only;
    bool independent_declared = false;
    std::string unavailable_reason;
};

struct ResolvedSiteBinding {
    SiteBindingSpec spec;
    std::vector<ResolvedSource> sources;
    unsigned bound_sources = 0, diversity_sources = 0, observation_sources = 0;
};

struct ContributionResolution {
    std::vector<ResolvedSiteBinding> sites;
    std::string failure;
    bool valid() const noexcept { return failure.empty(); }
};

struct ContributionLimits {
    unsigned max_sources = 256, max_sites = 65536, max_source_bits = 256;
};

ContributionResolution resolve_contribution_contract(
    const std::vector<ProviderCapabilities> &, const std::vector<SourceSpec> &,
    const std::vector<SiteBindingSpec> &, const ContributionLimits & = {});

}  // namespace pyobfuscator::native::cff
