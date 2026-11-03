#include "contribution_validate.hpp"

namespace pyobfuscator::native::cff {

bool contribution_identifier(const std::string &value) noexcept {
    if (value.empty() || value.size() > 256) return false;
    for (const unsigned char byte : value) if (byte < 32 || byte == 127) return false;
    return true;
}

std::string validate_contribution_source(const SourceSpec &source, const ContributionLimits &limits) {
    if (!contribution_identifier(source.id) || !contribution_identifier(source.provider) ||
            !contribution_identifier(source.encoding) || source.provider_version == 0 || source.word_label == 0)
        return "source needs bounded identities, provider version and a nonzero word label";
    if (source.bit_width == 0 || source.bit_width % 32 != 0 || source.bit_width > limits.max_source_bits)
        return "source width is outside the admitted uint32-word budget";
    if (source.earliest_readiness > 5) return "source readiness is outside L0-L5";
    switch (source.source_class) {
    case SourceClass::referenced_evidence:
        if (source.reference != ReferenceSemantics::independent_build) return "evidence needs an independent build reference";
        break;
    case SourceClass::authenticated_material:
        if (source.reference != ReferenceSemantics::authenticated_context) return "material needs its authenticated-context reference";
        break;
    case SourceClass::dynamic_value:
        if (source.reference != ReferenceSemantics::symbolic_relation || !contribution_identifier(source.normalizer))
            return "dynamic values need a named symbolic normalizer, never an assumed constant";
        break;
    default: return "unknown source class";
    }
    if (source.source_class != SourceClass::dynamic_value && !source.normalizer.empty())
        return "symbolic normalizer is only admitted for dynamic diversity";
    switch (source.policy) {
    case ObservationPolicy::once_per_instance:
    case ObservationPolicy::per_use:
        if (source.max_age != 0 || !source.age_unit.empty()) return "nonperiodic source cannot silently ignore an age policy";
        break;
    case ObservationPolicy::periodic_bounded_age:
        if (source.max_age == 0 || !contribution_identifier(source.age_unit)) return "periodic source needs an age bound and unit";
        break;
    default: return "unknown observation policy";
    }
    if (source.sharing != ObservationSharing::owner_independent && source.sharing != ObservationSharing::context_material)
        return "unknown observation sharing model";
    if (!source.group.empty() && !contribution_identifier(source.group)) return "invalid source group identity";
    return {};
}

std::string contribution_capability_failure(const SourceSpec &source, const ProviderCapabilities *provider, unsigned stage) {
    if (provider == nullptr) return "provider/version is not registered";
    if (!provider->available) return "provider implementation is unavailable";
    if (!provider->classes.count(source.source_class)) return "provider does not admit this source class";
    if (!provider->widths.count(source.bit_width)) return "provider does not admit this source width";
    if (!provider->references.count(source.reference)) return "provider does not admit this reference semantics";
    if (!provider->encodings.count(source.encoding)) return "provider does not admit this encoding";
    if (!provider->policies.count(source.policy)) return "provider does not admit this observation policy";
    if (source.earliest_readiness < provider->earliest_readiness || stage < source.earliest_readiness)
        return "source/provider is not ready at this site";
    if (source.sharing == ObservationSharing::owner_independent && !provider->independent_observations)
        return "provider has no independent owner observation contract";
    if (source.sharing == ObservationSharing::context_material && source.source_class != SourceClass::authenticated_material)
        return "context material sharing cannot stand in for independent evidence";
    if (source.policy == ObservationPolicy::periodic_bounded_age &&
            (!provider->monotonic_clock || source.age_unit != provider->age_unit))
        return "periodic provider has no matching monotonic-clock unit";
    if (source.source_class == SourceClass::dynamic_value && !provider->symbolic_normalizers.count(source.normalizer))
        return "symbolic normalizer has no registered provider adapter";
    return {};
}

}  // namespace pyobfuscator::native::cff
