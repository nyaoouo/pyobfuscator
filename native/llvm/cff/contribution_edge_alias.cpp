#include "contribution_edges.hpp"
#include "contribution_private.hpp"
#include "dedup_alias.hpp"

#include <tuple>

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
namespace {
bool same_source(const ResolvedSource &a, const ResolvedSource &b) {
    for (const auto *source : {&a, &b})
        if (source->spec.source_class != SourceClass::authenticated_material ||
                source->spec.sharing != ObservationSharing::context_material ||
                source->spec.provider != "owned-context-v1" || source->independent_declared) return false;
    const auto fields = [](const ResolvedSource &s) {
        const auto &p = s.spec;
        return std::tie(s.owner, s.encoding_tag, s.use, s.independent_declared, s.unavailable_reason,
            p.id, p.source_class, p.bit_width, p.reference, p.earliest_readiness, p.reportable,
            p.provider, p.encoding, p.normalizer, p.group, p.age_unit, p.provider_version,
            p.word_label, p.policy, p.sharing, p.max_age, p.observation_only);
    };
    return fields(a) == fields(b);
}
bool same_group(const ContributionSourceGroup &a, const ContributionSourceGroup &b) {
    const auto fields = [](const ContributionSourceGroup &group) {
        const auto &s = group.binding.spec;
        // The point name intentionally differs between compatible original aliases.
        return std::tie(group.domain, s.owner, s.sources, s.mixing_domain, s.result_width,
            s.required_real_path, s.readiness, group.binding.bound_sources,
            group.binding.diversity_sources, group.binding.observation_sources);
    };
    if (fields(a) != fields(b) || a.binding.sources.size() != b.binding.sources.size() ||
            a.binding.spec.groups.size() != b.binding.spec.groups.size()) return false;
    for (unsigned i = 0; i != a.binding.sources.size(); ++i)
        if (!same_source(a.binding.sources[i], b.binding.sources[i])) return false;
    for (unsigned i = 0; i != a.binding.spec.groups.size(); ++i) {
        const auto &x = a.binding.spec.groups[i], &y = b.binding.spec.groups[i];
        if (std::tie(x.id, x.minimum, x.independent_evidence) != std::tie(y.id, y.minimum, y.independent_evidence)) return false;
    }
    return true;
}
}
bool ContributionEdgePlan::compatible_policy(std::uint32_t first, std::uint32_t second) const {
    if (!private_) return false;
    if (private_->schema == 1) return true;
    if (private_->schema != 2) return false;
    const auto owner = owner_->getName().str();
    const auto *a = private_->group(owner, first), *b = private_->group(owner, second);
    return a != nullptr && b != nullptr && same_group(*a, *b);
}
std::string ContributionEdgePlan::coalesce(const DedupAlias &alias) {
    auto *from = alias.source(), *to = alias.target();
    if (!failure_.empty()) return failure_;
    if (!deferred_ || materialized_ || from == nullptr || to == nullptr || from == to ||
            from->getParent() == nullptr || to->getParent() == nullptr ||
            from->getFunction() != owner_ || to->getFunction() != owner_ ||
            from->getParent()->getTerminator() != from || to->getParent()->getTerminator() != to ||
            from->getOpcode() != to->getOpcode() || from->getNumSuccessors() != to->getNumSuccessors() ||
            !llvm::isa<llvm::BranchInst, llvm::SwitchInst, llvm::ReturnInst, llvm::UnreachableInst>(from))
        return failure_ = "automatic deduplication alias has no live pre-materialization owner";
    // Semantic block equality does not retire a private completion owner. Its
    // non-RAUW identity is part of the registered normal-return source trace.
    for (const auto &invoke : invokes_) for (const auto &body : invoke.completions)
        if (body == from->getParent() || body == to->getParent())
            return "dedup cannot merge registered framed completion identities";
    // Policy incompatibility is an expected unsupported candidate. Check before
    // mutating routes so an optional normalizer can leave both originals intact.
    for (const auto &edge : edges_) if (edge.terminator == from)
        for (const auto &other : edges_) if (other.terminator == to && edge.successor == other.successor) {
            if (edge.target != other.target) return failure_ = "automatic deduplication alias changes its original destination";
            if (edge.selected != other.selected) return "automatic deduplication merges selected and unselected original edges";
            if (edge.selected && !compatible_policy(edge.label, other.label))
                return "automatic deduplication merges incompatible ordered source policies";
        }
    for (auto &edge : edges_) if (edge.terminator == from) {
        authorized_aliases_.insert(edge.identity);
        edge.terminator = to; edge.origin = to;
    }
    return {};
}
std::string ContributionEdgePlan::plan_aliases() {
    canonical_.resize(edges_.size());
    for (unsigned i = 0; i != edges_.size(); ++i) {
        canonical_[i] = i;
        const auto &edge = edges_[i];
        const auto *term = insertion_source(edge);
        const auto *target = llvm::dyn_cast_or_null<llvm::BasicBlock>(edge.target);
        if (term == nullptr || target == nullptr || term->getFunction() != owner_ || target->getParent() != owner_ ||
                !term->isTerminator() || edge.successor >= term->getNumSuccessors() || term->getSuccessor(edge.successor) != target)
            return "automatic original edge lost its live normalized destination";
        for (unsigned j = 0; j != i; ++j) {
            const auto &other = edges_[j];
            if (edge.terminator != other.terminator || edge.successor != other.successor || edge.target != other.target) continue;
            if (!deferred_ || (!authorized_aliases_.count(edge.identity) && !authorized_aliases_.count(other.identity)))
                return "automatic original edges merged without a compiler deduplication witness";
            if (edge.selected != other.selected)
                return "automatic deduplication merges selected and unselected original edges";
            if (edge.selected && !compatible_policy(edge.label, other.label))
                return "automatic deduplication merges incompatible ordered source policies";
            canonical_[i] = canonical_[j]; break;
        }
    }
    return {};
}
unsigned ContributionEdgePlan::physical_selected() const {
    if (canonical_.size() != edges_.size()) return selected_;
    unsigned count = 0;
    for (unsigned i = 0; i != edges_.size(); ++i) count += edges_[i].selected && canonical_[i] == i;
    return count;
}
std::string ContributionEdgePlan::verify_aliases() const {
    if (!materialized_ || canonical_.size() != edges_.size()) return "automatic original edges have no materialized alias plan";
    for (unsigned i = 0; i != edges_.size(); ++i) {
        const auto &edge = edges_[i];
        const auto canonical = canonical_[i];
        if (canonical >= edges_.size() || canonical_[canonical] != canonical ||
                edge.selected != edges_[canonical].selected || edge.terminator != edges_[canonical].terminator ||
                edge.successor != edges_[canonical].successor || edge.target != edges_[canonical].target ||
                edge.gateway != edges_[canonical].gateway || (canonical != i && (!deferred_ ||
                    (!authorized_aliases_.count(edge.identity) && !authorized_aliases_.count(edges_[canonical].identity)) ||
                    (edge.selected && !compatible_policy(edge.label, edges_[canonical].label)))))
            return "automatic original edge lost its private canonical source binding";
    }
    return {};
}
std::vector<std::uint32_t> ContributionEdgePlan::aliased_point_labels() const {
    std::vector<std::uint32_t> labels;
    if (!materialized_ || canonical_.size() != edges_.size()) return labels;
    for (unsigned i = 0; i != edges_.size(); ++i)
        if (edges_[i].selected && canonical_[i] != i) labels.push_back(edges_[i].label);
    return labels;
}
}
