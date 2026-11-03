#include "contribution_edges.hpp"
#include "state_layout.hpp"
#include "contribution_gate.hpp"
#include "contribution_private.hpp"
#include "site_provenance.hpp"
#include "region_scope.hpp"

#include <algorithm>
#include <set>

#include "llvm/IR/Function.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"

namespace pyobfuscator::native::cff {
ContributionEdgePlan::ContributionEdgePlan(llvm::Function &function, const ResolvedRecipe &recipe)
    : owner_(&function), options_(recipe.contribution_options), region_scope_(recipe.region_scope) {
    const auto dedup = recipe.components.find("deduplicate-blocks");
    deferred_ = dedup != recipe.components.end() && dedup->second != Requirement::off;
    private_ = recipe.contribution;
    source_mixed_ = private_ && private_->schema == 4 &&
        options_.selection == ContributionSelection::original_edges;
    bounded_mixed_ = source_mixed_ && options_.minimum_edges == 3 &&
        options_.maximum_edges == 8;
    maximum_queries_ = recipe.max_contribution_sites;
    const bool exact_two = options_.minimum_edges == 2 && options_.maximum_edges == 2;
    if (source_mixed_ && (recipe.strategy != "relative-tree" || recipe.coverage != "whole" ||
            region_scope_ || deferred_ || options_.minimum_percent != 100 ||
            (!exact_two && !bounded_mixed_))) {
        failure_ = "source-mixed automatic edges need strict whole bounded recipe"; return;
    }
    if (deferred_ && ((recipe.coverage != "whole" && recipe.coverage != "hybrid-eh") || region_scope_)) {
        failure_ = "automatic deduplication requires a function normalization scope"; return;
    }
    if (recipe.region_scope) {
        region_entry_ = recipe.region_scope->entry_name(); region_exit_ = recipe.region_scope->exit_name();
    }
    lease_ = canonical_contribution_source(function, recipe, anchors_, multiple_scopes_, failure_);
    if (!failure_.empty()) return;
    if (source_mixed_) measured_ = function.getArg(1);
    if (private_ && private_->schema == 2) {
        const auto owner_rules = private_->groups.find(function.getName().str());
        if (owner_rules != private_->groups.end()) {
            for (const auto &anchor : anchors_) {
                const auto exact = owner_rules->second.sites.find(anchor.site);
                if (exact != owner_rules->second.sites.end() && exact->second.reference_site) {
                    failure_ = "explicit Scope anchor cannot have reference_site"; return;
                }
            }
            if (!multiple_scopes_) for (const auto &[site, rule] : owner_rules->second.sites)
                if (rule.reference_site) {
                    failure_ = "reference_site requires multiple distinct Scope references"; return;
                }
        }
    }
    if (multiple_scopes_ && (private_ == nullptr || private_->schema != 2 ||
            private_->provider != "measured-scope-v1")) {
        failure_ = "automatic contributions require one canonical argument/global lease reference held through return"; return;
    }
    if (multiple_scopes_ && (recipe.coverage != "whole" || deferred_ || region_scope_)) {
        failure_ = "multiple Scope original edges need whole schema2 measured without deduplication or region"; return;
    }
    if (multiple_scopes_) for (const auto *component : {"split-blocks", "common-exit"}) {
        const auto enabled = recipe.components.find(component);
        if (enabled != recipe.components.end() && enabled->second != Requirement::off) {
            failure_ = "multiple Scope original edges do not support split-blocks or common-exit"; return;
        }
    }
    std::set<std::uint32_t> labels;
    const auto points = discover_contribution_sites(function, recipe);
    explicit_points_ = points.size();
    for (const auto &point : points)
        labels.insert(static_cast<std::uint32_t>(llvm::cast<llvm::ConstantInt>(llvm::cast<llvm::CallInst>(point.instruction)->getArgOperand(1))->getZExtValue()));
    unsigned sequence = 0;
    for (auto &body : function) {
        if (recipe.region_scope && !recipe.region_scope->contains(body)) continue;
        ++source_blocks_;
        auto *term = body.getTerminator();
        if (source_mixed_ && !llvm::isa<llvm::BranchInst, llvm::ReturnInst>(term)) {
            failure_ = "source-mixed automatic edges need branch/return terminators"; return;
        }
        if (multiple_scopes_ && llvm::isa<llvm::InvokeInst, llvm::ResumeInst>(term)) {
            failure_ = "multiple Scope original edges do not support EH terminators"; return;
        }
        const auto *invoke = llvm::dyn_cast<llvm::InvokeInst>(term);
        const bool hybrid_terminal = recipe.coverage == "hybrid-eh" &&
            llvm::isa<llvm::InvokeInst, llvm::ResumeInst>(term);
        if (!llvm::isa<llvm::BranchInst, llvm::SwitchInst, llvm::ReturnInst, llvm::UnreachableInst>(term) && !hybrid_terminal) {
            failure_ = "automatic normal-edge inventory encountered an unsupported terminator"; return;
        }
        if (invoke != nullptr) {
            ++excluded_unwind_edges_;
            invokes_.push_back({term, invoke->getNormalDest(), invoke->getUnwindDest(), nullptr});
        }
        const auto successors = invoke == nullptr ? term->getNumSuccessors() : 1;
        for (unsigned index = 0; index != successors; ++index) {
            const auto id = instruction_provenance(*term) + ":instance:" + std::to_string(sequence) + ":edge:" + std::to_string(index);
            const auto label = component_seed(recipe.seeds.at("runtime-contribution"), function.getName(), id);
            if (label == 0 || !labels.insert(label).second) { failure_ = "automatic contribution identity collision; choose another seed"; return; }
            edges_.push_back({id, term, term->getSuccessor(index), nullptr, term, index, label});
        }
        ++sequence;
    }
    std::vector<unsigned> order(edges_.size());
    for (unsigned index = 0; index != order.size(); ++index) order[index] = index;
    std::stable_sort(order.begin(), order.end(), [&](unsigned left, unsigned right) { return edges_[left].label < edges_[right].label; });
    selected_ = std::min<unsigned>(options_.maximum_edges, edges_.size());
    const auto required = std::max<std::uint64_t>(options_.minimum_edges,
        (std::uint64_t(edges_.size()) * options_.minimum_percent + 99) / 100);
    if ((edges_.empty() && options_.minimum_percent != 0) || selected_ < required) {
        failure_ = "automatic contribution edge budget cannot satisfy minimum count/density"; return;
    }
    if (!deferred_ && selected_ + explicit_points_ > recipe.max_contribution_sites) {
        failure_ = "automatic and explicit queries exceed max_contribution_sites"; return;
    }
    for (unsigned index = 0; index != selected_; ++index) edges_[order[index]].selected = true;
    if (source_mixed_) {
        if (edges_.size() < (bounded_mixed_ ? 3u : 2u) ||
                edges_.size() > (bounded_mixed_ ? 8u : 2u) ||
                selected_ != edges_.size() || explicit_points_ != 0) {
            failure_ = "source-mixed automatic edges need complete bounded original-edge selection"; return;
        }
        const auto owner = function.getName().str();
        const auto rules = private_->groups.find(owner);
        if (rules == private_->groups.end() || rules->second.defaults ||
                rules->second.sites.size() != edges_.size()) {
            failure_ = "source-mixed automatic owner needs one exact private rule per original edge"; return;
        }
        std::set<std::vector<std::string>> owned_subsets;
        for (const auto &edge : edges_) {
            const auto found = rules->second.sites.find(edge.label);
            if (found == rules->second.sites.end() || found->second.reference_site) {
                failure_ = "source-mixed original edge lacks its exact private source rule"; return;
            }
            std::vector<std::string> owned;
            unsigned measured = 0;
            for (const auto &source : found->second.binding.sources) {
                if (source.spec.provider == "owned-context-v1") owned.push_back(source.spec.id);
                else if (source.spec.provider == "measured-scope-v1") ++measured;
            }
            if (owned.empty() || measured != 1) {
                failure_ = "source-mixed original edge needs owned and measured sources"; return;
            }
            if (!owned_subsets.insert(std::move(owned)).second) {
                failure_ = "source-mixed original edges need distinct owned source subsets"; return;
            }
        }
    }
    if (multiple_scopes_) {
        const auto owner = function.getName().str();
        const auto owner_rules = private_->groups.find(owner);
        if (owner_rules == private_->groups.end()) { failure_ = "multiple Scope owner has no source rules"; return; }
        std::set<std::uint32_t> selected_labels;
        for (const auto &edge : edges_) if (edge.selected) selected_labels.insert(edge.label);
        for (const auto &[site, rule] : owner_rules->second.sites)
            if (rule.reference_site && !selected_labels.count(site)) {
                failure_ = "reference_site requires a selected original edge"; return;
            }
        llvm::DominatorTree dominators(function);
        for (auto &edge : edges_) {
            if (!edge.selected) continue;
            const auto selected_rule = owner_rules->second.sites.find(edge.label);
            if (selected_rule == owner_rules->second.sites.end() || !selected_rule->second.reference_site) {
                failure_ = "selected multiple Scope edge needs an explicit reference_site"; return;
            }
            const auto site = *selected_rule->second.reference_site;
            const auto anchor = std::find_if(anchors_.begin(), anchors_.end(),
                [&](const ContributionEdgeAnchor &entry) { return entry.site == site; });
            if (anchor == anchors_.end()) { failure_ = "selected Scope edge names an absent reference_site"; return; }
            const auto *marker = llvm::dyn_cast_or_null<llvm::Instruction>(anchor->marker);
            const auto *source = llvm::dyn_cast_or_null<llvm::Instruction>(edge.origin);
            if (marker == nullptr || source == nullptr || !dominators.dominates(marker, source)) {
                failure_ = "selected Scope anchor does not dominate its original edge"; return;
            }
            const auto &bound = selected_rule->second;
            const auto &anchor_rule = contribution_source_group(*private_, owner, site);
            const auto &a = bound.binding.sources, &b = anchor_rule.binding.sources;
            if (a.size() != 1 || b.size() != 1 || bound.domain != anchor_rule.domain ||
                    bound.binding.spec.mixing_domain != anchor_rule.binding.spec.mixing_domain ||
                    a.front().spec.id != b.front().spec.id ||
                    a.front().spec.word_label != b.front().spec.word_label ||
                    a.front().spec.provider != b.front().spec.provider) {
                failure_ = "selected Scope edge source or domain differs from its anchor"; return;
            }
            edge.reference_site = site;
            edge.reference = anchor->origin;
        }
    }
}
std::string ContributionEdgePlan::failure() const { return failure_; }
std::string ContributionEdgePlan::bind_dispatch_states(const StateLayout &layout) {
    if (!source_mixed_) return {};
    if (selected_ != edges_.size() || edges_.size() < (bounded_mixed_ ? 3u : 2u) ||
            edges_.size() > (bounded_mixed_ ? 8u : 2u) || !materialized_)
        return "source-mixed original edges lost their complete gateways before state binding";
    std::vector<std::uint32_t> states(edges_.size());
    std::set<std::uint32_t> distinct;
    for (unsigned index = 0; index != edges_.size(); ++index) {
        const auto &edge = edges_[index];
        const auto *gateway = llvm::dyn_cast_or_null<llvm::BasicBlock>(edge.gateway);
        if (!edge.selected || gateway == nullptr || !layout.states.contains(gateway))
            return "source-mixed original edge has no frozen dispatch state";
        states[index] = layout.states.lookup(gateway);
        if (!distinct.insert(states[index]).second)
            return "source-mixed original edges share a dispatch state";
    }
    dispatch_states_ = std::move(states);
    return {};
}
llvm::json::Object ContributionEdgePlan::report(bool verified) const {
    verified &= final_verified_ && materialized_ && canonical_.size() == edges_.size();
    llvm::json::Array entries;
    for (unsigned i = 0; i != edges_.size(); ++i) {
        const auto &edge = edges_[i];
        const auto canonical = canonical_.size() == edges_.size() ? canonical_[i] : i;
        llvm::json::Object row{
        {"id", edge.identity}, {"successor", edge.successor}, {"selected", edge.selected},
        {"point", edge.label}, {"canonical", edges_[canonical].identity}, {"canonical_point", edges_[canonical].label},
        {"status", edge.selected ? verified ? "bound" : "unverified" : "unselected"}};
        if (edge.selected && multiple_scopes_) row["reference_site"] = edge.reference_site;
        if (source_mixed_ && edge.selected && dispatch_states_.size() == edges_.size())
            row["dispatch_state"] = dispatch_states_[i];
        entries.push_back(std::move(row));
    }
    llvm::json::Object result{{"basis", region_entry_.empty() ? "retained-cff-input-normal-successor-edges" : "retained-cff-input-region-normal-successor-edges"}, {"original_blocks", source_blocks_},
        {"original_edges", static_cast<std::int64_t>(edges_.size())}, {"selected_edges", selected_},
        {"bound_edges", verified ? selected_ : 0}, {"explicit_points", explicit_points_},
        {"physical_selected_edges", physical_selected()}, {"coalesced_selected_edges", selected_ - physical_selected()},
        {"alias_contract_verified", verified},
        {"minimum_edges", options_.minimum_edges}, {"minimum_percent", options_.minimum_percent},
        {"maximum_edges", options_.maximum_edges}, {"generated_edges_in_denominator", 0}, {"edges", std::move(entries)},
        {"excluded_unwind_edges", excluded_unwind_edges_},
        {"density_verified", verified && selected_ != 0 && !edges_.empty()}};
    if (!region_entry_.empty()) { result["region_entry"] = region_entry_; result["region_exit"] = region_exit_; }
    if (edges_.empty()) result["density_percent"] = nullptr;
    else result["density_percent"] = 100.0 * (verified ? selected_ : 0) / edges_.size();
    return result;
}
}
