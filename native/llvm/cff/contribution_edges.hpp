#pragma once

#include "recipe.hpp"
#include "llvm/IR/ValueHandle.h"
#include <set>

namespace llvm { class SwitchInst; class AllocaInst; class BranchInst; class InvokeInst; }
namespace pyobfuscator::native::cff {
class DedupAlias;
struct StateLayout;
struct ContributionEdgeAnchor {
    std::uint32_t site;
    llvm::WeakVH marker, reference, origin;
};
class ContributionEdgePlan {
public:
    ContributionEdgePlan(llvm::Function &, const ResolvedRecipe &);
    std::string failure() const;
    unsigned instrument(llvm::Function &, class CfgOrigins &);
    bool deferred() const { return deferred_; }
    std::string coalesce(const DedupAlias &);
    std::vector<std::uint32_t> aliased_point_labels() const;
    std::string before_lowering(const llvm::Function &);
    void switch_lowered(const llvm::SwitchInst &, llvm::AllocaInst &, llvm::BranchInst &);
    void invoke_lowered(const llvm::InvokeInst &, llvm::BasicBlock &);
    std::string replace_invoke(const llvm::InvokeInst &, llvm::InvokeInst &, llvm::BasicBlock &completion);
    std::string completion_split(llvm::BasicBlock &prefix, llvm::BasicBlock &suffix);
    std::string verify_sources(const llvm::Function &) const;
    std::string bind_dispatch_states(const StateLayout &);
    llvm::json::Object report(bool verified) const;
    void verified() { final_verified_ = true; }
    struct Edge {
        std::string identity;
        llvm::WeakTrackingVH terminator, target, gateway;
        const llvm::Instruction *origin;
        unsigned successor;
        std::uint32_t label;
        bool selected = false;
        std::uint32_t reference_site = 0;
        llvm::WeakVH reference;
    };
    const std::vector<Edge> &edges() const { return edges_; }
private:
    struct Switch {
        const llvm::SwitchInst *original;
        llvm::WeakTrackingVH source_branch, condition, slot, store;
        std::vector<llvm::WeakTrackingVH> checks;
        std::vector<llvm::ConstantInt *> cases;
        std::vector<llvm::WeakTrackingVH> targets;
    };
    struct Invoke {
        llvm::WeakVH source;
        llvm::WeakTrackingVH normal, unwind;
        llvm::WeakVH bridge;
        std::vector<llvm::WeakVH> completions;
    };
    const llvm::BasicBlock *normal_entry(const Invoke &) const;
    bool valid_completions(const Invoke &) const;
    bool source_targets_gateway(const Edge &) const;
    llvm::Instruction *insertion_source(const Edge &) const;
    bool compatible_policy(std::uint32_t, std::uint32_t) const;
    std::string plan_aliases();
    std::string verify_aliases() const;
    unsigned physical_selected() const;
    llvm::Function *owner_;
    llvm::WeakTrackingVH lease_;
    llvm::WeakTrackingVH measured_;
    std::vector<ContributionEdgeAnchor> anchors_;
    bool multiple_scopes_ = false;
    ContributionOptions options_;
    std::shared_ptr<RegionScope> region_scope_;
    std::vector<Edge> edges_;
    std::vector<Switch> switches_;
    std::vector<Invoke> invokes_;
    std::string failure_;
    unsigned selected_ = 0, source_blocks_ = 0, explicit_points_ = 0, excluded_unwind_edges_ = 0;
    unsigned maximum_queries_ = 0;
    std::string region_entry_, region_exit_;
    bool final_verified_ = false;
    bool deferred_ = false, materialized_ = false;
    bool source_mixed_ = false;
    bool bounded_mixed_ = false;
    std::shared_ptr<const ContributionPrivate> private_;
    std::vector<unsigned> canonical_;
    std::vector<std::uint32_t> dispatch_states_;
    std::set<std::string> authorized_aliases_;
};
llvm::Value *canonical_contribution_source(llvm::Function &, const ResolvedRecipe &,
    std::vector<ContributionEdgeAnchor> &, bool &multiple, std::string &failure);
llvm::Value *contribution_edge_reference_origin(llvm::Value *, llvm::Function &);
}
